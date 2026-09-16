package mpcceremony

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// checkpointReaderV4 confines all referenced reads to one public staging root.
// Large payloads are hashed as streams; JSON and signatures remain bounded.
type checkpointReaderV4 struct {
	root          *os.Root
	path          string
	flatCandidate bool // internal V4 release layout only; never caller-defined aliases
}

func openCheckpointReaderV4(path string) (*checkpointReaderV4, error) {
	if path == "" {
		return nil, errors.New("public artifact root is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("public artifact root must be a real directory")
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return &checkpointReaderV4{root: root, path: abs}, nil
}

func (r *checkpointReaderV4) read(ref ArtifactRef, limit int64, capture bool) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if err := validatePortableStorageName(ref.Name); err != nil {
		return nil, err
	}
	if ref.Digest.Size <= 0 || ref.Digest.Size > limit {
		return nil, fmt.Errorf("artifact %s exceeds its permitted size", ref.Name)
	}
	if capture && limit > maxSignedRecordBytes {
		return nil, errors.New("large artifacts must be streamed, not retained in memory")
	}
	name := ref.Name
	if r.flatCandidate {
		var err error
		name, err = releasePhysicalNameV4(name)
		if err != nil {
			return nil, err
		}
	}
	parts := strings.Split(name, "/")
	var before os.FileInfo
	for i := range parts {
		info, err := r.root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) {
			return nil, errors.New("artifact path must not traverse symbolic links or non-directories")
		}
		before = info
	}
	if !before.Mode().IsRegular() || before.Size() != ref.Digest.Size {
		return nil, fmt.Errorf("artifact %s is not a regular file of the expected size", ref.Name)
	}
	f, err := r.root.Open(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return nil, errors.New("artifact changed while being opened")
	}
	sha := sha256.New()
	blake, _ := blake2b.New256(nil)
	writers := []io.Writer{sha, blake}
	var buf bytes.Buffer
	if capture {
		writers = append(writers, &buf)
	}
	size, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(f, ref.Digest.Size+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	actual := Digest{SHA256: fmt.Sprintf("sha256:%x", sha.Sum(nil)), Blake2b256: fmt.Sprintf("blake2b256:%x", blake.Sum(nil)), Size: size}
	if actual != ref.Digest || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("artifact %s differs from its exact committed bytes", ref.Name)
	}
	if capture {
		return buf.Bytes(), nil
	}
	return nil, nil
}

func (r *checkpointReaderV4) pair(refs SignedArtifactRefs) ([]byte, []byte, error) {
	if err := refs.Validate(); err != nil {
		return nil, nil, err
	}
	record, err := r.read(refs.Record, maxSignedRecordBytes, true)
	if err != nil {
		return nil, nil, err
	}
	signature, err := r.read(refs.Signature, 4096, true)
	if err != nil {
		return nil, nil, err
	}
	return record, signature, nil
}

type checkpointAncestryV4 struct {
	head                     CheckpointV4
	allocations              map[string]CheckpointTransitionV4
	enrollments              []SignedArtifactRefs
	enrollmentTransitions    []CheckpointTransitionV4
	mirrors                  []SignedArtifactRefs
	witnesses                []SignedArtifactRefs
	beaconEvidence           []SignedArtifactRefs
	audits                   []SignedArtifactRefs
	incidents                []CheckpointTransitionV4
	accepted                 map[ContributionScope]SignedArtifactRefs
	acceptedTransitions      map[ContributionScope]CheckpointTransitionV4
	checkpoints              []SignedArtifactRefs // newest to oldest, including head
	finalCandidateCheckpoint *SignedArtifactRefs
	count                    uint64
	turnCommitments          map[ContributionScope]*TurnCommitmentV4
}

func loadCheckpointAncestryV4(reader *checkpointReaderV4, d CeremonyDefinition, definitionBytes, definitionSignature []byte, refs SignedArtifactRefs) (checkpointAncestryV4, error) {
	result := checkpointAncestryV4{allocations: map[string]CheckpointTransitionV4{}, accepted: map[ContributionScope]SignedArtifactRefs{}, acceptedTransitions: map[ContributionScope]CheckpointTransitionV4{}, turnCommitments: map[ContributionScope]*TurnCommitmentV4{}}
	var child *CheckpointV4
	for {
		if result.count > MaxCheckpointSequenceV4 {
			return checkpointAncestryV4{}, errors.New("checkpoint ancestry exceeds protocol limit")
		}
		record, signature, err := reader.pair(refs)
		if err != nil {
			return checkpointAncestryV4{}, err
		}
		current, err := VerifySignedCheckpointV4(d, definitionBytes, definitionSignature, record, signature)
		if err != nil {
			return checkpointAncestryV4{}, err
		}
		if child == nil {
			result.head = current
		} else {
			// reader.pair already matched both exact predecessor references.
			if err := ValidateCheckpointTransitionV4(current, *child); err != nil {
				return checkpointAncestryV4{}, err
			}
			// Check scoped governance while its exact authenticated predecessor
			// is in hand. This also covers callers that signed a checkpoint
			// without the normal preparation API, without retaining whole copies
			// of every checkpoint's growing inventory in memory.
			if isGovernanceTransitionV4(child.Transition.Kind) {
				if err := verifyCheckpointGovernanceV4(reader, d, current, child.Transition); err != nil {
					return checkpointAncestryV4{}, err
				}
			}
		}
		result.count++
		if err := collectTurnCommitmentV4(result.turnCommitments, current); err != nil {
			return checkpointAncestryV4{}, err
		}
		result.checkpoints = append(result.checkpoints, refs)
		if current.Transition.Kind == CheckpointIncidentRecorded {
			result.incidents = append(result.incidents, current.Transition)
		}
		if current.Transition.Kind == CheckpointFinalCandidateRecorded {
			pair := refs
			result.finalCandidateCheckpoint = &pair
		}
		if current.Transition.Kind == CheckpointAuditRecorded {
			result.audits = append(result.audits, *current.Transition.Record)
		}
		if current.Transition.Kind == CheckpointWitnessRecorded {
			result.witnesses = append(result.witnesses, *current.Transition.Record)
		}
		if current.Transition.Kind == CheckpointBeaconEvidenceRecorded {
			result.beaconEvidence = append(result.beaconEvidence, *current.Transition.Record)
		}
		if current.Transition.Kind == CheckpointMirrorRecorded {
			result.mirrors = append(result.mirrors, *current.Transition.Record)
		}
		if current.Transition.Kind == CheckpointPhase1CandidateAccepted || current.Transition.Kind == CheckpointPhase2CandidateAccepted {
			if _, exists := result.acceptedTransitions[*current.Transition.Scope]; exists {
				return checkpointAncestryV4{}, errors.New("duplicate accepted transition for the same contribution scope")
			}
			result.accepted[*current.Transition.Scope] = *current.Transition.Record
			result.acceptedTransitions[*current.Transition.Scope] = current.Transition
		}
		if current.Transition.Kind == CheckpointEnrollmentRecorded {
			result.enrollments = append(result.enrollments, *current.Transition.Record)
			result.enrollmentTransitions = append(result.enrollmentTransitions, current.Transition)
		}
		if current.Transition.Kind == CheckpointPhase1CandidateAllocated || current.Transition.Kind == CheckpointPhase2CandidateAllocated {
			if _, exists := result.allocations[current.Transition.AttemptID]; exists {
				return checkpointAncestryV4{}, errors.New("duplicate candidate allocation attempt")
			}
			result.allocations[current.Transition.AttemptID] = current.Transition
		}
		if current.PreviousCheckpoint == nil {
			return result, nil
		}
		refs = *current.PreviousCheckpoint
		child = &current
	}
}

// VerifyStoredCheckpointV4 authenticates the exact signed checkpoint ancestry
// and legal structural edges. It neither downloads nor hashes every historical
// large payload, replays contribution mathematics, or claims global freshness.
// Governance edges additionally recheck their bounded evidence and exact scope.
// The delivery service selects the current root; callers supply its exact pair.
func VerifyStoredCheckpointV4(trust TrustPaths, artifactRoot string, head SignedArtifactRefs) (CheckpointV4, error) {
	c, err := openStoredCheckpointV4(trust, artifactRoot, head)
	if err != nil {
		return CheckpointV4{}, err
	}
	defer c.reader.root.Close()
	return c.ancestry.head, nil
}

type storedCheckpointContextV4 struct {
	reader          *checkpointReaderV4
	trusted         *TrustedCeremony
	definitionBytes []byte
	ancestry        checkpointAncestryV4
}

// The caller owns the returned reader and must close it. Failed construction
// never leaves an open root or returns a partially verified ancestry.
func openStoredCheckpointV4(trust TrustPaths, artifactRoot string, head SignedArtifactRefs) (*storedCheckpointContextV4, error) {
	trusted, err := LoadSignedDefinition(trust)
	if err != nil {
		return nil, err
	}
	db, err := MarshalCanonical(trusted.Definition)
	if err != nil {
		return nil, err
	}
	ds, err := readRegularBounded(trust.DefinitionSignaturePath, 4096)
	if err != nil {
		return nil, err
	}
	reader, err := openCheckpointReaderV4(artifactRoot)
	if err != nil {
		return nil, err
	}
	ancestry, err := loadCheckpointAncestryV4(reader, trusted.Definition, db, ds, head)
	if err != nil {
		reader.root.Close()
		return nil, err
	}
	return &storedCheckpointContextV4{reader: reader, trusted: trusted, definitionBytes: db, ancestry: ancestry}, nil
}

// CheckpointPreparationV4 verifies a proposed protocol update before it may be
// signed. Proposal contains only protocol references; Relay owns delivery
// manifests and object keys. No files are written and no signature is created.
type CheckpointPreparationV4 struct {
	Trust        TrustPaths
	ArtifactRoot string
	Proposal     CheckpointV4
	Circuit      *CompiledCircuit
	// RejectedCandidateDir is private input only for an explicit rejection. Its
	// normalized inventory hashes become state, never these unaccepted files.
	RejectedCandidateDir string
}

func PrepareCheckpointV4(options CheckpointPreparationV4) ([]byte, error) {
	if (options.Proposal.Transition.Kind == CheckpointContributionRejected) != (options.RejectedCandidateDir != "") {
		return nil, errors.New("only explicit rejection requires a private candidate directory")
	}
	trusted, err := loadOperationalCeremony(options.Trust)
	if err != nil {
		return nil, err
	}
	d := trusted.Definition
	db, err := MarshalCanonical(d)
	if err != nil {
		return nil, err
	}
	ds, err := readRegularBounded(options.Trust.DefinitionSignaturePath, 4096)
	if err != nil {
		return nil, err
	}
	c := options.Proposal
	if err := validateCheckpointDefinitionBindingV4(d, db, ds, c); err != nil {
		return nil, err
	}
	reader, err := openCheckpointReaderV4(options.ArtifactRoot)
	if err != nil {
		return nil, err
	}
	defer reader.root.Close()
	var previous *CheckpointV4
	allocations := map[string]CheckpointTransitionV4{}
	enrollments := []SignedArtifactRefs{}
	var evidenceAncestry checkpointAncestryV4
	if c.PreviousCheckpoint != nil {
		ancestry, err := loadCheckpointAncestryV4(reader, d, db, ds, *c.PreviousCheckpoint)
		if err != nil {
			return nil, err
		}
		previous = &ancestry.head
		allocations = ancestry.allocations
		enrollments = ancestry.enrollments
		evidenceAncestry = ancestry
		if err := ValidateCheckpointTransitionV4(*previous, c); err != nil {
			return nil, err
		}
	}
	// Check every newly accepted byte before issuing any signable result.
	if isGovernanceTransitionV4(c.Transition.Kind) {
		// A stop must remain possible with missing unrelated payloads or
		// incomplete enrollments. Verify only its exact authorizing evidence.
		if previous == nil {
			return nil, errors.New("governance requires an initialized ceremony")
		}
		if err := verifyCheckpointGovernanceV4(reader, d, *previous, c.Transition); err != nil {
			return nil, err
		}
		return MarshalCanonical(c)
	}
	for _, ref := range c.AcceptedArtifacts {
		if previous != nil && slices.Contains(previous.AcceptedArtifacts, ref) {
			continue
		}
		limit := MaxArtifactSize
		if strings.HasSuffix(ref.Name, ".sig") {
			limit = 4096
		} else if strings.HasSuffix(ref.Name, ".json") {
			limit = maxSignedRecordBytes
		}
		if c.Transition.Kind == CheckpointFinalReleaseRecorded {
			limit = finalReleaseArtifactLimitV4(ref)
		}
		if _, err := reader.read(ref, limit, false); err != nil {
			return nil, err
		}
	}
	verifiedEnrollments, err := loadCheckpointEnrollmentsV4(reader, d, db, enrollments)
	if err != nil {
		return nil, err
	}
	if c.Transition.Kind == CheckpointEnrollmentRecorded {
		if err := verifyNewCheckpointEnrollmentV4(reader, d, db, c.Transition, verifiedEnrollments); err != nil {
			return nil, err
		}
		return MarshalCanonical(c)
	}
	if c.Transition.Kind == CheckpointAuditRecorded || c.Transition.Kind == CheckpointFinalReleaseRecorded {
		refs := append([]SignedArtifactRefs{}, evidenceAncestry.audits...)
		if c.Transition.Kind == CheckpointAuditRecorded {
			refs = append(refs, *c.Transition.Record)
		}
		if _, err := verifyCheckpointAuditsV4(reader, d, previous.Progress, verifiedEnrollments, refs, c.Transition.Kind == CheckpointFinalReleaseRecorded); err != nil {
			return nil, err
		}
		if c.Transition.Kind == CheckpointAuditRecorded {
			return MarshalCanonical(c)
		}
	}
	if c.Transition.Kind == CheckpointMirrorRecorded || c.Transition.Kind == CheckpointPhase1Closed || c.Transition.Kind == CheckpointPhase2Closed {
		mirrorRefs := append([]SignedArtifactRefs{}, evidenceAncestry.mirrors...)
		if c.Transition.Kind == CheckpointMirrorRecorded {
			mirrorRefs = append(mirrorRefs, *c.Transition.Record)
		}
		mirrors, err := verifyCheckpointMirrorsV4(reader, d, db, evidenceAncestry.accepted, verifiedEnrollments, mirrorRefs)
		if err != nil {
			return nil, err
		}
		if c.Transition.Kind == CheckpointMirrorRecorded {
			return MarshalCanonical(c)
		}
		phase := Phase1
		if c.Transition.Kind == CheckpointPhase2Closed {
			phase = Phase2
		}
		for scope := range evidenceAncestry.accepted {
			if scope.Phase == phase && len(mirrors[scope]) < int(d.AssurancePolicy.MirrorsPerAcceptedHead) {
				return nil, errors.New("each accepted head requires its signed mirror minimum before closure")
			}
		}
	}
	if c.Transition.Kind == CheckpointPhase1CandidateAllocated || c.Transition.Kind == CheckpointPhase2CandidateAllocated {
		if _, ok := verifiedEnrollments[c.Transition.Scope.ParticipantID]; !ok {
			return nil, errors.New("participant enrollment must be committed before candidate allocation")
		}
	}
	if c.Transition.Kind == CheckpointWitnessRecorded || c.Transition.Kind == CheckpointBeaconEvidenceRecorded || c.Transition.Kind == CheckpointPhase1Sealed || c.Transition.Kind == CheckpointFinalCandidateRecorded {
		witnessRefs := append([]SignedArtifactRefs{}, evidenceAncestry.witnesses...)
		beaconRefs := append([]SignedArtifactRefs{}, evidenceAncestry.beaconEvidence...)
		if c.Transition.Kind == CheckpointWitnessRecorded {
			witnessRefs = append(witnessRefs, *c.Transition.Record)
		}
		if c.Transition.Kind == CheckpointBeaconEvidenceRecorded {
			beaconRefs = append(beaconRefs, *c.Transition.Record)
		}
		witnessCounts, err := verifyCheckpointWitnessesV4(reader, d, previous.Progress, verifiedEnrollments, witnessRefs)
		if err != nil {
			return nil, err
		}
		beacons, err := verifyCheckpointBeaconEvidenceV4(reader, d, previous.Progress, beaconRefs, c.Transition)
		if err != nil {
			return nil, err
		}
		if c.Transition.Kind == CheckpointWitnessRecorded || c.Transition.Kind == CheckpointBeaconEvidenceRecorded {
			return MarshalCanonical(c)
		}
		phase := Phase1
		if c.Transition.Kind == CheckpointFinalCandidateRecorded {
			phase = Phase2
		}
		if witnessCounts[phase] < int(d.AssurancePolicy.PublicWitnessesPerPhase) {
			return nil, errors.New("signed witness minimum is not satisfied for this phase")
		}
		if !beacons[phase] {
			return nil, errors.New("verified multi-relay beacon evidence is required for this phase")
		}
	}
	if err := verifyCheckpointEvidenceV4(options, trusted, reader, previous, allocations); err != nil {
		return nil, err
	}
	return MarshalCanonical(c)
}

func verifyCheckpointEvidenceV4(options CheckpointPreparationV4, trusted *TrustedCeremony, reader *checkpointReaderV4, previous *CheckpointV4, allocations map[string]CheckpointTransitionV4) error {
	c := options.Proposal
	d := trusted.Definition
	switch c.Transition.Kind {
	case CheckpointInitial:
		chain, refs, err := VerifyAcceptedPhase1Chain(options.Trust, options.Circuit, PhaseTranscriptPaths{RootDir: reader.path, ChainPath: filepath.Join(reader.path, c.Progress.Phase1.Chain.Record.Name), ChainSignaturePath: filepath.Join(reader.path, c.Progress.Phase1.Chain.Signature.Name)})
		if err != nil {
			return err
		}
		return verifyV4ChainProjection(chain, refs, c.Progress.Phase1)
	case CheckpointPhase1CandidateAllocated, CheckpointPhase2CandidateAllocated:
		return verifyCandidateAllocationV4(d, *previous, c.Transition)
	case CheckpointPhase1CandidateAccepted, CheckpointPhase2CandidateAccepted:
		return verifyAcceptedCandidateV4(options, trusted, reader, *previous, allocations)
	case CheckpointContributionRejected:
		return verifyRejectedInventoryV4(options.RejectedCandidateDir, *c.Transition.Contribution)
	case CheckpointDeliveryRetired, CheckpointDeliveryReallocated:
		return nil // No protocol claim or accepted artifact is added.
	case CheckpointPhase1Closed, CheckpointPhase2Closed, CheckpointPhase1BeaconRecorded, CheckpointPhase2BeaconRecorded, CheckpointPhase1Sealed, CheckpointPhase2Initialized:
		return verifyCheckpointLifecycleV4(options, trusted, reader, *previous)
	case CheckpointFinalCandidateRecorded:
		return verifyFinalCandidateV4(options, trusted, reader, *previous)
	case CheckpointFinalReleaseRecorded:
		_, _, err := verifyFinalReleasePackageV4(options.Trust, reader.path, c)
		return err
	default:
		return errors.New("real-artifact authoring for this v4 transition is not implemented yet")
	}
}

func verifyRejectedInventoryV4(dir string, inventory CandidateInventory) error {
	if err := inventory.Validate(); err != nil {
		return err
	}
	reader, err := openCheckpointReaderV4(dir)
	if err != nil {
		return err
	}
	defer reader.root.Close()
	entries, err := reader.root.Open(".")
	if err != nil {
		return err
	}
	defer entries.Close()
	names, err := entries.Readdirnames(len(inventory.Files) + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) != len(inventory.Files) {
		return errors.New("rejected directory does not contain the exact complete candidate inventory")
	}
	for _, ref := range inventory.Files {
		if !slices.Contains(names, ref.Name) {
			return errors.New("rejected directory has missing or extra candidate files")
		}
		limit := int64(maxSignedRecordBytes)
		if ref.Name == "contribution.bin" {
			limit = MaxArtifactSize
		} else if strings.HasSuffix(ref.Name, ".sig") {
			limit = 4096
		}
		if _, err := reader.read(ref, limit, false); err != nil {
			return err
		}
	}
	return nil
}

func verifyAcceptedCandidateV4(options CheckpointPreparationV4, trusted *TrustedCeremony, reader *checkpointReaderV4, previous CheckpointV4, allocations map[string]CheckpointTransitionV4) error {
	c := options.Proposal
	scope := *c.Transition.Scope
	before, after := previous.Progress.Phase1, c.Progress.Phase1
	if scope.Phase == Phase2 {
		before = *previous.Progress.Phase2
		after = *c.Progress.Phase2
	}
	paths := PhaseTranscriptPaths{RootDir: reader.path, ChainPath: filepath.Join(reader.path, after.Chain.Record.Name), ChainSignaturePath: filepath.Join(reader.path, after.Chain.Signature.Name)}
	var chain Chain
	var refs SignedArtifactRefs
	var err error
	if scope.Phase == Phase1 {
		chain, refs, err = VerifyAcceptedPhase1Chain(options.Trust, options.Circuit, paths)
	} else {
		seal := previous.Progress.Phase1Seal
		chain, refs, err = VerifyAcceptedPhase2Chain(options.Trust, options.Circuit, reader.path, filepath.Join(reader.path, seal.Record.Name), filepath.Join(reader.path, seal.Signature.Name), paths)
	}
	if err != nil {
		return err
	}
	if err := verifyV4ChainProjection(chain, refs, after); err != nil {
		return err
	}
	oldBytes, oldSig, err := reader.pair(before.Chain)
	if err != nil {
		return err
	}
	var old Chain
	if err := VerifySignedRecord(oldBytes, oldSig, &old, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
		return err
	}
	if err := old.ValidateAgainstDefinition(trusted.Definition); err != nil {
		return err
	}
	if err := verifyV4ChainProjection(old, before.Chain, before); err != nil {
		return err
	}
	if chain.PhaseID != old.PhaseID || chain.Genesis != old.Genesis || len(chain.Records) != len(old.Records)+1 || !reflect.DeepEqual(chain.Records[:len(old.Records)], old.Records) {
		return errors.New("accepted chain does not extend the exact previous chain")
	}
	last := chain.Records[len(chain.Records)-1]
	if err := verifyCandidateChainInventoryV4(last, scope, *c.Transition.Contribution, c.Transition.Evidence); err != nil {
		return err
	}
	if last.ParticipantID != scope.ParticipantID {
		return errors.New("accepted chain names another participant")
	}
	allocation, ok := allocations[c.Transition.AttemptID]
	if !ok || allocation.Scope == nil || *allocation.Scope != scope {
		return errors.New("candidate has no matching authenticated allocation")
	}
	return verifyCandidateChronologyV4(reader, allocation, c.Transition, chain)
}

func verifyCandidateChronologyV4(reader *checkpointReaderV4, allocation, tx CheckpointTransitionV4, chain Chain) error {
	read := func(ref ArtifactRef, out any) error {
		b, err := reader.read(ref, maxSignedRecordBytes, true)
		if err != nil {
			return err
		}
		return UnmarshalCanonical(b, out)
	}
	last := chain.Records[len(chain.Records)-1]
	var attestation ContributionAttestation
	var erasure ErasureAttestation
	if err := read(last.Attestation, &attestation); err != nil {
		return err
	}
	if err := read(last.Erasure, &erasure); err != nil {
		return err
	}
	timestamps := []string{allocation.AllocatedAt, attestation.ContributedAt, erasure.DestroyedAt, last.AcceptedAt}
	var before time.Time
	for i, value := range timestamps {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return err
		}
		// Existing cleanup validation permits the same recorded timestamp as
		// contribution; allocation and acceptance must be strictly ordered.
		if i > 0 && ((i == 2 && parsed.Before(before)) || (i != 2 && !parsed.After(before))) {
			return errors.New("candidate allocation, contribution, cleanup and acceptance timestamps are not ordered")
		}
		before = parsed
	}
	return nil
}

func verifyCandidateAllocationV4(d CeremonyDefinition, previous CheckpointV4, tx CheckpointTransitionV4) error {
	if tx.Scope == nil {
		return errors.New("candidate allocation lacks its scope")
	}
	if err := tx.Scope.ValidateAssignment(d); err != nil {
		return err
	}
	if err := previous.Progress.currentTurn(*tx.Scope); err != nil {
		return err
	}
	participant, ok := d.ParticipantByID(tx.Scope.ParticipantID)
	if !ok || participant.Identity.Ed25519PublicKeyHex == "" {
		return errors.New("candidate allocation lacks the assigned participant signing key")
	}
	return nil
}

// Bind the delivery result to the exact bytes covered by chain replay, not
// merely another valid set of artifacts present in the same transcript.
func verifyCandidateChainInventoryV4(last ChainRecord, scope ContributionScope, inventory CandidateInventory, evidence []ArtifactRef) error {
	if err := inventory.Validate(); err != nil {
		return err
	}
	if inventory.Scope != scope {
		return errors.New("candidate inventory names another contribution scope")
	}
	base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
	expected := []ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	for i, ref := range expected {
		mapped := inventory.Files[i]
		mapped.Name = base + mapped.Name
		if mapped != ref {
			return errors.New("candidate inventory differs from the replayed chain artifacts")
		}
	}
	for _, ref := range evidence {
		if ref.Name == base+"verification.json" {
			if ref != last.Verification {
				return errors.New("candidate verification differs from the replayed chain artifact")
			}
			return nil
		}
	}
	return errors.New("candidate verification artifact is missing")
}

func verifyReturnHandoffV4(reader *checkpointReaderV4, d CeremonyDefinition, scope ContributionScope, inventory CandidateInventory) error {
	if err := inventory.Validate(); err != nil {
		return err
	}
	if len(inventory.Files) != 7 || inventory.Scope != scope {
		return errors.New("return handoff requires the complete seven-file inventory for this scope")
	}
	base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
	refs := SignedArtifactRefs{Record: ArtifactRef{Name: base + inventory.Files[5].Name, Digest: inventory.Files[5].Digest}, Signature: ArtifactRef{Name: base + inventory.Files[6].Name, Digest: inventory.Files[6].Digest}}
	record, signature, err := reader.pair(refs)
	if err != nil {
		return err
	}
	return verifyReturnHandoffBytesV4(d, scope, inventory, record, signature)
}

func verifyReturnHandoffBytesV4(d CeremonyDefinition, scope ContributionScope, inventory CandidateInventory, record, signature []byte) error {
	if err := inventory.Validate(); err != nil {
		return err
	}
	if len(inventory.Files) != 7 || inventory.Scope != scope || NewDigest(record) != inventory.Files[5].Digest || NewDigest(signature) != inventory.Files[6].Digest {
		return errors.New("return handoff differs from the complete candidate inventory")
	}
	base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
	participant, ok := d.ParticipantByID(scope.ParticipantID)
	if !ok {
		return errors.New("return sender is not in roster")
	}
	key, err := identityPublicKey(participant.Identity)
	if err != nil {
		return err
	}
	var handoff TransferHandoff
	if err := VerifySignedRecord(record, signature, &handoff, participant.Identity.KeyID, key); err != nil {
		return err
	}
	if err := verifyTransferSource(d, handoff.Source); err != nil {
		return err
	}
	expected := append([]ArtifactRef{}, inventory.Files[:5]...)
	for i := range expected {
		expected[i].Name = base + expected[i].Name
	}
	if handoff.CeremonyID != d.CeremonyID || handoff.Phase != scope.Phase || handoff.Index != scope.Index || handoff.PredecessorHeadID != scope.ParentHeadID || handoff.SenderID != scope.ParticipantID || handoff.SenderKeyID != participant.Identity.KeyID || handoff.RecipientID != d.Coordinator.ID || handoff.RecipientKeyID != d.Coordinator.KeyID || !slices.Equal(handoff.Files, expected) {
		return errors.New("return handoff does not bind this participant and complete candidate")
	}
	return nil
}

func verifyV4ChainProjection(chain Chain, refs SignedArtifactRefs, state CheckpointPhaseState) error {
	head, err := chain.HeadPayload()
	if err != nil {
		return err
	}
	id, err := chain.HeadRecordID()
	if err != nil {
		return err
	}
	if chain.Phase != state.Phase || len(chain.Records) != int(state.AcceptedCount) || refs != state.Chain || head != state.HeadPayload || id != state.HeadRecordID {
		return errors.New("checkpoint projection differs from the authenticated chain")
	}
	return nil
}

func verifyOutboundHandoffV4(reader *checkpointReaderV4, d CeremonyDefinition, previous CheckpointV4, scope ContributionScope, refs SignedArtifactRefs) (TransferHandoff, error) {
	var handoff TransferHandoff
	if err := scope.ValidateAssignment(d); err != nil {
		return handoff, err
	}
	if err := previous.Progress.currentTurn(scope); err != nil {
		return handoff, err
	}
	record, signature, err := reader.pair(refs)
	if err != nil {
		return handoff, err
	}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return handoff, err
	}
	if err := VerifySignedRecord(record, signature, &handoff, d.Coordinator.KeyID, key); err != nil {
		return handoff, err
	}
	if err := verifyTransferSource(d, handoff.Source); err != nil {
		return handoff, err
	}
	participant, _ := d.ParticipantByID(scope.ParticipantID)
	head := previous.Progress.Phase1.HeadPayload
	if scope.Phase == Phase2 {
		head = previous.Progress.Phase2.HeadPayload
	}
	if handoff.CeremonyID != d.CeremonyID || handoff.Phase != scope.Phase || handoff.Index != scope.Index || handoff.PredecessorHeadID != scope.ParentHeadID || handoff.SenderID != d.Coordinator.ID || handoff.SenderKeyID != d.Coordinator.KeyID || handoff.RecipientID != scope.ParticipantID || handoff.RecipientKeyID != participant.Identity.KeyID || !slices.Equal(handoff.Files, []ArtifactRef{head}) {
		return TransferHandoff{}, errors.New("outbound handoff does not bind the exact scheduled participant and accepted input")
	}
	return handoff, nil
}

func verifyOutboundReceiptV4(reader *checkpointReaderV4, d CeremonyDefinition, previous CheckpointV4, t CheckpointTransitionV4, outbound map[string]SignedArtifactRefs) error {
	participant, ok := d.ParticipantByID(t.Scope.ParticipantID)
	if !ok {
		return errors.New("receipt participant is not in the signed roster")
	}
	key, err := identityPublicKey(participant.Identity)
	if err != nil {
		return err
	}
	record, signature, err := reader.pair(*t.Record)
	if err != nil {
		return err
	}
	var receipt TransferReceipt
	if err := VerifySignedRecord(record, signature, &receipt, participant.Identity.KeyID, key); err != nil {
		return err
	}
	refs, ok := outbound[receipt.HandoffSHA256]
	if !ok {
		return errors.New("receipt does not name a handoff committed in this checkpoint ancestry")
	}
	handoff, err := verifyOutboundHandoffV4(reader, d, previous, *t.Scope, refs)
	if err != nil {
		return err
	}
	handoffBytes, _, err := reader.pair(refs)
	if err != nil {
		return err
	}
	// Confirm a second read did not silently change the parsed signed record.
	var again TransferHandoff
	if err := UnmarshalCanonical(handoffBytes, &again); err != nil {
		return err
	}
	if !reflect.DeepEqual(handoff, again) {
		return errors.New("handoff changed during receipt verification")
	}
	return VerifyTransferReceipt(handoffBytes, handoff, receipt)
}
