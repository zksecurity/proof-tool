package mpcceremony

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/crypto/blake2b"
)

// CandidateAllocationCheckpointV4Options identifies one fresh coordinator
// allocation. The phase, participant, index and parent head are derived from
// authenticated ceremony state rather than supplied by the transport layer.
type CandidateAllocationCheckpointV4Options struct {
	Trust        TrustPaths
	ArtifactRoot string
	Checkpoint   SignedArtifactRefs
	AttemptID    string
	AllocatedAt  string
}

// CandidateAllocationCheckpointV4 is an internally prepared, unsigned
// checkpoint. The caller must sign its Canonical bytes with the authenticated
// coordinator key and publish the record/signature pair atomically.
type CandidateAllocationCheckpointV4 struct {
	Checkpoint CheckpointV4
	Scope      ContributionScope
	Canonical  []byte
}

// PrepareCandidateAllocationCheckpointV4 derives and verifies the exact next
// contribution turn. It never accepts caller-supplied phase, index,
// participant or parent-head values.
func PrepareCandidateAllocationCheckpointV4(options CandidateAllocationCheckpointV4Options) (CandidateAllocationCheckpointV4, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return CandidateAllocationCheckpointV4{}, fmt.Errorf("attempt ID: %w", err)
	}
	if err := validateTimestamp("allocated_at", options.AllocatedAt); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	if stored.trusted.Definition.Schema != DefinitionSchemaV4 {
		_ = stored.reader.root.Close()
		return CandidateAllocationCheckpointV4{}, errors.New("candidate allocation requires definition v4")
	}
	previous := stored.ancestry.head
	d := stored.trusted.Definition
	if err := stored.reader.root.Close(); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}

	phase := Phase1
	state := previous.Progress.Phase1
	policy := d.Phase1Policy
	if previous.Progress.Phase1Closure != nil {
		if previous.Progress.Phase2 == nil || previous.Progress.Phase2Closure != nil {
			return CandidateAllocationCheckpointV4{}, errors.New("ceremony is not accepting contribution allocations")
		}
		phase = Phase2
		state = *previous.Progress.Phase2
		policy = d.Phase2Policy
	}
	index := int(state.AcceptedCount) + 1
	if index > len(policy.Participants) {
		return CandidateAllocationCheckpointV4{}, errors.New("signed participant schedule has no next contribution")
	}
	scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: uint8(index), ParticipantID: policy.Participants[index-1], ParentHeadID: state.HeadRecordID}
	if err := scope.ValidateAssignment(d); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}

	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	next.PreviousCheckpoint = &options.Checkpoint
	next.Sequence++
	kind := CheckpointPhase1CandidateAllocated
	if phase == Phase2 {
		kind = CheckpointPhase2CandidateAllocated
	}
	next.Transition = CheckpointTransitionV4{Kind: kind, Scope: &scope, AttemptID: options.AttemptID, AllocatedAt: options.AllocatedAt, Evidence: []ArtifactRef{}}
	next.Deliveries, err = AllocateDeliveryV2(previous.Deliveries, scope, CheckpointSubmissionCandidate, options.AttemptID)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next})
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	return CandidateAllocationCheckpointV4{Checkpoint: next, Scope: scope, Canonical: canonical}, nil
}

type AcceptAllocatedCandidateV4Options struct {
	Trust                     TrustPaths
	Circuit                   *CompiledCircuit
	ArtifactRoot              string
	Checkpoint                SignedArtifactRefs
	AttemptID                 string
	CandidateDir              string
	CoordinatorPrivateKeyPath string
	AcceptedAt                string
}

type AcceptedCandidateCheckpointV4 struct {
	Checkpoint CheckpointV4
	Scope      ContributionScope
	Candidate  CandidateInventory
	Accepted   AcceptContributionFilesResult
	Canonical  []byte
}

// RejectAllocatedCandidateV4Options identifies one active allocation whose
// complete candidate bytes are being retained as rejected. Unlike acceptance,
// rejection intentionally does not parse or validate the candidate's records,
// signatures, cleanup claim, or contribution mathematics: it commits only the
// exact five private bytes that were rejected.
type RejectAllocatedCandidateV4Options struct {
	Trust                TrustPaths
	ArtifactRoot         string
	Checkpoint           SignedArtifactRefs
	AttemptID            string
	RejectedCandidateDir string
}

// RejectedCandidateCheckpointV4 is an internally prepared unsigned rejection
// checkpoint. The caller signs Canonical with the authenticated coordinator
// key and publishes the pair atomically.
type RejectedCandidateCheckpointV4 struct {
	Checkpoint CheckpointV4
	Scope      ContributionScope
	Candidate  CandidateInventory
	Canonical  []byte
}

// RejectAllocatedCandidateV4 derives a rejection from the authenticated active
// allocation. It never accepts caller-supplied phase, index, participant, or
// parent-head values, and never creates a replacement allocation.
func RejectAllocatedCandidateV4(options RejectAllocatedCandidateV4Options) (RejectedCandidateCheckpointV4, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return RejectedCandidateCheckpointV4{}, fmt.Errorf("attempt ID: %w", err)
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}
	if stored.trusted.Definition.Schema != DefinitionSchemaV4 {
		_ = stored.reader.root.Close()
		return RejectedCandidateCheckpointV4{}, errors.New("candidate rejection requires definition v4")
	}
	allocation, ok := stored.ancestry.allocations[options.AttemptID]
	if !ok || allocation.Scope == nil {
		_ = stored.reader.root.Close()
		return RejectedCandidateCheckpointV4{}, errors.New("candidate attempt is not allocated by the authenticated checkpoint ancestry")
	}
	previous := stored.ancestry.head
	scope := *allocation.Scope
	active := false
	for _, slot := range previous.Deliveries {
		if slot.AttemptID == options.AttemptID && slot.Kind == CheckpointSubmissionCandidate && slot.Status == DeliveryAllocated && slot.Scope == scope {
			active = true
		}
	}
	if !active {
		_ = stored.reader.root.Close()
		return RejectedCandidateCheckpointV4{}, errors.New("candidate allocation is no longer active at the authenticated checkpoint")
	}
	if err := previous.Progress.currentTurn(scope); err != nil {
		_ = stored.reader.root.Close()
		return RejectedCandidateCheckpointV4{}, err
	}
	if err := stored.reader.root.Close(); err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}

	inventory, err := rejectedCandidateInventoryV4(options.RejectedCandidateDir, scope)
	if err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}
	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}
	next.PreviousCheckpoint = &options.Checkpoint
	next.Sequence++
	next.Transition = CheckpointTransitionV4{Kind: CheckpointContributionRejected, Scope: &scope, AttemptID: options.AttemptID, Contribution: &inventory, Evidence: []ArtifactRef{}}
	next.Deliveries, err = AdvanceDeliveryV2(previous.Deliveries, options.AttemptID, DeliveryRejected, &inventory)
	if err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next, RejectedCandidateDir: options.RejectedCandidateDir})
	if err != nil {
		return RejectedCandidateCheckpointV4{}, err
	}
	return RejectedCandidateCheckpointV4{Checkpoint: next, Scope: scope, Candidate: inventory, Canonical: canonical}, nil
}

// rejectedCandidateInventoryV4 hashes exactly the fixed candidate filenames
// without interpreting their contents. That lets an invalid candidate be
// retained and identified safely without treating an unverified attestation or
// cleanup claim as valid evidence.
func rejectedCandidateInventoryV4(dir string, scope ContributionScope) (CandidateInventory, error) {
	reader, err := openCheckpointReaderV4(dir)
	if err != nil {
		return CandidateInventory{}, err
	}
	defer func() { _ = reader.root.Close() }()
	expected := []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"}
	entries, err := reader.root.Open(".")
	if err != nil {
		return CandidateInventory{}, err
	}
	names, err := entries.Readdirnames(len(expected) + 1)
	_ = entries.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return CandidateInventory{}, err
	}
	if len(names) != len(expected) {
		return CandidateInventory{}, errors.New("rejected directory does not contain the exact complete candidate inventory")
	}
	files := make([]ArtifactRef, 0, len(expected))
	for _, name := range expected {
		if !slices.Contains(names, name) {
			return CandidateInventory{}, errors.New("rejected directory has missing or extra candidate files")
		}
		limit := int64(maxSignedRecordBytes)
		if name == "contribution.bin" {
			limit = MaxArtifactSize
		} else if name == "attestation.sig" || name == "erasure.sig" {
			limit = 4096
		}
		ref, err := rejectedCandidateFileRefV4(reader, name, limit)
		if err != nil {
			return CandidateInventory{}, err
		}
		files = append(files, ref)
	}
	inventory := CandidateInventory{Schema: CandidateInventorySchemaV1, Scope: scope, Files: files}
	if err := inventory.Validate(); err != nil {
		return CandidateInventory{}, err
	}
	return inventory, nil
}

func rejectedCandidateFileRefV4(reader *checkpointReaderV4, name string, limit int64) (ArtifactRef, error) {
	before, err := reader.root.Lstat(name)
	if err != nil {
		return ArtifactRef{}, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return ArtifactRef{}, errors.New("rejected candidate file must be a bounded regular file")
	}
	f, err := reader.root.Open(name)
	if err != nil {
		return ArtifactRef{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return ArtifactRef{}, err
	}
	if !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return ArtifactRef{}, errors.New("rejected candidate file changed while opening")
	}
	sha := sha256.New()
	blake, err := blake2b.New256(nil)
	if err != nil {
		return ArtifactRef{}, err
	}
	size, err := io.Copy(io.MultiWriter(sha, blake), io.LimitReader(f, limit+1))
	if err != nil {
		return ArtifactRef{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return ArtifactRef{}, err
	}
	if size != before.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return ArtifactRef{}, errors.New("rejected candidate file changed while reading")
	}
	return ArtifactRef{Name: name, Digest: Digest{SHA256: fmt.Sprintf("sha256:%x", sha.Sum(nil)), Blake2b256: fmt.Sprintf("blake2b256:%x", blake.Sum(nil)), Size: size}}, nil
}

// VerifyAndAcceptAllocatedCandidateV4 authenticates the allocation, verifies
// the candidate mathematics, publishes immutable accepted artifacts, and
// prepares the exact next checkpoint. No phase, participant, index, or input
// chain path is accepted from the caller.
func VerifyAndAcceptAllocatedCandidateV4(options AcceptAllocatedCandidateV4Options) (AcceptedCandidateCheckpointV4, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return AcceptedCandidateCheckpointV4{}, fmt.Errorf("attempt ID: %w", err)
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	if stored.trusted.Definition.Schema != DefinitionSchemaV4 {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate acceptance requires definition v4")
	}
	allocation, ok := stored.ancestry.allocations[options.AttemptID]
	if !ok || allocation.Scope == nil {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate attempt is not allocated by the authenticated checkpoint ancestry")
	}
	previous := stored.ancestry.head
	scope := *allocation.Scope
	active := false
	for _, slot := range previous.Deliveries {
		if slot.AttemptID == options.AttemptID && slot.Kind == CheckpointSubmissionCandidate && slot.Status == DeliveryAllocated && slot.Scope == scope {
			active = true
		}
	}
	if !active {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate allocation is no longer active at the authenticated checkpoint")
	}
	if err := previous.Progress.currentTurn(scope); err != nil {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, err
	}
	if err := stored.reader.root.Close(); err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}

	state := previous.Progress.Phase1
	if scope.Phase == Phase2 {
		state = *previous.Progress.Phase2
	}
	paths := PhaseTranscriptPaths{RootDir: options.ArtifactRoot, ChainPath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(state.Chain.Record.Name)), ChainSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(state.Chain.Signature.Name))}
	accept := AcceptContributionFilesOptions{Trust: options.Trust, Circuit: options.Circuit, Phase: scope.Phase, Transcript: paths, CandidateDir: options.CandidateDir, CoordinatorPrivateKeyPath: options.CoordinatorPrivateKeyPath, AcceptedAt: options.AcceptedAt}
	if scope.Phase == Phase2 {
		if previous.Progress.Phase1Seal == nil {
			return AcceptedCandidateCheckpointV4{}, errors.New("phase2 acceptance requires the authenticated phase1 seal")
		}
		accept.Phase1SealPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Progress.Phase1Seal.Record.Name))
		accept.Phase1SealSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Progress.Phase1Seal.Signature.Name))
	}
	accepted, err := VerifyAndAcceptContribution(accept)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	acceptedPaths := PhaseTranscriptPaths{RootDir: options.ArtifactRoot, ChainPath: accepted.ChainPath, ChainSignaturePath: accepted.ChainSignaturePath}
	var chain Chain
	var chainRefs SignedArtifactRefs
	if scope.Phase == Phase1 {
		chain, chainRefs, err = VerifyAcceptedPhase1Chain(options.Trust, options.Circuit, acceptedPaths)
	} else {
		chain, chainRefs, err = VerifyAcceptedPhase2Chain(options.Trust, options.Circuit, options.ArtifactRoot, accept.Phase1SealPath, accept.Phase1SealSignaturePath, acceptedPaths)
	}
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	last := chain.Records[len(chain.Records)-1]
	files := []ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	inventory := CandidateInventory{Schema: CandidateInventorySchemaV1, Scope: scope, Files: slices.Clone(files)}
	for i := range inventory.Files {
		inventory.Files[i].Name = filepath.Base(inventory.Files[i].Name)
	}
	if err := inventory.Validate(); err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	evidence := append(slices.Clone(files), last.Verification)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })

	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	next.PreviousCheckpoint = &options.Checkpoint
	next.Sequence++
	kind := CheckpointPhase1CandidateAccepted
	if scope.Phase == Phase2 {
		kind = CheckpointPhase2CandidateAccepted
	}
	next.Transition = CheckpointTransitionV4{Kind: kind, Scope: &scope, AttemptID: options.AttemptID, Record: &chainRefs, Evidence: evidence, Contribution: &inventory}
	next.Deliveries, err = AdvanceDeliveryV2(previous.Deliveries, options.AttemptID, DeliveryAccepted, &inventory)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	payload, err := chain.HeadPayload()
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	nextState := CheckpointPhaseState{Phase: scope.Phase, AcceptedCount: scope.Index, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}
	if scope.Phase == Phase1 {
		next.Progress.Phase1 = nextState
	} else {
		next.Progress.Phase2 = &nextState
	}
	next.AcceptedArtifacts = appendUniqueSortedArtifactsV4(previous.AcceptedArtifacts, append(signedArtifacts(&chainRefs), evidence...)...)
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next, Circuit: options.Circuit})
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	return AcceptedCandidateCheckpointV4{Checkpoint: next, Scope: scope, Candidate: inventory, Accepted: accepted, Canonical: canonical}, nil
}

func cloneCheckpointForTurnV4(value CheckpointV4) (CheckpointV4, error) {
	data, err := MarshalCanonical(value)
	if err != nil {
		return CheckpointV4{}, err
	}
	var cloned CheckpointV4
	if err := UnmarshalCanonical(data, &cloned); err != nil {
		return CheckpointV4{}, err
	}
	return cloned, nil
}

func appendUniqueSortedArtifactsV4(base []ArtifactRef, values ...ArtifactRef) []ArtifactRef {
	result := slices.Clone(base)
	if result == nil {
		// V4 distinguishes an explicit empty artifact set from a missing/null
		// set. Some lifecycle records have no auxiliary evidence, but they must
		// still encode evidence as [] rather than omitting the list.
		result = []ArtifactRef{}
	}
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
