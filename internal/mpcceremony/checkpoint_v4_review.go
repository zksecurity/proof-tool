package mpcceremony

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

// ReleaseReviewV4 is a deterministic local result, not a signed authorization.
// Signing/packaging must recompute it against the same exact checkpoint.
type ReleaseReviewV4 struct {
	CeremonyID               string                         `json:"ceremony_id"`
	ReviewCheckpoint         SignedArtifactRefs             `json:"review_checkpoint"`
	FinalCandidateCheckpoint SignedArtifactRefs             `json:"final_candidate_checkpoint"`
	CandidateArtifacts       []ArtifactRef                  `json:"candidate_artifacts"`
	RequiredArtifacts        []ArtifactRef                  `json:"required_artifacts"`
	OperationalBundle        SignedArtifactRefs             `json:"operational_bundle"`
	Audits                   []SignedArtifactRefs           `json:"audits"`
	ReplayVerification       CheckpointReplayVerificationV4 `json:"replay_verification"`
	ReleasedAt               string                         `json:"released_at"`
}

func (r ReleaseReviewV4) Validate() error {
	if err := validateHashID("ceremony_id", r.CeremonyID); err != nil {
		return err
	}
	for _, pair := range []SignedArtifactRefs{r.ReviewCheckpoint, r.FinalCandidateCheckpoint, r.OperationalBundle} {
		if err := pair.Validate(); err != nil {
			return err
		}
	}
	if err := validateV4ArtifactSet(r.CandidateArtifacts, MaxCheckpointArtifacts); err != nil {
		return err
	}
	if len(r.CandidateArtifacts) == 0 {
		return errors.New("review requires exact candidate files")
	}
	if len(r.RequiredArtifacts) == 0 {
		return errors.New("review requires exact dependency files")
	}
	if err := validateV4ArtifactSet(r.RequiredArtifacts, maxReleaseReviewArtifactsV4); err != nil {
		return err
	}
	if r.Audits == nil {
		return errors.New("review requires explicit audits")
	}
	if len(r.Audits) > 0 {
		if err := validateSignedArtifactSet("audits", r.Audits); err != nil {
			return err
		}
	}
	if r.ReplayVerification.Method != CoordinatorReplayReleaseV1 {
		return errors.New("review requires coordinator full replay claim")
	}
	if err := r.ReplayVerification.ToolBinary.Validate(); err != nil {
		return err
	}
	return validateTimestamp("released_at", r.ReleasedAt)
}

// VerifyReleaseReviewV4 verifies signatures, exact files, lifecycle consistency
// and required evidence. It trusts the coordinator's approved replay claim;
// it never calls contribution replay and accepts no replay/circuit input.
func VerifyReleaseReviewV4(trust TrustPaths, artifactRoot string, head, bundleRefs SignedArtifactRefs, releasedAt time.Time) (ReleaseReviewV4, error) {
	return verifyReleaseReviewV4(trust, artifactRoot, head, bundleRefs, releasedAt, false)
}

func verifyReleaseReviewV4(trust TrustPaths, artifactRoot string, head, bundleRefs SignedArtifactRefs, releasedAt time.Time, flatCandidate bool) (ReleaseReviewV4, error) {
	if releasedAt.IsZero() || releasedAt.Location() != time.UTC {
		return ReleaseReviewV4{}, errors.New("release time must be nonzero UTC")
	}
	if bundleRefs.Record.Name != OperationalEvidenceBundleFile || bundleRefs.Signature.Name != OperationalEvidenceSignatureFile {
		return ReleaseReviewV4{}, errors.New("review requires the canonical operational bundle pair")
	}
	trusted, err := loadOperationalCeremony(trust)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	d := trusted.Definition
	if d.Schema != DefinitionSchemaV4 {
		return ReleaseReviewV4{}, errors.New("this review API requires definition V4; legacy replay rules are unchanged")
	}
	db, err := MarshalCanonical(d)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	ds, err := readRegularBounded(trust.DefinitionSignaturePath, 4096)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	reader, err := openCheckpointReaderV4(artifactRoot)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	defer func() { _ = reader.root.Close() }()
	reader.flatCandidate = flatCandidate
	a, err := loadCheckpointAncestryV4(reader, d, db, ds, head)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	if a.head.Progress.Terminal != nil || a.head.Progress.FinalRelease != nil || a.finalCandidateCheckpoint == nil || a.head.Progress.ReleaseReview == nil {
		return ReleaseReviewV4{}, errors.New("review requires an unreleased final candidate and its signed operational bundle checkpoint")
	}
	if *a.head.Progress.ReleaseReview != bundleRefs {
		return ReleaseReviewV4{}, errors.New("review bundle differs from the exact signed checkpoint")
	}
	raw, sig, err := reader.pair(*a.finalCandidateCheckpoint)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	final, err := VerifySignedCheckpointV4(d, db, ds, raw, sig)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	if final.Transition.Kind != CheckpointFinalCandidateRecorded || !reflect.DeepEqual(final.Progress.FinalCandidate, a.head.Progress.FinalCandidate) {
		return ReleaseReviewV4{}, errors.New("review candidate differs from its committed replay claim")
	}
	if final.Transition.Record.Record.Name != "final/candidate/"+CandidateMetadataFile || final.Transition.Record.Signature.Name != "final/candidate/"+CandidateSignatureFile {
		return ReleaseReviewV4{}, errors.New("review requires the canonical final candidate pair")
	}
	for _, ref := range append(signedArtifacts(final.Transition.Record), final.Transition.Evidence...) {
		limit := MaxArtifactSize
		if strings.HasSuffix(ref.Name, ".json") || strings.HasSuffix(ref.Name, ".sig") || strings.HasSuffix(ref.Name, ".txt") {
			limit = maxSignedRecordBytes
		}
		if _, err := reader.read(ref, limit, false); err != nil {
			return ReleaseReviewV4{}, err
		}
	}
	// Logical names belong to the authenticated protocol, not the location
	// where the signer saved its independently trusted local copy.
	definitionRef := a.head.Definition.Record
	candidateDir := filepath.Join(reader.path, "final/candidate")
	if flatCandidate {
		candidateDir = reader.path
	}
	candidate, candidateRef, err := verifyCandidate(d, definitionRef, candidateDir)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	verifyTree := verifyCandidateClosedTree
	if flatCandidate {
		verifyTree = verifyCandidateSubsetV4
	}
	candidate, inventory, err := verifyTree(d, definitionRef, candidateDir, candidate, candidateRef)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	for i := range inventory {
		inventory[i].Name = "final/candidate/" + inventory[i].Name
	}
	want := append(signedArtifacts(final.Transition.Record), final.Transition.Evidence...)
	slices.SortFunc(want, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	if !slices.Equal(inventory, want) {
		return ReleaseReviewV4{}, errors.New("review differs from committed closed candidate inventory")
	}
	if err := verifyReviewLifecycleV4(reader, trusted, a.head.Progress, candidate, candidateDir); err != nil {
		return ReleaseReviewV4{}, err
	}
	if err := verifyCandidatePublicOutputsV4(d, candidate, candidateDir); err != nil {
		return ReleaseReviewV4{}, err
	}
	bb, bs, err := reader.pair(bundleRefs)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	var bundle OperationalEvidenceBundle
	if err := VerifySignedRecord(bb, bs, &bundle, d.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
		return ReleaseReviewV4{}, err
	}
	assembledAt, _ := time.Parse(time.RFC3339Nano, bundle.AssembledAt)
	derived, err := PrepareOperationalBundleV4(trust, artifactRoot, head, assembledAt)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	canonical, err := MarshalCanonical(derived.Bundle)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	if !bytes.Equal(canonical, bb) {
		return ReleaseReviewV4{}, errors.New("signed bundle does not match the exact review checkpoint")
	}
	operational, err := verifyReleaseOperationalEvidence(d, trusted.CoordinatorPublicKey, candidate, reader.path, filepath.Join(reader.path, bundleRefs.Record.Name), filepath.Join(reader.path, bundleRefs.Signature.Name), releasedAt)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	enrollments, err := loadCheckpointEnrollmentsV4(reader, d, db, a.enrollments)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	audits := sortedSignedRefsV4(a.audits)
	latest, err := verifyCheckpointAuditsV4(reader, d, a.head.Progress, enrollments, audits, true)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	finalizedAt, _ := time.Parse(time.RFC3339Nano, candidate.FinalizedAt)
	if err := validateReleaseChronology(releasedAt, finalizedAt, latest); err != nil {
		return ReleaseReviewV4{}, err
	}
	result := ReleaseReviewV4{CeremonyID: d.CeremonyID, ReviewCheckpoint: head, FinalCandidateCheckpoint: *a.finalCandidateCheckpoint, CandidateArtifacts: inventory, OperationalBundle: bundleRefs, Audits: audits, ReplayVerification: *final.Transition.ReplayVerification, ReleasedAt: releasedAt.Format(time.RFC3339Nano)}
	result.RequiredArtifacts, err = releaseReviewDependenciesV4(reader, a, inventory, bundleRefs, operational.Verified.ReferencedArtifacts, audits)
	if err != nil {
		return ReleaseReviewV4{}, err
	}
	if err := result.Validate(); err != nil {
		return ReleaseReviewV4{}, err
	}
	// Bind every returned dependency to bytes at this root, including the
	// definition pair when the independently trusted local copy lives elsewhere.
	for _, ref := range result.RequiredArtifacts {
		if _, err := reader.read(ref, MaxArtifactSize, false); err != nil {
			return ReleaseReviewV4{}, err
		}
	}
	return result, nil
}

// Reuse the existing record validators and summary derivation, stopping before
// replayAll. All inputs come from the exact checkpoint, not alternative paths.
func verifyReviewLifecycleV4(reader *checkpointReaderV4, trusted *TrustedCeremony, p CheckpointProgressV4, candidate CandidateMetadata, candidateDir string) error {
	if p.Phase1Closure == nil || p.Phase1Beacon == nil || p.Phase1Seal == nil || p.Phase2 == nil || p.Phase2Closure == nil || p.Phase2Beacon == nil {
		return errors.New("review requires both completed phases")
	}
	r := loadedReplay{definition: trusted.Definition, phase1ChainRef: p.Phase1.Chain.Record, phase2ChainRef: p.Phase2.Chain.Record}
	// Existing final metadata uses basenames for signed chain summaries.
	r.phase1ChainRef.Name = path.Base(r.phase1ChainRef.Name)
	r.phase2ChainRef.Name = path.Base(r.phase2ChainRef.Name)
	for _, item := range []struct {
		refs   SignedArtifactRefs
		record any
	}{
		{p.Phase1.Chain, &r.phase1Chain}, {*p.Phase1Closure, &r.phase1Close}, {*p.Phase1Beacon, &r.phase1Beacon}, {*p.Phase1Seal, &r.phase1Seal},
		{p.Phase2.Chain, &r.phase2Chain}, {*p.Phase2Closure, &r.phase2Close}, {*p.Phase2Beacon, &r.phase2Beacon},
	} {
		raw, sig, err := reader.pair(item.refs)
		if err != nil {
			return err
		}
		if err := VerifySignedRecord(raw, sig, item.record, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
			return err
		}
	}
	if err := validateReplayRecords(r); err != nil {
		return err
	}
	if err := validatePhase2CloseBoundaryV4(r.phase1Close, r.phase1Beacon, r.phase2Close); err != nil {
		return err
	}
	for _, item := range []struct {
		close  CloseRecord
		beacon BeaconRecord
	}{{r.phase1Close, r.phase1Beacon}, {r.phase2Close, r.phase2Beacon}} {
		if _, err := reader.read(item.beacon.RawResponse, maxSignedRecordBytes, false); err != nil {
			return err
		}
		if err := VerifyBeaconRecordFiles(trusted, reader.path, item.close, item.beacon); err != nil {
			return err
		}
	}
	seal, err := loadCandidatePhase2Seal(trusted.Definition, candidate, candidateDir)
	if err != nil {
		return err
	}
	if err := ValidateSeal(r.phase2Close, r.phase2Beacon, seal); err != nil {
		return err
	}
	first, err := phaseSummary(r.phase1Chain, r.phase1ChainRef, r.phase1Close, r.phase1Beacon, r.phase1Seal)
	if err != nil {
		return err
	}
	second, err := phaseSummary(r.phase2Chain, r.phase2ChainRef, r.phase2Close, r.phase2Beacon, seal)
	if err != nil {
		return err
	}
	var report VerificationReport
	if _, err := readCanonicalFile(filepath.Join(candidateDir, candidate.VerificationReport.Name), &report); err != nil {
		return err
	}
	if err := validateCandidateReplayClaims(candidate, first, second, seal, report); err != nil {
		return fmt.Errorf("review lifecycle: %w", err)
	}
	return nil
}
