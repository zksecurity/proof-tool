package mpcceremony

import (
	"errors"
	"fmt"
	"slices"
)

// V4 checkpoints can have 16,384 predecessors with names up to 512 bytes.
// Bound only the V3 transcript, which embeds their exact dependency inventory;
// ordinary signed records retain the existing 16 MiB bound.
const maxFinalTranscriptV3Bytes = 64 << 20

func newFinalTranscriptV3(d CeremonyDefinition, candidate CandidateMetadata, review ReleaseReviewV4) (FinalTranscript, error) {
	if !d.UsesCoordinatorReplay() {
		return FinalTranscript{}, errors.New("final transcript v3 requires definition v4")
	}
	audits := make([]ArtifactRef, len(review.Audits))
	for i, pair := range review.Audits {
		audits[i] = pair.Record
	}
	return NewFinalTranscript(FinalTranscript{
		Schema: FinalTranscriptSchemaV3, CeremonyID: d.CeremonyID,
		AssurancePolicy: cloneAssurancePolicy(d.AssurancePolicy),
		Definition:      candidate.Definition, Circuit: d.Circuit,
		Phase1: candidate.Phase1, Phase2: candidate.Phase2,
		Audits: audits, OperationalEvidence: review.OperationalBundle,
		ProvingKey: candidate.ProvingKey, VerifyingKey: candidate.VerifyingKey,
		CardanoVerifyingKey: candidate.CardanoVerifyingKey,
		FinalizedAt:         review.ReleasedAt, ReleaseReview: &review,
	})
}

func validateFinalTranscriptReviewV3(t FinalTranscript) error {
	r := t.ReleaseReview
	if r == nil {
		return errors.New("final transcript v3 requires release_review")
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("final transcript release review: %w", err)
	}
	if t.CeremonyID != r.CeremonyID || t.FinalizedAt != r.ReleasedAt || t.OperationalEvidence != r.OperationalBundle {
		return errors.New("final transcript differs from its exact review scope, bundle or time")
	}
	if !slices.Contains(r.RequiredArtifacts, t.Definition) {
		return errors.New("final transcript definition is absent from reviewed dependencies")
	}
	for _, ref := range []ArtifactRef{t.ProvingKey, t.VerifyingKey, t.CardanoVerifyingKey} {
		ref.Name = "final/candidate/" + ref.Name
		if !slices.Contains(r.CandidateArtifacts, ref) {
			return errors.New("final transcript key is absent from reviewed candidate")
		}
	}
	if len(t.Audits) != len(r.Audits) {
		return errors.New("final transcript audit count differs from review")
	}
	for i, pair := range r.Audits {
		if t.Audits[i] != pair.Record {
			return errors.New("final transcript audits differ from review")
		}
	}
	return nil
}
