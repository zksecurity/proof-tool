package mpcceremony

import "errors"

// CheckpointDiscoveryV4 is only a signed discovery hint. It deliberately omits
// cumulative payload inventories. Legal ancestry must still be verified using
// VerifyStoredCheckpointV4 before the caller uses progress or deliveries.
type CheckpointDiscoveryV4 struct {
	CeremonyID               string              `json:"ceremony_id"`
	Sequence                 uint64              `json:"sequence"`
	PreviousCheckpoint       *SignedArtifactRefs `json:"previous_checkpoint,omitempty"`
	VerificationDependencies []ArtifactRef       `json:"verification_dependencies"`
	// Optional guidance dependency, not needed by structural verification.
	Enrollment *SignedArtifactRefs `json:"enrollment,omitempty"`
}

// DiscoverSignedCheckpointV4 authenticates one exact pair, without loading its
// predecessors. Dependencies are precisely the extra files read for this edge
// by the stored ancestry verifier (governance only), not all accepted artifacts.
func DiscoverSignedCheckpointV4(d CeremonyDefinition, definition, definitionSignature, record, signature []byte) (CheckpointDiscoveryV4, error) {
	c, err := VerifySignedCheckpointV4(d, definition, definitionSignature, record, signature)
	if err != nil {
		return CheckpointDiscoveryV4{}, err
	}
	r := CheckpointDiscoveryV4{CeremonyID: c.CeremonyID, Sequence: c.Sequence, PreviousCheckpoint: c.PreviousCheckpoint, VerificationDependencies: []ArtifactRef{}}
	if c.Transition.Kind == CheckpointEnrollmentRecorded {
		pair := *c.Transition.Record
		if pair.Record.Digest.Size > maxSignedRecordBytes || pair.Signature.Digest.Size > 4096 {
			return CheckpointDiscoveryV4{}, errors.New("enrollment discovery pair exceeds metadata limit")
		}
		r.Enrollment = &pair
	}
	if !isGovernanceTransitionV4(c.Transition.Kind) {
		return r, nil
	}
	add := func(ref ArtifactRef, limit int64) error {
		if ref.Digest.Size <= 0 || ref.Digest.Size > limit {
			return errors.New("checkpoint discovery dependency exceeds verification limit")
		}
		r.VerificationDependencies = append(r.VerificationDependencies, ref)
		return nil
	}
	if err := add(c.Transition.Record.Record, maxSignedRecordBytes); err != nil {
		return CheckpointDiscoveryV4{}, err
	}
	if err := add(c.Transition.Record.Signature, 4096); err != nil {
		return CheckpointDiscoveryV4{}, err
	}
	for _, ref := range c.Transition.Evidence {
		limit := int64(1 << 20)
		if next := c.Transition.RestartDefinition; next != nil {
			if ref == next.Record {
				limit = maxSignedRecordBytes
			}
			if ref == next.Signature {
				limit = 4096
			}
		}
		if err := add(ref, limit); err != nil {
			return CheckpointDiscoveryV4{}, err
		}
	}
	return r, nil
}
