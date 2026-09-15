package mpcceremony

import (
	"errors"
	"time"
)

// Collection does not repeat auditor mathematics; the existing signed audit
// asserts that replay. Release still checks the full signed audit minimum.
func verifyCheckpointAuditsV4(reader *checkpointReaderV4, d CeremonyDefinition, p CheckpointProgressV4, enrollments map[string]EnrollmentRecord, refs []SignedArtifactRefs, requireMinimum bool) (time.Time, error) {
	if p.FinalCandidate == nil {
		return time.Time{}, errors.New("audit collection requires a frozen final candidate")
	}
	if len(refs) > MaxAuditors {
		return time.Time{}, errors.New("audit collection exceeds supported auditor count")
	}
	rb, sb, err := reader.pair(*p.FinalCandidate)
	if err != nil {
		return time.Time{}, err
	}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return time.Time{}, err
	}
	var candidate CandidateMetadata
	if err = VerifySignedRecord(rb, sb, &candidate, d.Coordinator.KeyID, key); err != nil {
		return time.Time{}, err
	}
	if candidate.CeremonyID != d.CeremonyID {
		return time.Time{}, errors.New("audit candidate belongs to another ceremony")
	}
	inputs := make([]signedAuditInput, 0, len(refs))
	for _, ref := range refs {
		raw, sig, err := reader.pair(ref)
		if err != nil {
			return time.Time{}, err
		}
		var record AuditRecord
		if err = UnmarshalCanonical(raw, &record); err != nil {
			return time.Time{}, err
		}
		enrollment, ok := enrollments[record.AuditorID]
		if !ok || enrollment.Role != EnrollmentAuditor || enrollment.Identity.KeyID != record.AuditorKeyID {
			return time.Time{}, errors.New("audit signer requires its committed auditor enrollment")
		}
		inputs = append(inputs, signedAuditInput{record: raw, signature: sig, name: ref.Record.Name})
	}
	_, latest, err := verifyAuditCollection(d, candidate, inputs, requireMinimum)
	return latest, err
}
