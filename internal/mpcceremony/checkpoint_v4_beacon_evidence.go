package mpcceremony

import (
	"errors"
)

func checkpointClosureV4(reader *checkpointReaderV4, d CeremonyDefinition, p CheckpointProgressV4, phase Phase) (CloseRecord, []byte, ArtifactRef, error) {
	refs := p.Phase1Closure
	if phase == Phase2 {
		refs = p.Phase2Closure
	} else if phase != Phase1 {
		return CloseRecord{}, nil, ArtifactRef{}, errors.New("invalid evidence phase")
	}
	if refs == nil {
		return CloseRecord{}, nil, ArtifactRef{}, errors.New("evidence requires the committed phase closure")
	}
	rb, sb, err := reader.pair(*refs)
	if err != nil {
		return CloseRecord{}, nil, ArtifactRef{}, err
	}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return CloseRecord{}, nil, ArtifactRef{}, err
	}
	var close CloseRecord
	err = VerifySignedRecord(rb, sb, &close, d.Coordinator.KeyID, key)
	return close, rb, refs.Record, err
}

func verifyCheckpointWitnessesV4(reader *checkpointReaderV4, d CeremonyDefinition, p CheckpointProgressV4, enrollments map[string]EnrollmentRecord, refs []SignedArtifactRefs) (map[Phase]int, error) {
	counts := map[Phase]int{}
	if d.AssurancePolicy.PublicWitnessesPerPhase == 0 && len(refs) > 0 {
		return nil, errors.New("witness evidence is disabled by signed policy")
	}
	groups := map[Phase][]SignedPublicWitness{}
	for _, pair := range refs {
		rb, sb, err := reader.pair(pair)
		if err != nil {
			return nil, err
		}
		var receipt PublicWitnessReceipt
		if err = UnmarshalCanonical(rb, &receipt); err != nil {
			return nil, err
		}
		enrollment, ok := enrollments[receipt.Witness.ID]
		if !ok || enrollment.Role != EnrollmentPublicWitness || enrollment.Identity != receipt.Witness {
			return nil, errors.New("witness has no matching committed enrollment")
		}
		key, err := identityPublicKey(enrollment.Identity)
		if err != nil {
			return nil, err
		}
		_, _, closureRef, err := checkpointClosureV4(reader, d, p, receipt.Phase)
		if err != nil {
			return nil, err
		}
		if receipt.Closure != closureRef {
			return nil, errors.New("witness names another closure artifact")
		}
		groups[receipt.Phase] = append(groups[receipt.Phase], SignedPublicWitness{RecordBytes: rb, SignatureBytes: sb, TrustedKey: key})
	}
	for phase, receipts := range groups {
		closure, bytes, _, err := checkpointClosureV4(reader, d, p, phase)
		if err != nil {
			return nil, err
		}
		// Allow partial collection; the lifecycle gate enforces the full minimum.
		if err = VerifyPublicWitnessQuorum(d, closure, bytes, receipts, 1); err != nil {
			return nil, err
		}
		counts[phase] = len(receipts)
	}
	return counts, nil
}
