package mpcceremony

import (
	"errors"
	"slices"
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

func verifyCheckpointBeaconEvidenceV4(reader *checkpointReaderV4, d CeremonyDefinition, p CheckpointProgressV4, refs []SignedArtifactRefs, tx CheckpointTransitionV4) (map[Phase]bool, error) {
	result := map[Phase]bool{}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return nil, err
	}
	for _, pair := range refs {
		rb, sb, err := reader.pair(pair)
		if err != nil {
			return nil, err
		}
		var evidence MultiRelayBeaconEvidence
		if err = VerifySignedRecord(rb, sb, &evidence, d.Coordinator.KeyID, key); err != nil {
			return nil, err
		}
		closure, _, _, err := checkpointClosureV4(reader, d, p, evidence.Phase)
		if err != nil {
			return nil, err
		}
		if result[evidence.Phase] {
			return nil, errors.New("duplicate beacon evidence for phase")
		}
		beaconRefs := p.Phase1Beacon
		if evidence.Phase == Phase2 {
			beaconRefs = p.Phase2Beacon
		}
		if beaconRefs == nil {
			return nil, errors.New("beacon evidence requires the recorded phase beacon")
		}
		raw := map[string][]byte{}
		expected := []ArtifactRef{}
		for _, observation := range evidence.Observations {
			b, err := reader.read(observation.RawResponse, maxDrandResponseBytes, true)
			if err != nil {
				return nil, err
			}
			raw[observation.RelayID] = b
			expected = append(expected, observation.RawResponse)
		}
		if err = ValidateMultiRelayBeaconEvidence(d, closure, evidence, raw); err != nil {
			return nil, err
		}
		if tx.Kind == CheckpointBeaconEvidenceRecorded && tx.Record != nil && pair == *tx.Record {
			slices.SortFunc(expected, compareArtifactRefName)
			if !slices.Equal(expected, tx.Evidence) {
				return nil, errors.New("beacon evidence edge differs from its signed raw responses")
			}
		}
		result[evidence.Phase] = true
	}
	return result, nil
}
