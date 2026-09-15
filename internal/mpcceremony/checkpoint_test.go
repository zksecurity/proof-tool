package mpcceremony

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestCheckpointSchemasPreserveLegacyAndForbidCrossVersionUse(t *testing.T) {
	currentDefinition := adversarialDefinition(t)
	current := phase1CheckpointSequence(t)[0]
	current.AssurancePolicy = cloneAssurancePolicy(currentDefinition.AssurancePolicy)
	if err := validateCheckpointDefinitionVersion(currentDefinition, current); err != nil {
		t.Fatal(err)
	}
	previousCurrent := current
	previousCurrent.Schema = CheckpointSchemaV2
	if err := validateCheckpointDefinitionVersion(currentDefinition, previousCurrent); err != nil {
		t.Fatalf("existing checkpoint v2 rejected: %v", err)
	}

	legacyCheckpoint := current
	legacyCheckpoint.Schema = CheckpointSchemaV1
	legacyCheckpoint.AssurancePolicy = nil
	if err := legacyCheckpoint.Validate(); err != nil {
		t.Fatalf("legacy checkpoint rejected: %v", err)
	}
	raw, err := MarshalCanonical(legacyCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("assurance_policy")) {
		t.Fatal("legacy checkpoint canonical bytes gained a new field")
	}
	if err := validateCheckpointDefinitionVersion(currentDefinition, legacyCheckpoint); err == nil {
		t.Fatal("definition v3 accepted checkpoint v1")
	}

	legacyDefinition := currentDefinition
	legacyDefinition.Schema = DefinitionSchemaV2
	legacyDefinition.AssurancePolicy = nil
	legacyDefinition.CeremonyID = ""
	legacyID, err := ComputeCeremonyID(legacyDefinition)
	if err != nil {
		t.Fatal(err)
	}
	legacyDefinition.CeremonyID = legacyID
	if err := validateCheckpointDefinitionVersion(legacyDefinition, current); err == nil {
		t.Fatal("legacy definition accepted checkpoint v3")
	}
	if err := validateCheckpointDefinitionVersion(legacyDefinition, legacyCheckpoint); err != nil {
		t.Fatalf("legacy definition/checkpoint pairing rejected: %v", err)
	}

	mismatch := current
	other := *mismatch.AssurancePolicy
	other.PublicWitnessesPerPhase++
	mismatch.AssurancePolicy = &other
	if err := validateCheckpointDefinitionVersion(currentDefinition, mismatch); err == nil {
		t.Fatal("checkpoint v2 accepted changed assurance policy")
	}

	next := current
	next.Schema = CheckpointSchemaV1
	next.AssurancePolicy = nil
	next.Sequence = 1
	next.PreviousCheckpoint = &SignedArtifactRefs{}
	if err := ValidateCheckpointTransition(current, next); err == nil {
		t.Fatal("checkpoint transition switched schema versions")
	}
}

func TestCheckpointV2CannotClaimPhase1ClosureOrBeacon(t *testing.T) {
	previous := phase1CheckpointSequence(t)[3]
	previous.Schema = CheckpointSchemaV2
	closed := phase1ClosedCheckpoint(t, previous)
	closed.Schema = CheckpointSchemaV2
	if err := closed.Validate(); err == nil || !strings.Contains(err.Error(), "require checkpoint v3") {
		t.Fatalf("checkpoint v2 closure err=%v", err)
	}

	closed.Schema = CheckpointSchema
	beacon := cloneCheckpoint(t, closed)
	beacon.Schema = CheckpointSchemaV2
	beacon.Phase1Beacon = func() *SignedArtifactRefs { value := checkpointSigned("legacy-beacon"); return &value }()
	beacon.Transition = CheckpointTransition{Kind: CheckpointPhase1BeaconRecorded, Phase: Phase1, Record: beacon.Phase1Beacon,
		Evidence: []ArtifactRef{checkpointArtifact("legacy-raw.json", "raw")}}
	beacon.AcceptedArtifacts = appendCheckpointArtifacts(beacon.AcceptedArtifacts, beacon.Phase1Beacon.Record, beacon.Phase1Beacon.Signature, beacon.Transition.Evidence[0])
	if err := beacon.Validate(); err == nil || !strings.Contains(err.Error(), "require checkpoint v3") {
		t.Fatalf("checkpoint v2 beacon err=%v", err)
	}
}

func checkpointArtifact(name, contents string) ArtifactRef {
	return ArtifactRef{Name: name, Digest: NewDigest([]byte(contents))}
}

func checkpointSigned(prefix string) SignedArtifactRefs {
	return SignedArtifactRefs{
		Record:    checkpointArtifact(prefix+".json", prefix+" record"),
		Signature: checkpointArtifact(prefix+".sig", prefix+" signature"),
	}
}

func checkpointArtifacts(values ...ArtifactRef) []ArtifactRef {
	result := append([]ArtifactRef(nil), values...)
	slices.SortFunc(result, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func appendCheckpointArtifacts(base []ArtifactRef, values ...ArtifactRef) []ArtifactRef {
	return checkpointArtifacts(append(append([]ArtifactRef(nil), base...), values...)...)
}

func checkpointReference(t *testing.T, checkpoint Checkpoint, suffix string) SignedArtifactRefs {
	t.Helper()
	raw, err := MarshalCanonical(checkpoint)
	if err != nil {
		t.Fatalf("marshal checkpoint reference: %v", err)
	}
	return SignedArtifactRefs{
		Record: ArtifactRef{
			Name:   "state/checkpoints/checkpoint-" + suffix + ".json",
			Digest: NewDigest(raw),
		},
		Signature: checkpointArtifact("state/checkpoints/checkpoint-"+suffix+".sig", "checkpoint "+suffix+" signature"),
	}
}

func cloneCheckpoint(t *testing.T, checkpoint Checkpoint) Checkpoint {
	t.Helper()
	raw, err := MarshalCanonical(checkpoint)
	if err != nil {
		t.Fatalf("marshal checkpoint clone: %v", err)
	}
	var result Checkpoint
	if err := UnmarshalCanonical(raw, &result); err != nil {
		t.Fatalf("unmarshal checkpoint clone: %v", err)
	}
	return result
}

func phase1CheckpointSequence(t *testing.T) [4]Checkpoint {
	t.Helper()
	definition := checkpointSigned("00-definition")
	genesis := checkpointArtifact("01-phase1-genesis.bin", "genesis")
	chain0 := checkpointSigned("02-phase1-chain-0000")
	head0 := "sha256:" + strings.Repeat("1", 64)
	participant := "participant-01"
	receiptAttempt := strings.Repeat("a", 32)
	candidateAttempt := strings.Repeat("b", 32)

	cp0 := Checkpoint{
		Schema:          CheckpointSchema,
		Workflow:        StorageFirstWorkflowV1,
		CeremonyID:      "sha256:" + strings.Repeat("c", 64),
		Definition:      definition,
		AssurancePolicy: &AssurancePolicy{PublicWitnessesPerPhase: 1, MirrorsPerAcceptedHead: 1, PassingCeremonyAudits: 1},
		RelayReleaseID:  "role-images-7ba406f",
		Sequence:        0,
		Transition:      CheckpointTransition{Kind: CheckpointInitial},
		Phase1: CheckpointPhaseState{
			Phase: Phase1, AcceptedCount: 0, HeadRecordID: head0,
			HeadPayload: genesis, Chain: chain0,
		},
		AcceptedArtifacts: checkpointArtifacts(definition.Record, definition.Signature, genesis, chain0.Record, chain0.Signature),
		Submissions:       []CheckpointSubmissionSlot{},
	}
	if err := cp0.Validate(); err != nil {
		t.Fatalf("cp0: %v", err)
	}

	handoff := checkpointSigned("10-outbound-handoff")
	cp0Ref := checkpointReference(t, cp0, "0000")
	cp1 := cloneCheckpoint(t, cp0)
	cp1.Sequence = 1
	cp1.PreviousCheckpoint = &cp0Ref
	cp1.Transition = CheckpointTransition{
		Kind: CheckpointPhase1OutboundPublished, Phase: Phase1, Index: 1,
		ParticipantID: participant, AttemptID: receiptAttempt, Record: &handoff,
	}
	cp1.AcceptedArtifacts = appendCheckpointArtifacts(cp1.AcceptedArtifacts, handoff.Record, handoff.Signature)
	cp1.Submissions = []CheckpointSubmissionSlot{{
		Kind: CheckpointSubmissionReceipt, Phase: Phase1, Index: 1,
		IdentityID: participant, AttemptID: receiptAttempt,
		ManifestKey:           "submissions/receipt/" + receiptAttempt + "/manifest.json",
		BasisCheckpointSHA256: cp0Ref.Record.Digest.SHA256, ParentHeadID: head0,
		Status: CheckpointSubmissionAllocated,
	}}

	receipt := checkpointSigned("20-receipt-envelope")
	receiptAck := checkpointSigned("21-receipt-acknowledgement")
	receiptManifest := checkpointArtifact("22-receipt-manifest.json", "receipt manifest")
	receiptPayload := checkpointArtifact("23-receipt.json", "receipt payload")
	receiptEvidence := checkpointArtifacts(receiptManifest, receiptPayload)
	cp1Ref := checkpointReference(t, cp1, "0001")
	cp2 := cloneCheckpoint(t, cp1)
	cp2.Sequence = 2
	cp2.PreviousCheckpoint = &cp1Ref
	cp2.Transition = CheckpointTransition{
		Kind: CheckpointPhase1ReceiptAccepted, Phase: Phase1, Index: 1,
		ParticipantID: participant, AttemptID: receiptAttempt, NextAttemptID: candidateAttempt,
		Record: &receipt, Acknowledgement: &receiptAck, Evidence: receiptEvidence,
	}
	cp2.AcceptedArtifacts = appendCheckpointArtifacts(cp2.AcceptedArtifacts, receipt.Record, receipt.Signature, receiptAck.Record, receiptAck.Signature, receiptManifest, receiptPayload)
	cp2.Submissions[0].Status = CheckpointSubmissionAccepted
	cp2.Submissions[0].Acknowledgement = &receiptAck
	cp2.Submissions = append(cp2.Submissions, CheckpointSubmissionSlot{
		Kind: CheckpointSubmissionCandidate, Phase: Phase1, Index: 1,
		IdentityID: participant, AttemptID: candidateAttempt,
		ManifestKey:           "submissions/candidate/" + candidateAttempt + "/manifest.json",
		BasisCheckpointSHA256: cp1Ref.Record.Digest.SHA256, ParentHeadID: head0,
		Status: CheckpointSubmissionAllocated,
	})

	candidate := checkpointSigned("30-candidate-envelope")
	candidateAck := checkpointSigned("31-candidate-acknowledgement")
	payload1 := checkpointArtifact("32-phase1-contribution-0001.bin", "contribution")
	chain1 := checkpointSigned("33-phase1-chain-0001")
	candidateManifest := checkpointArtifact("34-candidate-manifest.json", "candidate manifest")
	candidatePayloads := checkpointArtifacts(
		checkpointArtifact("35-attestation.json", "attestation"),
		checkpointArtifact("36-attestation.sig", "attestation signature"),
		checkpointArtifact("37-cleanup.json", "cleanup"),
		checkpointArtifact("38-cleanup.sig", "cleanup signature"),
		payload1,
	)
	candidateEvidence := checkpointArtifacts(append([]ArtifactRef{candidateManifest}, candidatePayloads...)...)
	cp2Ref := checkpointReference(t, cp2, "0002")
	cp3 := cloneCheckpoint(t, cp2)
	cp3.Sequence = 3
	cp3.PreviousCheckpoint = &cp2Ref
	cp3.Transition = CheckpointTransition{
		Kind: CheckpointPhase1CandidateAccepted, Phase: Phase1, Index: 1,
		ParticipantID: participant, AttemptID: candidateAttempt,
		Record: &candidate, Acknowledgement: &candidateAck, Evidence: candidateEvidence,
	}
	cp3.Phase1 = CheckpointPhaseState{
		Phase: Phase1, AcceptedCount: 1,
		HeadRecordID: "sha256:" + strings.Repeat("2", 64),
		HeadPayload:  payload1, Chain: chain1,
	}
	cp3.AcceptedArtifacts = appendCheckpointArtifacts(cp3.AcceptedArtifacts,
		candidate.Record, candidate.Signature, candidateAck.Record, candidateAck.Signature,
		candidateManifest, chain1.Record, chain1.Signature,
	)
	cp3.AcceptedArtifacts = appendCheckpointArtifacts(cp3.AcceptedArtifacts, candidatePayloads...)
	cp3.Submissions[1].Status = CheckpointSubmissionAccepted
	cp3.Submissions[1].Acknowledgement = &candidateAck

	return [4]Checkpoint{cp0, cp1, cp2, cp3}
}

func TestCheckpointPhase1LegalSequence(t *testing.T) {
	checkpoints := phase1CheckpointSequence(t)
	for index := range checkpoints {
		if err := checkpoints[index].Validate(); err != nil {
			t.Fatalf("checkpoint %d: %v", index, err)
		}
		raw, err := MarshalCanonical(checkpoints[index])
		if err != nil {
			t.Fatalf("checkpoint %d canonical marshal: %v", index, err)
		}
		var decoded Checkpoint
		if err := UnmarshalCanonical(raw, &decoded); err != nil {
			t.Fatalf("checkpoint %d canonical round trip: %v", index, err)
		}
	}
	for index := 1; index < len(checkpoints); index++ {
		if err := ValidateCheckpointTransition(checkpoints[index-1], checkpoints[index]); err != nil {
			t.Fatalf("transition %d: %v", index, err)
		}
	}
}

func TestCheckpointRejectsMislabeledPhase1State(t *testing.T) {
	sequence := phase1CheckpointSequence(t)
	for index := range sequence {
		changed := cloneCheckpoint(t, sequence[index])
		changed.Phase1.Phase = Phase2
		if err := changed.Validate(); err == nil || !strings.Contains(err.Error(), "phase1 state must identify phase1") {
			t.Fatalf("checkpoint %d mislabeled phase1 err=%v", index, err)
		}
	}
}

func TestCheckpointPhase1ClosureIsOneWayAndExact(t *testing.T) {
	sequence := phase1CheckpointSequence(t)
	previous := sequence[3]
	next := phase1ClosedCheckpoint(t, previous)
	if err := ValidateCheckpointTransition(previous, next); err != nil {
		t.Fatalf("valid phase1 closure: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{"changed head", func(c *Checkpoint) { c.Phase1.HeadRecordID = "sha256:" + strings.Repeat("9", 64) }},
		{"changed slots", func(c *Checkpoint) { c.Submissions = c.Submissions[:1] }},
		{"different committed closure", func(c *Checkpoint) {
			c.Phase1Closure = &SignedArtifactRefs{Record: checkpointArtifact("other.json", "other"), Signature: checkpointArtifact("other.sig", "other sig")}
		}},
		{"unexpected artifact", func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, checkpointArtifact("unexpected.json", "unexpected"))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCheckpoint(t, next)
			test.mutate(&changed)
			if err := ValidateCheckpointTransition(previous, changed); err == nil {
				t.Fatal("mutated closure unexpectedly accepted")
			}
		})
	}

	afterClose := cloneCheckpoint(t, next)
	illegalOutbound := checkpointSigned("41-illegal-outbound")
	afterClose.Transition = CheckpointTransition{
		Kind: CheckpointPhase1OutboundPublished, Phase: Phase1, Index: 2,
		ParticipantID: "participant-02", AttemptID: strings.Repeat("e", 32), Record: &illegalOutbound,
	}
	if err := validateOutboundTransition(next, afterClose, Phase1); err == nil || !strings.Contains(err.Error(), "after closure") {
		t.Fatalf("phase1 turn after closure err=%v", err)
	}

	for _, index := range []int{1, 2} {
		t.Run(fmt.Sprintf("allocated slot at checkpoint %d", index), func(t *testing.T) {
			pending := sequence[index]
			closure := phase1ClosedCheckpoint(t, pending)
			if err := ValidateCheckpointTransition(pending, closure); err == nil || !strings.Contains(err.Error(), "still allocated") {
				t.Fatalf("closure with allocated submission err=%v", err)
			}
		})
	}

	t.Run("second outbound while turn pending", func(t *testing.T) {
		pending := sequence[1]
		duplicate := cloneCheckpoint(t, pending)
		duplicate.Sequence++
		previousRef := checkpointReference(t, pending, "duplicate-outbound-parent")
		duplicate.PreviousCheckpoint = &previousRef
		record := checkpointSigned("duplicate-outbound")
		duplicate.Transition = CheckpointTransition{
			Kind: CheckpointPhase1OutboundPublished, Phase: Phase1, Index: 1,
			ParticipantID: "participant-01", AttemptID: strings.Repeat("f", 32), Record: &record,
		}
		duplicate.AcceptedArtifacts = appendCheckpointArtifacts(duplicate.AcceptedArtifacts, record.Record, record.Signature)
		duplicate.Submissions = append(duplicate.Submissions, CheckpointSubmissionSlot{
			Kind: CheckpointSubmissionReceipt, Phase: Phase1, Index: 1,
			IdentityID: "participant-01", AttemptID: strings.Repeat("f", 32),
			ManifestKey: "submissions/duplicate/manifest.json", BasisCheckpointSHA256: previousRef.Record.Digest.SHA256,
			ParentHeadID: pending.Phase1.HeadRecordID, Status: CheckpointSubmissionAllocated,
		})
		if err := ValidateCheckpointTransition(pending, duplicate); err == nil || !strings.Contains(err.Error(), "another submission attempt") {
			t.Fatalf("duplicate outbound err=%v", err)
		}
	})
}

func phase1ClosedCheckpoint(t *testing.T, previous Checkpoint) Checkpoint {
	t.Helper()
	closure := checkpointSigned("40-phase1-closure")
	previousRef := checkpointReference(t, previous, "0003")
	next := cloneCheckpoint(t, previous)
	next.Sequence++
	next.PreviousCheckpoint = &previousRef
	next.Transition = CheckpointTransition{Kind: CheckpointPhase1Closed, Phase: Phase1, Record: &closure}
	next.Phase1Closure = &closure
	next.AcceptedArtifacts = appendCheckpointArtifacts(next.AcceptedArtifacts, closure.Record, closure.Signature)
	return next
}

func TestCheckpointPhase1BeaconRequiresExactClosureAndRawResponse(t *testing.T) {
	previous := phase1ClosedCheckpoint(t, phase1CheckpointSequence(t)[3])
	beacon := checkpointSigned("50-phase1-beacon")
	raw := checkpointArtifact("51-phase1-raw-response.bin", "raw beacon")
	previousRef := checkpointReference(t, previous, "0004")
	next := cloneCheckpoint(t, previous)
	next.Sequence++
	next.PreviousCheckpoint = &previousRef
	next.Transition = CheckpointTransition{Kind: CheckpointPhase1BeaconRecorded, Phase: Phase1, Record: &beacon, Evidence: []ArtifactRef{raw}}
	next.Phase1Beacon = &beacon
	next.AcceptedArtifacts = appendCheckpointArtifacts(next.AcceptedArtifacts, beacon.Record, beacon.Signature, raw)
	if err := ValidateCheckpointTransition(previous, next); err != nil {
		t.Fatalf("valid phase1 beacon: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{"changed closure", func(c *Checkpoint) {
			c.Phase1Closure = func() *SignedArtifactRefs { value := checkpointSigned("other-closure"); return &value }()
		}},
		{"missing raw response", func(c *Checkpoint) { c.Transition.Evidence = nil }},
		{"changed slots", func(c *Checkpoint) { c.Submissions = c.Submissions[:1] }},
		{"unexpected artifact", func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, checkpointArtifact("unexpected-beacon.json", "unexpected"))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCheckpoint(t, next)
			test.mutate(&changed)
			if err := ValidateCheckpointTransition(previous, changed); err == nil {
				t.Fatal("mutated beacon unexpectedly accepted")
			}
		})
	}
}

func TestCheckpointPhase1SealRequiresExactBeaconAndCommons(t *testing.T) {
	base := phase1ClosedCheckpoint(t, phase1CheckpointSequence(t)[3])
	beaconRefs := checkpointSigned("50-phase1-beacon")
	raw := checkpointArtifact("51-phase1-raw-response.json", "raw beacon")
	beacon := cloneCheckpoint(t, base)
	beacon.Sequence++
	parent := checkpointReference(t, base, "0004")
	beacon.PreviousCheckpoint = &parent
	beacon.Transition = CheckpointTransition{Kind: CheckpointPhase1BeaconRecorded, Phase: Phase1, Record: &beaconRefs, Evidence: []ArtifactRef{raw}}
	beacon.Phase1Beacon = &beaconRefs
	beacon.AcceptedArtifacts = appendCheckpointArtifacts(beacon.AcceptedArtifacts, beaconRefs.Record, beaconRefs.Signature, raw)

	sealRefs := checkpointSigned("60-phase1-seal")
	commons := checkpointArtifact("phase1/sealed/commons.bin", "derived commons")
	sealed := cloneCheckpoint(t, beacon)
	sealed.Sequence++
	sealParent := checkpointReference(t, beacon, "0005")
	sealed.PreviousCheckpoint = &sealParent
	sealed.Transition = CheckpointTransition{Kind: CheckpointPhase1Sealed, Phase: Phase1, Record: &sealRefs, Evidence: []ArtifactRef{commons}}
	sealed.Phase1Seal = &sealRefs
	sealed.AcceptedArtifacts = appendCheckpointArtifacts(sealed.AcceptedArtifacts, sealRefs.Record, sealRefs.Signature, commons)
	if err := ValidateCheckpointTransition(beacon, sealed); err != nil {
		t.Fatalf("valid phase1 seal: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{"changed beacon", func(c *Checkpoint) {
			c.Phase1Beacon = func() *SignedArtifactRefs { value := checkpointSigned("other-beacon"); return &value }()
		}},
		{"missing commons", func(c *Checkpoint) { c.Transition.Evidence = nil }},
		{"changed head", func(c *Checkpoint) { c.Phase1.HeadRecordID = "sha256:" + strings.Repeat("8", 64) }},
		{"unexpected artifact", func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, checkpointArtifact("unexpected-seal.json", "unexpected"))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCheckpoint(t, sealed)
			test.mutate(&changed)
			if err := ValidateCheckpointTransition(beacon, changed); err == nil {
				t.Fatal("mutated phase1 seal unexpectedly accepted")
			}
		})
	}
}

func TestPhase1SealRejectsUnverifiedExtraOutputs(t *testing.T) {
	seal := SealRecord{Phase: Phase1, Outputs: []ArtifactRef{
		checkpointArtifact("phase1/sealed/commons.bin", "commons"),
		checkpointArtifact("phase1/sealed/unverified.bin", "unverified"),
	}}
	if _, err := phase1CommonsOutput(seal); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("extra Phase 1 seal output err=%v", err)
	}
}

func TestCheckpointPhase2InitializationRequiresExactGenesis(t *testing.T) {
	base := phase1ClosedCheckpoint(t, phase1CheckpointSequence(t)[3])
	beaconRefs := checkpointSigned("phase1/beacon/record")
	raw := checkpointArtifact("phase1/beacon/raw-response.bin", "raw")
	beacon := cloneCheckpoint(t, base)
	beacon.Sequence++
	beaconParent := checkpointReference(t, base, "phase1-closed")
	beacon.PreviousCheckpoint = &beaconParent
	beacon.Transition = CheckpointTransition{Kind: CheckpointPhase1BeaconRecorded, Phase: Phase1, Record: &beaconRefs, Evidence: []ArtifactRef{raw}}
	beacon.Phase1Beacon = &beaconRefs
	beacon.AcceptedArtifacts = appendCheckpointArtifacts(beacon.AcceptedArtifacts, beaconRefs.Record, beaconRefs.Signature, raw)
	sealRefs := checkpointSigned("phase1/sealed/seal")
	commons := checkpointArtifact("phase1/sealed/commons.bin", "commons")
	sealed := cloneCheckpoint(t, beacon)
	sealed.Sequence++
	sealParent := checkpointReference(t, beacon, "phase1-beacon")
	sealed.PreviousCheckpoint = &sealParent
	sealed.Transition = CheckpointTransition{Kind: CheckpointPhase1Sealed, Phase: Phase1, Record: &sealRefs, Evidence: []ArtifactRef{commons}}
	sealed.Phase1Seal = &sealRefs
	sealed.AcceptedArtifacts = appendCheckpointArtifacts(sealed.AcceptedArtifacts, sealRefs.Record, sealRefs.Signature, commons)

	chain := checkpointSigned("phase2/chain-0000")
	genesis := checkpointArtifact("phase2/genesis.bin", "phase2 genesis")
	next := cloneCheckpoint(t, sealed)
	next.Sequence++
	phase2Parent := checkpointReference(t, sealed, "phase1-sealed")
	next.PreviousCheckpoint = &phase2Parent
	next.Transition = CheckpointTransition{Kind: CheckpointPhase2Initialized, Phase: Phase2, Record: &chain, Evidence: []ArtifactRef{genesis}}
	phase2 := CheckpointPhaseState{Phase: Phase2, HeadRecordID: "sha256:" + strings.Repeat("7", 64), HeadPayload: genesis, Chain: chain}
	next.Phase2 = &phase2
	next.AcceptedArtifacts = appendCheckpointArtifacts(next.AcceptedArtifacts, chain.Record, chain.Signature, genesis)
	if err := ValidateCheckpointTransition(sealed, next); err != nil {
		t.Fatalf("valid phase2 initialization: %v", err)
	}
	changed := cloneCheckpoint(t, next)
	changed.Phase2.HeadPayload = checkpointArtifact("phase2/other.bin", "other")
	if err := ValidateCheckpointTransition(sealed, changed); err == nil {
		t.Fatal("changed phase2 genesis unexpectedly accepted")
	}
	changed = cloneCheckpoint(t, next)
	changed.AcceptedArtifacts = appendCheckpointArtifacts(changed.AcceptedArtifacts, checkpointArtifact("phase2/unexpected.bin", "unexpected"))
	if err := ValidateCheckpointTransition(sealed, changed); err == nil {
		t.Fatal("unexpected phase2 artifact accepted")
	}
	unsealed := cloneCheckpoint(t, sealed)
	unsealed.Phase1Seal = nil
	if err := ValidateCheckpointTransition(unsealed, next); err == nil {
		t.Fatal("phase2 initialization from unsealed parent accepted")
	}
	repeated := cloneCheckpoint(t, next)
	repeated.Sequence++
	repeatedParent := checkpointReference(t, next, "phase2-initialized")
	repeated.PreviousCheckpoint = &repeatedParent
	if err := ValidateCheckpointTransition(next, repeated); err == nil {
		t.Fatal("repeated phase2 initialization accepted")
	}
}

func TestCheckpointPhase2ParticipantTurnSequence(t *testing.T) {
	base := phase1ClosedCheckpoint(t, phase1CheckpointSequence(t)[3])
	beaconRefs := checkpointSigned("phase1/beacon/record")
	raw := checkpointArtifact("phase1/beacon/raw-response.bin", "raw")
	beacon := cloneCheckpoint(t, base)
	beacon.Sequence++
	parent := checkpointReference(t, base, "p2-base")
	beacon.PreviousCheckpoint = &parent
	beacon.Transition = CheckpointTransition{Kind: CheckpointPhase1BeaconRecorded, Phase: Phase1, Record: &beaconRefs, Evidence: []ArtifactRef{raw}}
	beacon.Phase1Beacon = &beaconRefs
	beacon.AcceptedArtifacts = appendCheckpointArtifacts(beacon.AcceptedArtifacts, beaconRefs.Record, beaconRefs.Signature, raw)
	sealRefs := checkpointSigned("phase1/sealed/seal")
	commons := checkpointArtifact("phase1/sealed/commons.bin", "commons")
	sealed := cloneCheckpoint(t, beacon)
	sealed.Sequence++
	sealParent := checkpointReference(t, beacon, "p2-beacon")
	sealed.PreviousCheckpoint = &sealParent
	sealed.Transition = CheckpointTransition{Kind: CheckpointPhase1Sealed, Phase: Phase1, Record: &sealRefs, Evidence: []ArtifactRef{commons}}
	sealed.Phase1Seal = &sealRefs
	sealed.AcceptedArtifacts = appendCheckpointArtifacts(sealed.AcceptedArtifacts, sealRefs.Record, sealRefs.Signature, commons)
	chain0 := checkpointSigned("phase2/chain-0000")
	genesis := checkpointArtifact("phase2/genesis.bin", "phase2 genesis")
	initialized := cloneCheckpoint(t, sealed)
	initialized.Sequence++
	initializedParent := checkpointReference(t, sealed, "p2-sealed")
	initialized.PreviousCheckpoint = &initializedParent
	initialized.Transition = CheckpointTransition{Kind: CheckpointPhase2Initialized, Phase: Phase2, Record: &chain0, Evidence: []ArtifactRef{genesis}}
	initialized.Phase2 = &CheckpointPhaseState{Phase: Phase2, HeadRecordID: "sha256:" + strings.Repeat("7", 64), HeadPayload: genesis, Chain: chain0}
	initialized.AcceptedArtifacts = appendCheckpointArtifacts(initialized.AcceptedArtifacts, chain0.Record, chain0.Signature, genesis)

	participant := "participant-01"
	receiptAttempt, candidateAttempt := strings.Repeat("c", 32), strings.Repeat("d", 32)
	handoff := checkpointSigned("phase2/handoff")
	outbound := cloneCheckpoint(t, initialized)
	outbound.Sequence++
	outboundParent := checkpointReference(t, initialized, "p2-initialized")
	outbound.PreviousCheckpoint = &outboundParent
	outbound.Transition = CheckpointTransition{Kind: CheckpointPhase2OutboundPublished, Phase: Phase2, Index: 1, ParticipantID: participant, AttemptID: receiptAttempt, Record: &handoff}
	outbound.AcceptedArtifacts = appendCheckpointArtifacts(outbound.AcceptedArtifacts, handoff.Record, handoff.Signature)
	outbound.Submissions = append(outbound.Submissions, CheckpointSubmissionSlot{Kind: CheckpointSubmissionReceipt, Phase: Phase2, Index: 1, IdentityID: participant, AttemptID: receiptAttempt, ManifestKey: "submissions/phase2-receipt/manifest.json", BasisCheckpointSHA256: outboundParent.Record.Digest.SHA256, ParentHeadID: initialized.Phase2.HeadRecordID, Status: CheckpointSubmissionAllocated})

	receiptRecord, receiptAck := checkpointSigned("phase2/receipt"), checkpointSigned("phase2/receipt-ack")
	receiptManifest := checkpointArtifact("submissions/phase2-receipt/manifest.json", "manifest")
	receiptPayload := checkpointArtifact("submissions/phase2-receipt/receipt.json", "receipt")
	receipt := cloneCheckpoint(t, outbound)
	receipt.Sequence++
	receiptParent := checkpointReference(t, outbound, "p2-outbound")
	receipt.PreviousCheckpoint = &receiptParent
	receipt.Transition = CheckpointTransition{Kind: CheckpointPhase2ReceiptAccepted, Phase: Phase2, Index: 1, ParticipantID: participant, AttemptID: receiptAttempt, NextAttemptID: candidateAttempt, Record: &receiptRecord, Acknowledgement: &receiptAck, Evidence: checkpointArtifacts(receiptManifest, receiptPayload)}
	receipt.AcceptedArtifacts = appendCheckpointArtifacts(receipt.AcceptedArtifacts, receiptRecord.Record, receiptRecord.Signature, receiptAck.Record, receiptAck.Signature, receiptManifest, receiptPayload)
	phase2ReceiptIndex := len(receipt.Submissions) - 1
	receipt.Submissions[phase2ReceiptIndex].Status = CheckpointSubmissionAccepted
	receipt.Submissions[phase2ReceiptIndex].Acknowledgement = &receiptAck
	receipt.Submissions = append(receipt.Submissions, CheckpointSubmissionSlot{Kind: CheckpointSubmissionCandidate, Phase: Phase2, Index: 1, IdentityID: participant, AttemptID: candidateAttempt, ManifestKey: "submissions/phase2-candidate/manifest.json", BasisCheckpointSHA256: receiptParent.Record.Digest.SHA256, ParentHeadID: initialized.Phase2.HeadRecordID, Status: CheckpointSubmissionAllocated})

	candidateRecord, candidateAck := checkpointSigned("phase2/candidate"), checkpointSigned("phase2/candidate-ack")
	candidateManifest := checkpointArtifact("submissions/phase2-candidate/manifest.json", "manifest")
	payload := checkpointArtifact("phase2/contributions/0001/contribution.bin", "contribution")
	candidateEvidence := checkpointArtifacts(candidateManifest, payload)
	candidate := cloneCheckpoint(t, receipt)
	candidate.Sequence++
	candidateParent := checkpointReference(t, receipt, "p2-receipt")
	candidate.PreviousCheckpoint = &candidateParent
	candidate.Transition = CheckpointTransition{Kind: CheckpointPhase2CandidateAccepted, Phase: Phase2, Index: 1, ParticipantID: participant, AttemptID: candidateAttempt, Record: &candidateRecord, Acknowledgement: &candidateAck, Evidence: candidateEvidence}
	chain1 := checkpointSigned("phase2/chain-0001")
	candidate.Phase2 = &CheckpointPhaseState{Phase: Phase2, AcceptedCount: 1, HeadRecordID: "sha256:" + strings.Repeat("8", 64), HeadPayload: payload, Chain: chain1}
	candidate.AcceptedArtifacts = appendCheckpointArtifacts(candidate.AcceptedArtifacts, candidateRecord.Record, candidateRecord.Signature, candidateAck.Record, candidateAck.Signature, candidateManifest, payload, chain1.Record, chain1.Signature)
	phase2CandidateIndex := len(candidate.Submissions) - 1
	candidate.Submissions[phase2CandidateIndex].Status = CheckpointSubmissionAccepted
	candidate.Submissions[phase2CandidateIndex].Acknowledgement = &candidateAck

	for _, edge := range [][2]Checkpoint{{initialized, outbound}, {outbound, receipt}, {receipt, candidate}} {
		if err := ValidateCheckpointTransition(edge[0], edge[1]); err != nil {
			t.Fatalf("valid phase2 turn edge %s: %v", edge[1].Transition.Kind, err)
		}
		for _, field := range []string{"closure", "beacon", "seal"} {
			changed := cloneCheckpoint(t, edge[1])
			replacement := edge[0].Definition
			switch field {
			case "closure":
				changed.Phase1Closure = &replacement
			case "beacon":
				changed.Phase1Beacon = &replacement
			case "seal":
				changed.Phase1Seal = &replacement
			}
			if err := ValidateCheckpointTransition(edge[0], changed); err == nil {
				t.Fatalf("%s edge accepted changed phase1 %s", edge[1].Transition.Kind, field)
			}
		}
	}

	closureRefs := checkpointSigned("phase2/closure/record")
	closed := cloneCheckpoint(t, candidate)
	closed.Sequence++
	closedParent := checkpointReference(t, candidate, "p2-candidate")
	closed.PreviousCheckpoint = &closedParent
	closed.Transition = CheckpointTransition{Kind: CheckpointPhase2Closed, Phase: Phase2, Record: &closureRefs}
	closed.Phase2Closure = &closureRefs
	closed.AcceptedArtifacts = appendCheckpointArtifacts(closed.AcceptedArtifacts, closureRefs.Record, closureRefs.Signature)
	if err := ValidateCheckpointTransition(candidate, closed); err != nil {
		t.Fatalf("valid phase2 closure: %v", err)
	}

	phase2BeaconRefs := checkpointSigned("phase2/beacon/record")
	phase2Raw := checkpointArtifact("phase2/beacon/raw-response.bin", "phase2 raw")
	beaconed := cloneCheckpoint(t, closed)
	beaconed.Sequence++
	beaconParent := checkpointReference(t, closed, "p2-closed")
	beaconed.PreviousCheckpoint = &beaconParent
	beaconed.Transition = CheckpointTransition{Kind: CheckpointPhase2BeaconRecorded, Phase: Phase2, Record: &phase2BeaconRefs, Evidence: []ArtifactRef{phase2Raw}}
	beaconed.Phase2Beacon = &phase2BeaconRefs
	beaconed.AcceptedArtifacts = appendCheckpointArtifacts(beaconed.AcceptedArtifacts, phase2BeaconRefs.Record, phase2BeaconRefs.Signature, phase2Raw)
	if err := ValidateCheckpointTransition(closed, beaconed); err != nil {
		t.Fatalf("valid phase2 beacon: %v", err)
	}
	finalRefs := checkpointSigned("final/candidate/candidate")
	finalEvidence := checkpointArtifacts(
		checkpointArtifact("final/candidate/candidate-checksums.sha256", "checksums"),
		checkpointArtifact("final/candidate/ownership.pk", "pk"),
	)
	finalized := cloneCheckpoint(t, beaconed)
	finalized.Sequence++
	finalParent := checkpointReference(t, beaconed, "p2-beaconed")
	finalized.PreviousCheckpoint = &finalParent
	finalized.Transition = CheckpointTransition{Kind: CheckpointFinalCandidateRecorded, Record: &finalRefs, Evidence: finalEvidence}
	finalized.FinalCandidate = &finalRefs
	finalized.AcceptedArtifacts = appendCheckpointArtifacts(finalized.AcceptedArtifacts, finalRefs.Record, finalRefs.Signature, finalEvidence[0], finalEvidence[1])
	if err := ValidateCheckpointTransition(beaconed, finalized); err != nil {
		t.Fatalf("valid final candidate: %v", err)
	}

	allocated := cloneCheckpoint(t, candidate)
	allocated.Submissions[phase2CandidateIndex].Status = CheckpointSubmissionAllocated
	if err := ValidateCheckpointTransition(allocated, closed); err == nil {
		t.Fatal("phase2 closed with an allocated submission")
	}
	repeatedClose := cloneCheckpoint(t, closed)
	repeatedClose.Sequence++
	repeatedCloseParent := checkpointReference(t, closed, "p2-closed-again")
	repeatedClose.PreviousCheckpoint = &repeatedCloseParent
	if err := ValidateCheckpointTransition(closed, repeatedClose); err == nil {
		t.Fatal("phase2 closed twice")
	}
	withoutClosure := cloneCheckpoint(t, beaconed)
	withoutClosure.Phase2Closure = nil
	if err := ValidateCheckpointTransition(candidate, withoutClosure); err == nil {
		t.Fatal("phase2 beacon accepted without closure")
	}
	repeatedBeacon := cloneCheckpoint(t, beaconed)
	repeatedBeacon.Sequence++
	repeatedBeaconParent := checkpointReference(t, beaconed, "p2-beacon-again")
	repeatedBeacon.PreviousCheckpoint = &repeatedBeaconParent
	if err := ValidateCheckpointTransition(beaconed, repeatedBeacon); err == nil {
		t.Fatal("phase2 beacon accepted twice")
	}
	changedPhase1 := cloneCheckpoint(t, closed)
	replacement := closed.Definition
	changedPhase1.Phase1Seal = &replacement
	if err := ValidateCheckpointTransition(candidate, changedPhase1); err == nil {
		t.Fatal("phase2 closure accepted changed phase1 lifecycle")
	}
	unexpected := cloneCheckpoint(t, beaconed)
	unexpected.AcceptedArtifacts = appendCheckpointArtifacts(unexpected.AcceptedArtifacts, checkpointArtifact("phase2/unexpected.bin", "unexpected"))
	if err := ValidateCheckpointTransition(closed, unexpected); err == nil {
		t.Fatal("phase2 beacon accepted an unexpected artifact")
	}
	tooEarly := cloneCheckpoint(t, finalized)
	tooEarly.Phase2Beacon = nil
	if err := ValidateCheckpointTransition(closed, tooEarly); err == nil {
		t.Fatal("final candidate accepted before phase2 beacon")
	}
	repeatedFinal := cloneCheckpoint(t, finalized)
	repeatedFinal.Sequence++
	repeatedFinalParent := checkpointReference(t, finalized, "final-again")
	repeatedFinal.PreviousCheckpoint = &repeatedFinalParent
	if err := ValidateCheckpointTransition(finalized, repeatedFinal); err == nil {
		t.Fatal("final candidate accepted twice")
	}
	extraFinal := cloneCheckpoint(t, finalized)
	extraFinal.AcceptedArtifacts = appendCheckpointArtifacts(extraFinal.AcceptedArtifacts, checkpointArtifact("final/candidate/extra.bin", "extra"))
	if err := ValidateCheckpointTransition(beaconed, extraFinal); err == nil {
		t.Fatal("final candidate accepted an extra artifact")
	}
}

func TestCheckpointOldSchemasRejectPhase2TurnTransition(t *testing.T) {
	for _, schema := range []string{CheckpointSchemaV1, CheckpointSchemaV2} {
		checkpoint := phase1CheckpointSequence(t)[0]
		checkpoint.Schema = schema
		checkpoint.Transition = CheckpointTransition{Kind: CheckpointPhase2OutboundPublished, Phase: Phase2, Index: 1, ParticipantID: "participant-01", AttemptID: strings.Repeat("e", 32), Record: func() *SignedArtifactRefs { value := checkpointSigned("phase2-outbound"); return &value }()}
		checkpoint.AcceptedArtifacts = appendCheckpointArtifacts(checkpoint.AcceptedArtifacts, checkpoint.Transition.Record.Record, checkpoint.Transition.Record.Signature)
		if schema == CheckpointSchemaV1 {
			checkpoint.AssurancePolicy = nil
		}
		if err := checkpoint.Validate(); err == nil {
			t.Fatalf("schema %s accepted phase2 turn without phase2 state", schema)
		}
	}
	for _, schema := range []string{CheckpointSchemaV1, CheckpointSchemaV2} {
		checkpoint := phase1CheckpointSequence(t)[0]
		checkpoint.Schema = schema
		if schema == CheckpointSchemaV1 {
			checkpoint.AssurancePolicy = nil
		}
		checkpoint.Submissions = []CheckpointSubmissionSlot{{
			Kind: CheckpointSubmissionReceipt, Phase: Phase2, Index: 1, IdentityID: "participant-01",
			AttemptID: strings.Repeat("f", 32), ManifestKey: "submissions/legacy/manifest.json",
			BasisCheckpointSHA256: "sha256:" + strings.Repeat("1", 64), ParentHeadID: "sha256:" + strings.Repeat("2", 64), Status: CheckpointSubmissionAllocated,
		}}
		if err := checkpoint.Validate(); err == nil {
			t.Fatalf("schema %s accepted phase2 submission slot", schema)
		}
	}
	for _, schema := range []string{CheckpointSchemaV1, CheckpointSchemaV2} {
		checkpoint := phase1CheckpointSequence(t)[0]
		checkpoint.Schema = schema
		if schema == CheckpointSchemaV1 {
			checkpoint.AssurancePolicy = nil
		}
		finalRefs := checkpointSigned("final/candidate/candidate")
		checkpoint.Transition = CheckpointTransition{Kind: CheckpointFinalCandidateRecorded, Record: &finalRefs}
		checkpoint.FinalCandidate = &finalRefs
		checkpoint.AcceptedArtifacts = appendCheckpointArtifacts(checkpoint.AcceptedArtifacts, finalRefs.Record, finalRefs.Signature)
		if err := checkpoint.Validate(); err == nil {
			t.Fatalf("schema %s accepted final-candidate state", schema)
		}
	}
}

func TestValidateCandidateReplayClaims(t *testing.T) {
	phase1 := PhaseSummary{Phase: Phase1}
	phase2 := PhaseSummary{Phase: Phase2}
	timestamp := "2026-09-15T00:00:00Z"
	candidate := CandidateMetadata{Phase1: phase1, Phase2: phase2, FinalizedAt: timestamp}
	seal := SealRecord{SealedAt: timestamp}
	report := VerificationReport{CheckedAt: timestamp}
	if err := validateCandidateReplayClaims(candidate, phase1, phase2, seal, report); err != nil {
		t.Fatalf("matching replay claims rejected: %v", err)
	}
	changed := candidate
	changed.Phase1.ContributionCount++
	if err := validateCandidateReplayClaims(changed, phase1, phase2, seal, report); err == nil {
		t.Fatal("changed Phase 1 summary accepted")
	}
	changed = candidate
	changed.Phase2.ContributionCount++
	if err := validateCandidateReplayClaims(changed, phase1, phase2, seal, report); err == nil {
		t.Fatal("changed Phase 2 summary accepted")
	}
	changed = candidate
	changed.FinalizedAt = "2026-09-15T00:00:01Z"
	if err := validateCandidateReplayClaims(changed, phase1, phase2, seal, report); err == nil {
		t.Fatal("inconsistent candidate chronology accepted")
	}
}

func TestCheckpointBoundsCoverBothMaximumParticipantSchedules(t *testing.T) {
	const turns = 2 * MaxParticipants
	if MaxCheckpointAncestry < turns*3+10 {
		t.Fatalf("ancestry bound %d cannot cover %d participant edges plus lifecycle", MaxCheckpointAncestry, turns*3)
	}
	if MaxCheckpointArtifacts < turns*21+10 {
		t.Fatalf("artifact bound %d cannot cover %d participant artifacts plus lifecycle", MaxCheckpointArtifacts, turns*21)
	}
}

func TestCheckpointPredecessorIncludesFetchableSignatureReference(t *testing.T) {
	checkpoints := phase1CheckpointSequence(t)
	parent := checkpoints[1].PreviousCheckpoint
	if parent == nil || parent.Record.Name == "" || parent.Signature.Name == "" ||
		parent.Record.Digest.SHA256 == "" || parent.Signature.Digest.SHA256 == "" {
		t.Fatal("checkpoint predecessor does not provide fetchable record and signature references")
	}
	changed := cloneCheckpoint(t, checkpoints[1])
	changed.PreviousCheckpoint.Signature = ArtifactRef{}
	if err := changed.Validate(); err == nil {
		t.Fatal("checkpoint accepted a predecessor without a fetchable signature reference")
	}
}

func TestInitialCheckpointRejectsProgressOrSubmissionState(t *testing.T) {
	cp0 := phase1CheckpointSequence(t)[0]
	advanced := cloneCheckpoint(t, cp0)
	advanced.Phase1.AcceptedCount = 1
	if err := advanced.Validate(); err == nil {
		t.Fatal("initial checkpoint accepted contribution progress")
	}
	withSubmission := cloneCheckpoint(t, cp0)
	withSubmission.Submissions = []CheckpointSubmissionSlot{{
		Kind: CheckpointSubmissionReceipt, Phase: Phase1, Index: 1,
		IdentityID: "participant-01", AttemptID: strings.Repeat("a", 32),
		ManifestKey:           "submissions/receipt/manifest.json",
		BasisCheckpointSHA256: "sha256:" + strings.Repeat("4", 64),
		ParentHeadID:          "sha256:" + strings.Repeat("5", 64),
		Status:                CheckpointSubmissionAllocated,
	}}
	if err := withSubmission.Validate(); err == nil {
		t.Fatal("initial checkpoint accepted a pending submission")
	}
}

func TestCheckpointTransitionRejectsIndependentMutations(t *testing.T) {
	valid := phase1CheckpointSequence(t)
	cases := []struct {
		name     string
		previous int
		next     int
		mutate   func(*Checkpoint)
	}{
		{"wrong predecessor digest", 0, 1, func(c *Checkpoint) { c.PreviousCheckpoint.Record.Digest = NewDigest([]byte("other")) }},
		{"skipped sequence", 0, 1, func(c *Checkpoint) { c.Sequence++ }},
		{"changed release", 0, 1, func(c *Checkpoint) { c.RelayReleaseID = "role-images-other" }},
		{"outbound advanced head", 0, 1, func(c *Checkpoint) { c.Phase1.HeadRecordID = "sha256:" + strings.Repeat("9", 64) }},
		{"receipt accepted wrong attempt", 1, 2, func(c *Checkpoint) { c.Transition.AttemptID = strings.Repeat("d", 32) }},
		{"receipt omitted candidate slot", 1, 2, func(c *Checkpoint) { c.Submissions = c.Submissions[:1] }},
		{"receipt omitted fetchable evidence", 1, 2, func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts[:len(c.AcceptedArtifacts)-1])
		}},
		{"receipt evidence not declared", 1, 2, func(c *Checkpoint) { c.Transition.Evidence = c.Transition.Evidence[:1] }},
		{"candidate did not advance head", 2, 3, func(c *Checkpoint) { c.Phase1 = valid[2].Phase1 }},
		{"candidate advanced by two", 2, 3, func(c *Checkpoint) { c.Phase1.AcceptedCount = 2 }},
		{"candidate omitted fetchable evidence", 2, 3, func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts[:len(c.AcceptedArtifacts)-1])
		}},
		{"unexpected accepted artifact", 2, 3, func(c *Checkpoint) {
			c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, checkpointArtifact("99-unexpected", "unexpected"))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			next := cloneCheckpoint(t, valid[test.next])
			test.mutate(&next)
			if err := ValidateCheckpointTransition(valid[test.previous], next); err == nil {
				t.Fatal("mutated transition unexpectedly accepted")
			}
		})
	}
	if err := ValidateCheckpointTransition(valid[0], valid[2]); err == nil {
		t.Fatal("checkpoint sequence skipped cp1")
	}
}

func TestCheckpointRejectsReusedAttemptOrManifestAndNonportableNames(t *testing.T) {
	cp1 := cloneCheckpoint(t, phase1CheckpointSequence(t)[1])
	base := cp1.Submissions[0]
	other := base
	other.Kind = CheckpointSubmissionCandidate
	other.Index = 2
	other.IdentityID = "participant-2"
	other.ManifestKey = "submissions/candidate/other/manifest.json"
	cp1.Submissions = append(cp1.Submissions, other)
	slices.SortFunc(cp1.Submissions, func(a, b CheckpointSubmissionSlot) int { return strings.Compare(a.key(), b.key()) })
	if err := cp1.Validate(); err == nil || !strings.Contains(err.Error(), "attempt IDs") {
		t.Fatalf("reused attempt err=%v", err)
	}

	cp1.Submissions[1].AttemptID = strings.Repeat("d", 32)
	cp1.Submissions[1].ManifestKey = cp1.Submissions[0].ManifestKey
	slices.SortFunc(cp1.Submissions, func(a, b CheckpointSubmissionSlot) int { return strings.Compare(a.key(), b.key()) })
	if err := cp1.Validate(); err == nil || !strings.Contains(err.Error(), "manifest keys") {
		t.Fatalf("reused manifest err=%v", err)
	}

	cp1.Submissions = cp1.Submissions[:1]
	cp1.AcceptedArtifacts[0].Name = "Phase1/portable.json"
	cp1.AcceptedArtifacts = checkpointArtifacts(cp1.AcceptedArtifacts...)
	if err := cp1.Validate(); err == nil || !strings.Contains(err.Error(), "lowercase ASCII") {
		t.Fatalf("nonportable name err=%v", err)
	}
}

func TestVerifySignedCheckpointBindsDefinitionAndCoordinator(t *testing.T) {
	definition := adversarialDefinition(t)
	definitionKey := adversarialPrivateKey(0x01)
	definitionBytes, definitionSignature, err := SignRecord(definition, definition.Coordinator.KeyID, definitionKey)
	if err != nil {
		t.Fatalf("sign definition: %v", err)
	}
	cp := phase1CheckpointSequence(t)[0]
	cp.CeremonyID = definition.CeremonyID
	cp.AssurancePolicy = cloneAssurancePolicy(definition.AssurancePolicy)
	cp.Definition = SignedArtifactRefs{
		Record:    ArtifactRef{Name: "ceremony.json", Digest: NewDigest(definitionBytes)},
		Signature: ArtifactRef{Name: "ceremony.sig", Digest: NewDigest(definitionSignature)},
	}
	cp.AcceptedArtifacts = appendCheckpointArtifacts(cp.AcceptedArtifacts[2:], cp.Definition.Record, cp.Definition.Signature)
	cpBytes, cpSignature, err := SignRecord(cp, definition.Coordinator.KeyID, definitionKey)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	if _, err := VerifySignedCheckpoint(definition, definitionBytes, definitionSignature, cpBytes, cpSignature); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	wrongPolicy := cp
	wrongPolicy.AssurancePolicy = cloneAssurancePolicy(cp.AssurancePolicy)
	wrongPolicy.AssurancePolicy.MirrorsPerAcceptedHead = 0
	wrongBytes, wrongPolicySignature, err := SignRecord(wrongPolicy, definition.Coordinator.KeyID, definitionKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpoint(definition, definitionBytes, definitionSignature, wrongBytes, wrongPolicySignature); err == nil {
		t.Fatal("checkpoint accepted an assurance policy different from the signed definition")
	}

	tamperedDefinition := append([]byte(nil), definitionBytes...)
	tamperedDefinition[len(tamperedDefinition)-1] ^= 1
	if _, err := VerifySignedCheckpoint(definition, tamperedDefinition, definitionSignature, cpBytes, cpSignature); err == nil {
		t.Fatal("checkpoint accepted tampered definition bytes")
	}
	otherKey := adversarialPrivateKey(0x22)
	_, wrongSignature, err := SignRecord(cp, "other-key", otherKey)
	if err != nil {
		t.Fatalf("sign checkpoint with other key: %v", err)
	}
	if _, err := VerifySignedCheckpoint(definition, definitionBytes, definitionSignature, cpBytes, wrongSignature); err == nil {
		t.Fatal("checkpoint accepted a non-coordinator signature")
	}
}
