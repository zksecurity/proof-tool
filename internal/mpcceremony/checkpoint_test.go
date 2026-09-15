package mpcceremony

import (
	"bytes"
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
		t.Fatal("legacy definition accepted checkpoint v2")
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
