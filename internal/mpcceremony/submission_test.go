package mpcceremony

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func submissionFixture(t *testing.T) (CeremonyDefinition, Checkpoint, CheckpointSubmissionSlot, SubmissionEnvelopeV1, ed25519.PrivateKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	definition := adversarialDefinition(t)
	definitionBytes, definitionSignatureBytes, err := SignRecord(definition, definition.Coordinator.KeyID, adversarialPrivateKey(0x01))
	if err != nil {
		t.Fatal(err)
	}
	definitionRefs := SignedArtifactRefs{
		Record:    ArtifactRef{Name: "definition/ceremony.json", Digest: NewDigest(definitionBytes)},
		Signature: ArtifactRef{Name: "definition/ceremony.sig", Digest: NewDigest(definitionSignatureBytes)},
	}
	checkpoint := phase1CheckpointSequence(t)[1]
	oldDefinition := checkpoint.Definition
	checkpoint.CeremonyID = definition.CeremonyID
	checkpoint.Definition = definitionRefs
	for i, ref := range checkpoint.AcceptedArtifacts {
		switch ref {
		case oldDefinition.Record:
			checkpoint.AcceptedArtifacts[i] = definitionRefs.Record
		case oldDefinition.Signature:
			checkpoint.AcceptedArtifacts[i] = definitionRefs.Signature
		}
	}
	checkpoint.AcceptedArtifacts = checkpointArtifacts(checkpoint.AcceptedArtifacts...)
	slot := checkpoint.Submissions[0]
	participant := definition.Roster[0].Identity
	slot.IdentityID = participant.ID
	checkpoint.Submissions[0] = slot
	checkpoint.Transition.ParticipantID = participant.ID
	if err := checkpoint.Validate(); err != nil {
		t.Fatalf("checkpoint fixture: %v", err)
	}
	checkpointBytes, err := MarshalCanonical(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	envelope := SubmissionEnvelopeV1{
		Schema: SubmissionEnvelopeSchemaV1, Workflow: checkpoint.Workflow,
		CeremonyID: definition.CeremonyID, Definition: definitionRefs, RelayReleaseID: checkpoint.RelayReleaseID,
		SubmitterID: participant.ID, SubmitterKeyID: participant.KeyID, SubmitterRole: SubmissionRoleParticipant,
		Kind: slot.Kind, Phase: slot.Phase, Index: slot.Index,
		ParentCheckpointSHA256: slot.BasisCheckpointSHA256, AllocationCheckpointSHA256: NewDigest(checkpointBytes).SHA256, ParentHeadID: slot.ParentHeadID,
		AttemptID: slot.AttemptID, ManifestKey: slot.ManifestKey,
		Payloads: []ArtifactRef{
			checkpointArtifact("submissions/receipt/"+slot.AttemptID+"/handoff-receipt.json", "receipt"),
			checkpointArtifact("submissions/receipt/"+slot.AttemptID+"/handoff-receipt.sig", "receipt signature"),
		},
	}
	return definition, checkpoint, slot, envelope, adversarialPrivateKey(0x11), adversarialPrivateKey(0x01), []byte(`{"files":["handoff-receipt.json","handoff-receipt.sig"]}`)
}

func TestSubmissionEnvelopeAndAcknowledgementExactBinding(t *testing.T) {
	definition, checkpoint, slot, envelope, participantKey, coordinatorKey, manifestBytes := submissionFixture(t)
	envelopeBytes, envelopeSignatureBytes, err := SignSubmissionEnvelope(definition, checkpoint, slot, envelope, participantKey)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	verifiedEnvelope, err := VerifySignedSubmissionEnvelope(definition, checkpoint, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		t.Fatalf("verify envelope: %v", err)
	}
	envelopeRefs := SignedArtifactRefs{
		Record:    ArtifactRef{Name: "submissions/receipt/envelope.json", Digest: NewDigest(envelopeBytes)},
		Signature: ArtifactRef{Name: "submissions/receipt/envelope.sig", Digest: NewDigest(envelopeSignatureBytes)},
	}
	manifest := ArtifactRef{Name: slot.ManifestKey, Digest: NewDigest(manifestBytes)}
	ack := SubmissionAcknowledgementV1{
		Schema: SubmissionAcknowledgementSchemaV1, Workflow: envelope.Workflow, CeremonyID: envelope.CeremonyID,
		Definition: envelope.Definition, RelayReleaseID: envelope.RelayReleaseID,
		CoordinatorID: definition.Coordinator.ID, CoordinatorKeyID: definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256, ParentHeadID: envelope.ParentHeadID,
		AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifest, Result: SubmissionAccepted,
	}
	ackBytes, ackSignatureBytes, err := SignSubmissionAcknowledgement(definition, checkpoint, slot, verifiedEnvelope, envelopeRefs, manifest, ack, coordinatorKey)
	if err != nil {
		t.Fatalf("sign acknowledgement: %v", err)
	}
	verified, err := VerifySignedSubmissionAcknowledgement(definition, checkpoint, slot,
		envelopeRefs.Record.Name, envelopeRefs.Signature.Name, envelopeBytes, envelopeSignatureBytes,
		manifest.Name, manifestBytes, ackBytes, ackSignatureBytes)
	if err != nil {
		t.Fatalf("verify acknowledgement: %v", err)
	}
	if verified.Result != SubmissionAccepted {
		t.Fatalf("result = %q", verified.Result)
	}

	if _, err := VerifySignedSubmissionAcknowledgement(definition, checkpoint, slot,
		envelopeRefs.Record.Name, envelopeRefs.Signature.Name, envelopeBytes, envelopeSignatureBytes,
		manifest.Name, append(manifestBytes, 'x'), ackBytes, ackSignatureBytes); err == nil {
		t.Fatal("changed manifest accepted")
	}
	if _, _, err := SignSubmissionAcknowledgement(definition, checkpoint, slot, envelope, envelopeRefs, manifest, ack, participantKey); err == nil {
		t.Fatal("participant key accepted as coordinator acknowledgement signer")
	}
}

func TestSubmissionEnvelopeRejectsSiblingAllocationCheckpoint(t *testing.T) {
	definition, checkpoint, slot, envelope, participantKey, _, _ := submissionFixture(t)
	envelopeBytes, envelopeSignatureBytes, err := SignSubmissionEnvelope(definition, checkpoint, slot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	sibling := checkpoint
	sibling.AcceptedArtifacts = checkpointArtifacts(append(sibling.AcceptedArtifacts, checkpointArtifact("sibling/marker.json", "different signed sibling"))...)
	if err := sibling.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedSubmissionEnvelope(definition, sibling, slot, envelopeBytes, envelopeSignatureBytes); err == nil || !strings.Contains(err.Error(), "exact checkpoint") {
		t.Fatalf("sibling checkpoint replay err=%v", err)
	}
}

func TestSubmissionEnvelopeRejectsWrongSlotRoleAndInventory(t *testing.T) {
	definition, checkpoint, slot, valid, participantKey, _, _ := submissionFixture(t)
	tests := []struct {
		name   string
		mutate func(*SubmissionEnvelopeV1)
	}{
		{"ceremony", func(v *SubmissionEnvelopeV1) { v.CeremonyID = "sha256:" + strings.Repeat("d", 64) }},
		{"definition", func(v *SubmissionEnvelopeV1) { v.Definition.Record.Name = "definition/other.json" }},
		{"attempt", func(v *SubmissionEnvelopeV1) { v.AttemptID = strings.Repeat("f", 32) }},
		{"manifest", func(v *SubmissionEnvelopeV1) { v.ManifestKey = "submissions/other/manifest.json" }},
		{"index", func(v *SubmissionEnvelopeV1) { v.Index = 2 }},
		{"parent checkpoint", func(v *SubmissionEnvelopeV1) { v.ParentCheckpointSHA256 = "sha256:" + strings.Repeat("f", 64) }},
		{"parent head", func(v *SubmissionEnvelopeV1) { v.ParentHeadID = "sha256:" + strings.Repeat("e", 64) }},
		{"release", func(v *SubmissionEnvelopeV1) { v.RelayReleaseID = "different-release" }},
		{"key", func(v *SubmissionEnvelopeV1) { v.SubmitterKeyID = definition.Roster[1].Identity.KeyID }},
		{"role", func(v *SubmissionEnvelopeV1) { v.SubmitterRole = "coordinator" }},
		{"unsorted inventory", func(v *SubmissionEnvelopeV1) { v.Payloads[0], v.Payloads[1] = v.Payloads[1], v.Payloads[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := valid
			changed.Payloads = append([]ArtifactRef(nil), valid.Payloads...)
			test.mutate(&changed)
			if _, _, err := SignSubmissionEnvelope(definition, checkpoint, slot, changed, participantKey); err == nil {
				t.Fatal("changed binding accepted")
			}
		})
	}
	if _, _, err := SignSubmissionEnvelope(definition, checkpoint, slot, valid, adversarialPrivateKey(0x12)); err == nil {
		t.Fatal("wrong participant private key accepted")
	}
}

func TestRejectedSubmissionRequiresSafeReasonCode(t *testing.T) {
	definition, checkpoint, slot, envelope, participantKey, coordinatorKey, manifestBytes := submissionFixture(t)
	envelopeBytes, envelopeSignatureBytes, err := SignSubmissionEnvelope(definition, checkpoint, slot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRefs := SignedArtifactRefs{
		Record:    ArtifactRef{Name: "submissions/receipt/envelope.json", Digest: NewDigest(envelopeBytes)},
		Signature: ArtifactRef{Name: "submissions/receipt/envelope.sig", Digest: NewDigest(envelopeSignatureBytes)},
	}
	manifest := ArtifactRef{Name: slot.ManifestKey, Digest: NewDigest(manifestBytes)}
	base := SubmissionAcknowledgementV1{
		Schema: SubmissionAcknowledgementSchemaV1, Workflow: envelope.Workflow, CeremonyID: envelope.CeremonyID,
		Definition: envelope.Definition, RelayReleaseID: envelope.RelayReleaseID,
		CoordinatorID: definition.Coordinator.ID, CoordinatorKeyID: definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256, ParentHeadID: envelope.ParentHeadID,
		AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifest, Result: SubmissionRejected, ReasonCode: "invalid-signature",
	}
	if _, _, err := SignSubmissionAcknowledgement(definition, checkpoint, slot, envelope, envelopeRefs, manifest, base, coordinatorKey); err != nil {
		t.Fatalf("safe rejection: %v", err)
	}
	base.ReasonCode = "secret: detailed operator message"
	if _, _, err := SignSubmissionAcknowledgement(definition, checkpoint, slot, envelope, envelopeRefs, manifest, base, coordinatorKey); err == nil {
		t.Fatal("unsafe rejection reason accepted")
	}
}
