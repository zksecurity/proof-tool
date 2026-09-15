// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"proof-tool/internal/mpcceremony"
)

func TestCheckpointPrepareSignAndFullyVerifyInitial(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	packet := filepath.Join(fixture.root, "prepared", "cp0")
	prepare := append(checkpointInitialEvidenceArgs(fixture), "--out-dir", packet)
	result := runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "prepare"}, prepare...))
	checkpointPath := result.Outputs["checkpoint"]
	requestPath := result.Outputs["signing_request"]
	if checkpointPath == "" || requestPath == "" {
		t.Fatalf("prepare outputs = %#v", result.Outputs)
	}

	keyPath := filepath.Join(fixture.root, "coordinator-signing.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	signaturePath := filepath.Join(fixture.root, "state", "cp0.sig")
	if err := os.MkdirAll(filepath.Dir(signaturePath), 0o700); err != nil {
		t.Fatal(err)
	}
	sign := append(checkpointInitialEvidenceArgs(fixture),
		"--checkpoint", checkpointPath, "--signing-request", requestPath,
		"--coordinator-signing-key", keyPath, "--out", signaturePath,
	)
	runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "sign"}, sign...))

	verify := append(checkpointInitialEvidenceArgs(fixture), "--checkpoint", checkpointPath, "--checkpoint-signature", signaturePath)
	result = runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "verify"}, verify...))
	inspection := result.CheckpointEvidenceInspection
	if inspection == nil || !inspection.FullyVerified || inspection.Sequence != 0 ||
		inspection.TransitionKind != mpcceremony.CheckpointInitial {
		t.Fatalf("evidence inspection = %#v", inspection)
	}
	storedArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--checkpoint", checkpointPath, "--checkpoint-signature", signaturePath,
	)
	result = runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "verify-stored"}, storedArgs...))
	if result.CheckpointEvidenceInspection == nil || !result.CheckpointEvidenceInspection.FullyVerified {
		t.Fatalf("stored evidence inspection = %#v", result.CheckpointEvidenceInspection)
	}
}

func TestCheckpointArtifactBytesRemainBoundAcrossPathReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "record.json")
	writeDecisionTestFile(t, path, []byte(`{"version":"A"}`), 0o600)
	data, ref, err := checkpointArtifactBytes(root, path, maxOperationalRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement.json")
	writeDecisionTestFile(t, replacement, []byte(`{"version":"B"}`), 0o600)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if ref.Digest != mpcceremony.NewDigest(data) {
		t.Fatal("returned checkpoint reference is not bound to the returned validation bytes")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Digest == mpcceremony.NewDigest(current) {
		t.Fatal("test replacement did not change the path contents")
	}
}

func TestCheckpointArtifactBytesRejectSymlinkComponents(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix checkpoint execution target")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	writeDecisionTestFile(t, filepath.Join(outside, "record.json"), []byte(`{"outside":true}`), 0o600)
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkpointArtifactBytes(root, filepath.Join(root, "redirect", "record.json"), maxOperationalRecordBytes); err == nil {
		t.Fatal("checkpoint artifact traversal followed a symbolic-link component")
	}
	writeDecisionTestFile(t, filepath.Join(root, "record.json"), []byte(`{"inside":true}`), 0o600)
	linkedRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(root, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := checkpointArtifactBytes(linkedRoot, filepath.Join(linkedRoot, "record.json"), maxOperationalRecordBytes); err == nil {
		t.Fatal("checkpoint artifact traversal accepted a symbolic-link artifact root")
	}
}

func TestCheckpointSignRejectsArbitraryValidLookingCheckpoint(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	packet := filepath.Join(fixture.root, "prepared", "cp0")
	result := runCheckpointCommandCLI(t, append(append([]string{"--format", "json", "checkpoint", "prepare"}, checkpointInitialEvidenceArgs(fixture)...), "--out-dir", packet))
	checkpointPath := result.Outputs["checkpoint"]
	raw := mustReadTestFile(t, checkpointPath)
	var checkpoint mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint.RelayReleaseID = "other-valid-release"
	changed, err := mpcceremony.MarshalCanonical(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, checkpointPath, changed, 0o600)
	keyPath := filepath.Join(fixture.root, "coordinator-signing.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	args := append(checkpointInitialEvidenceArgs(fixture),
		"--checkpoint", checkpointPath, "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", filepath.Join(fixture.root, "must-not-exist.sig"),
	)
	assertCheckpointCommandFails(t, append([]string{"--format", "json", "checkpoint", "sign"}, args...), "do not equal the checkpoint re-derived")
}

func TestCheckpointPrepareRejectsWrongOutboundSignature(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	cp0Path, cp0SignaturePath := prepareAndSignInitialCheckpoint(t, fixture)
	var cp0 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp0Path), &cp0); err != nil {
		t.Fatal(err)
	}
	participant := fixture.definition.Roster[0].Identity
	handoff, err := mpcceremony.NewTransferHandoff(
		fixture.definition, mpcceremony.Phase1, 1, cp0.Phase1.HeadRecordID,
		[]mpcceremony.ArtifactRef{cp0.Phase1.HeadPayload}, fixture.definition.Coordinator, participant,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(fixture.root, "custody", "outbound.json")
	handoffSignaturePath := filepath.Join(fixture.root, "custody", "outbound.sig")
	if err := os.MkdirAll(filepath.Dir(handoffPath), 0o700); err != nil {
		t.Fatal(err)
	}
	participantKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	handoffBytes, wrongSignature, err := mpcceremony.SignRecord(handoff, participant.KeyID, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, handoffPath, handoffBytes, 0o600)
	writeDecisionTestFile(t, handoffSignaturePath, wrongSignature, 0o600)

	args := checkpointOutboundEvidenceArgs(fixture, cp0Path, cp0SignaturePath, handoffPath, handoffSignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	args = append(args, "--out-dir", filepath.Join(fixture.root, "prepared", "cp1"))
	assertCheckpointCommandFails(t, append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "signature")
}

func TestCheckpointPrepareReceiptAcceptedAuthenticatesInnerEvidence(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	cp0Path, cp0SignaturePath := prepareAndSignInitialCheckpoint(t, fixture)
	cp1Path, cp1SignaturePath, handoff, handoffBytes := prepareAndSignOutboundCheckpoint(t, fixture, cp0Path, cp0SignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	var cp1 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp1Path), &cp1); err != nil {
		t.Fatal(err)
	}
	slot := cp1.Submissions[len(cp1.Submissions)-1]
	participantKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	receipt, err := mpcceremony.NewTransferReceipt(handoff, handoffBytes, mpcceremony.ReceiptReceiver, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID, "receipt.json")
	receiptSignaturePath := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID, "receipt.sig")
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptBytes, receiptSignatureBytes, err := mpcceremony.SignRecord(receipt, fixture.definition.Roster[0].Identity.KeyID, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, receiptPath, receiptBytes, 0o600)
	writeDecisionTestFile(t, receiptSignaturePath, receiptSignatureBytes, 0o600)
	receiptRef, err := checkpointArtifactRef(fixture.root, receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receiptSignatureRef, err := checkpointArtifactRef(fixture.root, receiptSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	payloads := checkpointSortedArtifacts(receiptRef, receiptSignatureRef)
	cp1Bytes, err := mpcceremony.MarshalCanonical(cp1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mpcceremony.SubmissionEnvelopeV1{
		Schema: mpcceremony.SubmissionEnvelopeSchemaV1, Workflow: cp1.Workflow,
		CeremonyID: cp1.CeremonyID, Definition: cp1.Definition, RelayReleaseID: cp1.RelayReleaseID,
		SubmitterID: slot.IdentityID, SubmitterKeyID: fixture.definition.Roster[0].Identity.KeyID,
		SubmitterRole: mpcceremony.SubmissionRoleParticipant, Kind: slot.Kind, Phase: slot.Phase, Index: slot.Index,
		ParentCheckpointSHA256: slot.BasisCheckpointSHA256, AllocationCheckpointSHA256: mpcceremony.NewDigest(cp1Bytes).SHA256, ParentHeadID: slot.ParentHeadID,
		AttemptID: slot.AttemptID, ManifestKey: slot.ManifestKey, Payloads: payloads,
	}
	envelopePath := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID, "envelope.json")
	envelopeSignaturePath := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID, "envelope.sig")
	envelopeBytes, envelopeSignatureBytes, err := mpcceremony.SignSubmissionEnvelope(fixture.definition, cp1, slot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, envelopePath, envelopeBytes, 0o600)
	writeDecisionTestFile(t, envelopeSignaturePath, envelopeSignatureBytes, 0o600)
	envelopeRefs, err := checkpointPairRefs(fixture.root, envelopePath, envelopeSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(slot.ManifestKey))
	manifestBytes := []byte(`{"files":["receipt.json","receipt.sig"]}`)
	writeDecisionTestFile(t, manifestPath, manifestBytes, 0o600)
	manifestRef, err := checkpointArtifactRef(fixture.root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	ack := mpcceremony.SubmissionAcknowledgementV1{
		Schema: mpcceremony.SubmissionAcknowledgementSchemaV1, Workflow: cp1.Workflow,
		CeremonyID: cp1.CeremonyID, Definition: cp1.Definition, RelayReleaseID: cp1.RelayReleaseID,
		CoordinatorID: fixture.definition.Coordinator.ID, CoordinatorKeyID: fixture.definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256, ParentHeadID: envelope.ParentHeadID,
		AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifestRef, Result: mpcceremony.SubmissionAccepted,
	}
	ackPath := filepath.Join(fixture.root, "acknowledgements", "receipt.json")
	ackSignaturePath := filepath.Join(fixture.root, "acknowledgements", "receipt.sig")
	if err := os.MkdirAll(filepath.Dir(ackPath), 0o700); err != nil {
		t.Fatal(err)
	}
	ackBytes, ackSignatureBytes, err := mpcceremony.SignSubmissionAcknowledgement(
		fixture.definition, cp1, slot, envelope, envelopeRefs, manifestRef, ack, ed25519.PrivateKey(fixture.coordinatorKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, ackPath, ackBytes, 0o600)
	writeDecisionTestFile(t, ackSignaturePath, ackSignatureBytes, 0o600)

	args := checkpointReceiptEvidenceArgs(fixture, cp1Path, cp1SignaturePath, envelopePath, envelopeSignaturePath, manifestPath, ackPath, ackSignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	cp2Packet := filepath.Join(fixture.root, "prepared", "cp2")
	result := runCheckpointCommandCLI(t, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", cp2Packet))
	var cp2 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, result.Outputs["checkpoint"]), &cp2); err != nil {
		t.Fatal(err)
	}
	if cp2.Sequence != 2 || cp2.Transition.Kind != mpcceremony.CheckpointPhase1ReceiptAccepted || len(cp2.Submissions) != 2 {
		t.Fatalf("cp2 = %#v", cp2)
	}
	keyPath := filepath.Join(fixture.root, "coordinator-key-for-cp2.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	cp2SignaturePath := filepath.Join(fixture.root, "state", "signed-cp2.sig")
	signArgs := append(args,
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp2SignaturePath,
	)
	runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "sign"}, signArgs...))
	stored := runCheckpointCommandCLI(t, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", result.Outputs["checkpoint"], "--checkpoint-signature", cp2SignaturePath, "--artifact-root", fixture.root))
	if stored.CheckpointEvidenceInspection == nil || !stored.CheckpointEvidenceInspection.FullyVerified {
		t.Fatalf("stored cp2 evidence inspection = %#v", stored.CheckpointEvidenceInspection)
	}

	writeDecisionTestFile(t, receiptSignaturePath, append(receiptSignatureBytes, '\n'), 0o600)
	assertCheckpointCommandFails(t,
		append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", filepath.Join(fixture.root, "prepared", "cp2-tampered")),
		"submission payload",
	)
	writeDecisionTestFile(t, receiptSignaturePath, receiptSignatureBytes, 0o600)
	writeDecisionTestFile(t, manifestPath, append(manifestBytes, '\n'), 0o600)
	assertCheckpointCommandFails(t,
		append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", filepath.Join(fixture.root, "prepared", "cp2-tampered-manifest")),
		"manifest",
	)
	writeDecisionTestFile(t, manifestPath, manifestBytes, 0o600)
	if err := os.Remove(receiptSignaturePath); err != nil {
		t.Fatal(err)
	}
	assertCheckpointCommandFails(t,
		append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", filepath.Join(fixture.root, "prepared", "cp2-missing-payload")),
		"submission payload",
	)
}

func TestCheckpointCommandFullLifecycleThroughPhase2Turn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("full signed workflow fixture requires Linux executable identity")
	}
	fixture, participantKey := writeWorkflowCheckpointCLIFixture(t)
	cp0Path, cp0SignaturePath := prepareAndSignInitialCheckpoint(t, fixture)
	cp1Path, cp1SignaturePath, handoff, handoffBytes := prepareAndSignOutboundCheckpoint(t, fixture, cp0Path, cp0SignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	cp2Path, cp2SignaturePath := prepareAndSignReceiptCheckpoint(t, fixture, participantKey, cp1Path, cp1SignaturePath, handoff, handoffBytes, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)

	var cp2 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp2Path), &cp2); err != nil {
		t.Fatal(err)
	}
	var candidateSlot mpcceremony.CheckpointSubmissionSlot
	for _, slot := range cp2.Submissions {
		if slot.Kind == mpcceremony.CheckpointSubmissionCandidate && slot.Status == mpcceremony.CheckpointSubmissionAllocated {
			candidateSlot = slot
		}
	}
	if candidateSlot.AttemptID == "" {
		t.Fatal("cp2 has no allocated candidate slot")
	}
	chainPath := filepath.Join(fixture.root, "phase1", "chain-0001.json")
	chainSignaturePath := filepath.Join(fixture.root, "phase1", "chain-0001.sig")
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{
		DefinitionPath: fixture.trustArgs[1], DefinitionSignaturePath: fixture.trustArgs[3], CoordinatorPublicKeyPath: fixture.trustArgs[5],
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := mpcceremony.LoadSignedChainExact(trusted, mpcceremony.PhaseTranscriptPaths{
		RootDir: fixture.root, ChainPath: chainPath, ChainSignaturePath: chainSignaturePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted := chain.Records[len(chain.Records)-1]
	payloads := checkpointSortedArtifacts(accepted.OutputPayload, accepted.Attestation, accepted.AttestationSignature, accepted.Erasure, accepted.ErasureSignature)
	envelope := mpcceremony.SubmissionEnvelopeV1{
		Schema: mpcceremony.SubmissionEnvelopeSchemaV1, Workflow: cp2.Workflow,
		CeremonyID: cp2.CeremonyID, Definition: cp2.Definition, RelayReleaseID: cp2.RelayReleaseID,
		SubmitterID: candidateSlot.IdentityID, SubmitterKeyID: fixture.definition.Roster[0].Identity.KeyID,
		SubmitterRole: mpcceremony.SubmissionRoleParticipant, Kind: candidateSlot.Kind, Phase: candidateSlot.Phase, Index: candidateSlot.Index,
		ParentCheckpointSHA256:     candidateSlot.BasisCheckpointSHA256,
		AllocationCheckpointSHA256: mpcceremony.NewDigest(mustReadTestFile(t, cp2Path)).SHA256,
		ParentHeadID:               candidateSlot.ParentHeadID,
		AttemptID:                  candidateSlot.AttemptID, ManifestKey: candidateSlot.ManifestKey, Payloads: payloads,
	}
	envelopePath := filepath.Join(fixture.root, "submissions", "candidate", candidateSlot.AttemptID, "envelope.json")
	envelopeSignaturePath := filepath.Join(fixture.root, "submissions", "candidate", candidateSlot.AttemptID, "envelope.sig")
	if err := os.MkdirAll(filepath.Dir(envelopePath), 0o700); err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeSignatureBytes, err := mpcceremony.SignSubmissionEnvelope(fixture.definition, cp2, candidateSlot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, envelopePath, envelopeBytes, 0o600)
	writeDecisionTestFile(t, envelopeSignaturePath, envelopeSignatureBytes, 0o600)
	envelopeRefs, err := checkpointPairRefs(fixture.root, envelopePath, envelopeSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(candidateSlot.ManifestKey))
	manifestBytes := []byte(`{"kind":"candidate","complete":true}`)
	writeDecisionTestFile(t, manifestPath, manifestBytes, 0o600)
	manifestRef, err := checkpointArtifactRef(fixture.root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	ack := mpcceremony.SubmissionAcknowledgementV1{
		Schema: mpcceremony.SubmissionAcknowledgementSchemaV1, Workflow: cp2.Workflow,
		CeremonyID: cp2.CeremonyID, Definition: cp2.Definition, RelayReleaseID: cp2.RelayReleaseID,
		CoordinatorID: fixture.definition.Coordinator.ID, CoordinatorKeyID: fixture.definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256:     envelope.ParentCheckpointSHA256,
		AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256,
		ParentHeadID:               envelope.ParentHeadID,
		AttemptID:                  envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifestRef, Result: mpcceremony.SubmissionAccepted,
	}
	ackPath := filepath.Join(fixture.root, "acknowledgements", "candidate.json")
	ackSignaturePath := filepath.Join(fixture.root, "acknowledgements", "candidate.sig")
	if err := os.MkdirAll(filepath.Dir(ackPath), 0o700); err != nil {
		t.Fatal(err)
	}
	ackBytes, ackSignatureBytes, err := mpcceremony.SignSubmissionAcknowledgement(
		fixture.definition, cp2, candidateSlot, envelope, envelopeRefs, manifestRef, ack, ed25519.PrivateKey(fixture.coordinatorKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, ackPath, ackBytes, 0o600)
	writeDecisionTestFile(t, ackSignaturePath, ackSignatureBytes, 0o600)

	args := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase1CandidateAccepted),
		"--previous-checkpoint", cp2Path, "--previous-checkpoint-signature", cp2SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", envelopePath, "--transition-record-signature", envelopeSignaturePath,
		"--manifest", manifestPath, "--acknowledgement", ackPath, "--acknowledgement-signature", ackSignaturePath,
	)
	cp3Packet := filepath.Join(fixture.root, "prepared", "cp3")
	result := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", cp3Packet))
	keyPath := filepath.Join(filepath.Dir(fixture.root), "identity-keys", "coordinator.ed25519.private.hex")
	cp3SignaturePath := filepath.Join(fixture.root, "state", "signed-cp3.sig")
	runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "sign"}, args...),
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp3SignaturePath))
	verified := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", result.Outputs["checkpoint"], "--checkpoint-signature", cp3SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 3 {
		t.Fatalf("cp3 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}

	closePath := filepath.Join(fixture.root, "phase1", "closure", "record.json")
	closeSignaturePath := filepath.Join(fixture.root, "phase1", "closure", "record.sig")
	closureArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase1Closed),
		"--previous-checkpoint", result.Outputs["checkpoint"], "--previous-checkpoint-signature", cp3SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", closePath, "--transition-record-signature", closeSignaturePath,
	)
	cp4Packet := filepath.Join(fixture.root, "prepared", "cp4")
	cp4 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, closureArgs...), "--out-dir", cp4Packet))
	cp4SignaturePath := filepath.Join(fixture.root, "state", "signed-cp4.sig")
	runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "sign"}, closureArgs...),
		"--checkpoint", cp4.Outputs["checkpoint"], "--signing-request", cp4.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp4SignaturePath))
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp4.Outputs["checkpoint"], "--checkpoint-signature", cp4SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 4 {
		t.Fatalf("cp4 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}

	beaconArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase1BeaconRecorded),
		"--previous-checkpoint", cp4.Outputs["checkpoint"], "--previous-checkpoint-signature", cp4SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", filepath.Join(fixture.root, "phase1", "beacon", "record.json"),
		"--transition-record-signature", filepath.Join(fixture.root, "phase1", "beacon", "record.sig"),
	)
	cp5Packet := filepath.Join(fixture.root, "prepared", "cp5")
	cp5 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, beaconArgs...), "--out-dir", cp5Packet))
	cp5SignaturePath := filepath.Join(fixture.root, "state", "signed-cp5.sig")
	runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "sign"}, beaconArgs...),
		"--checkpoint", cp5.Outputs["checkpoint"], "--signing-request", cp5.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp5SignaturePath))

	sealArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase1Sealed),
		"--previous-checkpoint", cp5.Outputs["checkpoint"], "--previous-checkpoint-signature", cp5SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", filepath.Join(fixture.root, "phase1", "sealed", "seal.json"),
		"--transition-record-signature", filepath.Join(fixture.root, "phase1", "sealed", "seal.sig"),
	)
	cp6Packet := filepath.Join(fixture.root, "prepared", "cp6")
	cp6 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, sealArgs...), "--out-dir", cp6Packet))
	cp6SignaturePath := filepath.Join(fixture.root, "state", "signed-cp6.sig")
	runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "sign"}, sealArgs...),
		"--checkpoint", cp6.Outputs["checkpoint"], "--signing-request", cp6.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp6SignaturePath))
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp6.Outputs["checkpoint"], "--checkpoint-signature", cp6SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 6 {
		t.Fatalf("cp6 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}
	phase2Genesis := filepath.Join(fixture.root, "phase2", "genesis.bin")
	phase2Chain0 := filepath.Join(fixture.root, "phase2", "chain-0000.json")
	phase2Chain0Signature := filepath.Join(fixture.root, "phase2", "chain-0000.sig")
	phase2Args := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase2Initialized),
		"--previous-checkpoint", cp6.Outputs["checkpoint"], "--previous-checkpoint-signature", cp6SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", phase2Chain0,
		"--transition-record-signature", phase2Chain0Signature,
		"--phase2-genesis", phase2Genesis,
	)
	cp7Packet := filepath.Join(fixture.root, "prepared", "cp7")
	cp7 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, phase2Args...), "--out-dir", cp7Packet))
	cp7SignaturePath := filepath.Join(fixture.root, "state", "signed-cp7.sig")
	runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "sign"}, phase2Args...),
		"--checkpoint", cp7.Outputs["checkpoint"], "--signing-request", cp7.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp7SignaturePath))
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp7.Outputs["checkpoint"], "--checkpoint-signature", cp7SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 7 {
		t.Fatalf("cp7 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}
	phase2Fixture := fixture
	phase2Fixture.chainPath, phase2Fixture.chainSignaturePath = chainPath, chainSignaturePath
	phase2Fixture.headPayloadPath = filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name))
	cp8Path, cp8SignaturePath, phase2Handoff, phase2HandoffBytes := prepareAndSignOutboundCheckpoint(t, phase2Fixture, cp7.Outputs["checkpoint"], cp7SignaturePath, mpcceremony.Phase2, phase2Chain0, phase2Chain0Signature, phase2Genesis)
	cp9Path, cp9SignaturePath := prepareAndSignReceiptCheckpoint(t, phase2Fixture, participantKey, cp8Path, cp8SignaturePath, phase2Handoff, phase2HandoffBytes, mpcceremony.Phase2, phase2Chain0, phase2Chain0Signature, phase2Genesis)
	phase2Chain1 := filepath.Join(fixture.root, "phase2", "chain-0001.json")
	phase2Chain1Signature := filepath.Join(fixture.root, "phase2", "chain-0001.sig")
	cp10Path, cp10SignaturePath := prepareAndSignCandidateCheckpoint(t, phase2Fixture, participantKey, cp9Path, cp9SignaturePath, mpcceremony.Phase2, phase2Chain1, phase2Chain1Signature)
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp10Path, "--checkpoint-signature", cp10SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 10 {
		t.Fatalf("cp10 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}
	phase2Chain, _, err := mpcceremony.LoadSignedChainExact(trusted, mpcceremony.PhaseTranscriptPaths{
		RootDir: fixture.root, ChainPath: phase2Chain1, ChainSignaturePath: phase2Chain1Signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	phase2Accepted := phase2Chain.Records[len(phase2Chain.Records)-1]
	phase2ActiveArgs := checkpointActivePhaseArgs(
		mpcceremony.Phase2,
		phase2Chain1,
		phase2Chain1Signature,
		filepath.Join(fixture.root, filepath.FromSlash(phase2Accepted.OutputPayload.Name)),
	)
	phase2ClosureArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase2Closed),
		"--previous-checkpoint", cp10Path, "--previous-checkpoint-signature", cp10SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", filepath.Join(fixture.root, "phase2", "closure", "record.json"),
		"--transition-record-signature", filepath.Join(fixture.root, "phase2", "closure", "record.sig"),
	)
	phase2ClosureArgs = append(phase2ClosureArgs, phase2ActiveArgs...)
	cp11 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, phase2ClosureArgs...), "--out-dir", filepath.Join(fixture.root, "prepared", "cp11")))
	cp11SignaturePath := filepath.Join(fixture.root, "state", "signed-cp11.sig")
	runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "sign"}, phase2ClosureArgs...),
		"--checkpoint", cp11.Outputs["checkpoint"], "--signing-request", cp11.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp11SignaturePath))
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp11.Outputs["checkpoint"], "--checkpoint-signature", cp11SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 11 {
		t.Fatalf("cp11 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}

	phase2BeaconArgs := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointPhase2BeaconRecorded),
		"--previous-checkpoint", cp11.Outputs["checkpoint"], "--previous-checkpoint-signature", cp11SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath,
		"--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", filepath.Join(fixture.root, "phase2", "beacon", "record.json"),
		"--transition-record-signature", filepath.Join(fixture.root, "phase2", "beacon", "record.sig"),
	)
	phase2BeaconArgs = append(phase2BeaconArgs, phase2ActiveArgs...)
	cp12 := runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, phase2BeaconArgs...), "--out-dir", filepath.Join(fixture.root, "prepared", "cp12")))
	cp12SignaturePath := filepath.Join(fixture.root, "state", "signed-cp12.sig")
	runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "sign"}, phase2BeaconArgs...),
		"--checkpoint", cp12.Outputs["checkpoint"], "--signing-request", cp12.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", cp12SignaturePath))
	verified = runCheckpointCommandExecutable(t, fixture.executable, append(append([]string{"--format", "json", "checkpoint", "verify-stored"}, fixture.trustArgs...),
		"--checkpoint", cp12.Outputs["checkpoint"], "--checkpoint-signature", cp12SignaturePath, "--artifact-root", fixture.root))
	if verified.CheckpointEvidenceInspection == nil || !verified.CheckpointEvidenceInspection.FullyVerified || verified.CheckpointEvidenceInspection.Sequence != 12 {
		t.Fatalf("cp12 stored verification = %#v", verified.CheckpointEvidenceInspection)
	}
	assertChangedCheckpointEvidenceFails(t, fixture.executable, phase2Args, "phase2/genesis.bin", "phase2-genesis")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, phase2Args, "phase2/chain-0000.json", "phase2-chain")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, phase2Args, "phase2/chain-0000.sig", "phase2-chain-signature")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, sealArgs, "phase1/sealed/seal.sig", "seal-signature")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, sealArgs, "phase1/sealed/commons.bin", "sealed-commons")

	assertChangedCheckpointEvidenceFails(t, fixture.executable, args, accepted.OutputPayload.Name, "candidate-payload")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, args, filepath.ToSlash(mustRelativeTestPath(t, fixture.root, manifestPath)), "manifest")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, args, filepath.ToSlash(mustRelativeTestPath(t, fixture.root, ackSignaturePath)), "acknowledgement")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, args, filepath.ToSlash(mustRelativeTestPath(t, fixture.root, chainPath)), "accepted-chain")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, phase2ClosureArgs, "phase2/closure/record.sig", "phase2-closure-signature")
	assertChangedCheckpointEvidenceFails(t, fixture.executable, phase2BeaconArgs, "phase2/beacon/raw-response.bin", "phase2-beacon-response")
}

func prepareAndSignCandidateCheckpoint(t *testing.T, fixture checkpointCLIFixture, participantKey ed25519.PrivateKey, previousPath, previousSignaturePath string, phase mpcceremony.Phase, chainPath, chainSignaturePath string) (string, string) {
	t.Helper()
	var previous mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, previousPath), &previous); err != nil {
		t.Fatal(err)
	}
	var slot mpcceremony.CheckpointSubmissionSlot
	for _, candidate := range previous.Submissions {
		if candidate.Phase == phase && candidate.Kind == mpcceremony.CheckpointSubmissionCandidate && candidate.Status == mpcceremony.CheckpointSubmissionAllocated {
			slot = candidate
		}
	}
	if slot.AttemptID == "" {
		t.Fatalf("%s checkpoint has no allocated candidate slot", phase)
	}
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: fixture.trustArgs[1], DefinitionSignaturePath: fixture.trustArgs[3], CoordinatorPublicKeyPath: fixture.trustArgs[5]})
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := mpcceremony.LoadSignedChainExact(trusted, mpcceremony.PhaseTranscriptPaths{RootDir: fixture.root, ChainPath: chainPath, ChainSignaturePath: chainSignaturePath})
	if err != nil {
		t.Fatal(err)
	}
	accepted := chain.Records[len(chain.Records)-1]
	payloads := checkpointSortedArtifacts(accepted.OutputPayload, accepted.Attestation, accepted.AttestationSignature, accepted.Erasure, accepted.ErasureSignature)
	previousBytes := mustReadTestFile(t, previousPath)
	envelope := mpcceremony.SubmissionEnvelopeV1{
		Schema: mpcceremony.SubmissionEnvelopeSchemaV1, Workflow: previous.Workflow,
		CeremonyID: previous.CeremonyID, Definition: previous.Definition, RelayReleaseID: previous.RelayReleaseID,
		SubmitterID: slot.IdentityID, SubmitterKeyID: fixture.definition.Roster[0].Identity.KeyID,
		SubmitterRole: mpcceremony.SubmissionRoleParticipant, Kind: slot.Kind, Phase: slot.Phase, Index: slot.Index,
		ParentCheckpointSHA256: slot.BasisCheckpointSHA256, AllocationCheckpointSHA256: mpcceremony.NewDigest(previousBytes).SHA256,
		ParentHeadID: slot.ParentHeadID, AttemptID: slot.AttemptID, ManifestKey: slot.ManifestKey, Payloads: payloads,
	}
	envelopeDir := filepath.Join(fixture.root, "submissions", string(phase)+"-candidate", slot.AttemptID)
	if err := os.MkdirAll(envelopeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envelopePath, envelopeSignaturePath := filepath.Join(envelopeDir, "envelope.json"), filepath.Join(envelopeDir, "envelope.sig")
	envelopeBytes, envelopeSignatureBytes, err := mpcceremony.SignSubmissionEnvelope(fixture.definition, previous, slot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, envelopePath, envelopeBytes, 0o600)
	writeDecisionTestFile(t, envelopeSignaturePath, envelopeSignatureBytes, 0o600)
	envelopeRefs, err := checkpointPairRefs(fixture.root, envelopePath, envelopeSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(slot.ManifestKey))
	manifestBytes := []byte(`{"kind":"candidate","complete":true}`)
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, manifestPath, manifestBytes, 0o600)
	manifestRef, err := checkpointArtifactRef(fixture.root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	ack := mpcceremony.SubmissionAcknowledgementV1{
		Schema: mpcceremony.SubmissionAcknowledgementSchemaV1, Workflow: previous.Workflow,
		CeremonyID: previous.CeremonyID, Definition: previous.Definition, RelayReleaseID: previous.RelayReleaseID,
		CoordinatorID: fixture.definition.Coordinator.ID, CoordinatorKeyID: fixture.definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256,
		ParentHeadID: envelope.ParentHeadID, AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifestRef, Result: mpcceremony.SubmissionAccepted,
	}
	ackPath, ackSignaturePath := filepath.Join(envelopeDir, "ack.json"), filepath.Join(envelopeDir, "ack.sig")
	ackBytes, ackSignatureBytes, err := mpcceremony.SignSubmissionAcknowledgement(fixture.definition, previous, slot, envelope, envelopeRefs, manifestRef, ack, ed25519.PrivateKey(fixture.coordinatorKey))
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, ackPath, ackBytes, 0o600)
	writeDecisionTestFile(t, ackSignaturePath, ackSignatureBytes, 0o600)
	kind := mpcceremony.CheckpointPhase1CandidateAccepted
	activeArgs := checkpointActivePhaseArgs(phase, chainPath, chainSignaturePath, filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)))
	if phase == mpcceremony.Phase2 {
		kind = mpcceremony.CheckpointPhase2CandidateAccepted
	}
	args := append(append([]string{}, fixture.trustArgs...), "--artifact-root", fixture.root, "--relay-release-id", "role-images-test",
		"--transition", string(kind), "--previous-checkpoint", previousPath, "--previous-checkpoint-signature", previousSignaturePath,
		"--transition-record", envelopePath, "--transition-record-signature", envelopeSignaturePath,
		"--manifest", manifestPath, "--acknowledgement", ackPath, "--acknowledgement-signature", ackSignaturePath)
	args = append(args, activeArgs...)
	if phase == mpcceremony.Phase2 {
		args = append(args, "--chain", fixture.chainPath, "--chain-signature", fixture.chainSignaturePath, "--head-payload", fixture.headPayloadPath)
	}
	packet := filepath.Join(fixture.root, "prepared", "signed-"+string(phase)+"-candidate")
	result := runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", packet))
	keyPath := filepath.Join(filepath.Dir(fixture.root), "identity-keys", "coordinator.ed25519.private.hex")
	signaturePath := filepath.Join(fixture.root, "state", "signed-"+string(phase)+"-candidate.sig")
	runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "sign"}, args...),
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", signaturePath))
	return result.Outputs["checkpoint"], signaturePath
}

func TestVerifyCandidateEnvelopePayloadsStreamsLargeContribution(t *testing.T) {
	root := t.TempDir()
	write := func(name string, contents []byte) mpcceremony.ArtifactRef {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		writeDecisionTestFile(t, path, contents, 0o600)
		ref, err := checkpointArtifactRef(root, path)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	large := bytes.Repeat([]byte{0x5a}, (16<<20)+1)
	accepted := mpcceremony.ChainRecord{
		OutputPayload:        write("phase1/contributions/0001/contribution.bin", large),
		Attestation:          write("phase1/contributions/0001/attestation.json", []byte(`{"attestation":true}`)),
		AttestationSignature: write("phase1/contributions/0001/attestation.sig", []byte(`{"signature":true}`)),
		Erasure:              write("phase1/contributions/0001/erasure.json", []byte(`{"cleanup":true}`)),
		ErasureSignature:     write("phase1/contributions/0001/erasure.sig", []byte(`{"signature":true}`)),
	}
	envelope := mpcceremony.SubmissionEnvelopeV1{Payloads: checkpointSortedArtifacts(
		accepted.OutputPayload, accepted.Attestation, accepted.AttestationSignature, accepted.Erasure, accepted.ErasureSignature,
	)}
	if err := verifyCandidateEnvelopePayloads(root, envelope, accepted); err != nil {
		t.Fatalf("stream exact contribution larger than operational-record cap: %v", err)
	}

	largePath := filepath.Join(root, filepath.FromSlash(accepted.OutputPayload.Name))
	f, err := os.OpenFile(largePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0x00}, int64(len(large)/2)); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateEnvelopePayloads(root, envelope, accepted); err == nil {
		t.Fatal("altered large contribution passed exact streaming digest verification")
	}
	writeDecisionTestFile(t, largePath, large, 0o600)
	if err := os.Truncate(largePath, int64(len(large)-1)); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateEnvelopePayloads(root, envelope, accepted); err == nil {
		t.Fatal("truncated large contribution passed exact streaming digest verification")
	}
}

func TestNextCheckpointParticipantRejectsCompleteMaximumSchedule(t *testing.T) {
	participants := make([]string, mpcceremony.MaxParticipants)
	for index := range participants {
		participants[index] = fmt.Sprintf("participant-%03d", index+1)
	}
	state := mpcceremony.CheckpointPhaseState{Phase: mpcceremony.Phase2, AcceptedCount: mpcceremony.MaxParticipants}
	if _, _, err := nextCheckpointParticipant(state, mpcceremony.PhasePolicy{Participants: participants, Minimum: 1}, mpcceremony.Phase2); err == nil {
		t.Fatal("complete 255-participant schedule returned another participant")
	}
}

func TestCheckpointPhase2BeaconMustDifferFromPhase1(t *testing.T) {
	phase1Close := mpcceremony.CloseRecord{BeaconProvider: "drand", BeaconNetwork: "quicknet", BeaconRound: 42}
	phase2Close := mpcceremony.CloseRecord{BeaconProvider: "drand", BeaconNetwork: "quicknet", BeaconRound: 42}
	if err := validateDistinctPhaseCloseRounds(phase1Close, phase2Close); err == nil {
		t.Fatal("phase2 closure reused phase1 beacon round")
	}
	phase2Close.BeaconRound = 43
	if err := validateDistinctPhaseCloseRounds(phase1Close, phase2Close); err != nil {
		t.Fatalf("distinct phase closure rounds: %v", err)
	}

	phase1Beacon := mpcceremony.BeaconRecord{Provider: "drand", Network: "quicknet", Round: 42, ChallengeSHA256: "sha256:" + strings.Repeat("1", 64)}
	phase2Beacon := mpcceremony.BeaconRecord{Provider: "drand", Network: "quicknet", Round: 43, ChallengeSHA256: phase1Beacon.ChallengeSHA256}
	if err := validateDistinctPhaseBeaconRecords(phase1Beacon, phase2Beacon); err == nil {
		t.Fatal("phase2 beacon reused phase1 challenge")
	}
	phase2Beacon.ChallengeSHA256 = "sha256:" + strings.Repeat("2", 64)
	phase2Beacon.Round = phase1Beacon.Round
	if err := validateDistinctPhaseBeaconRecords(phase1Beacon, phase2Beacon); err == nil {
		t.Fatal("phase2 beacon reused phase1 provider, network, and round")
	}
	phase2Beacon.Round = 43
	if err := validateDistinctPhaseBeaconRecords(phase1Beacon, phase2Beacon); err != nil {
		t.Fatalf("distinct phase beacon records: %v", err)
	}
}

func checkpointInitialEvidenceArgs(fixture checkpointCLIFixture) []string {
	return append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root,
		"--relay-release-id", "role-images-test",
		"--transition", string(mpcceremony.CheckpointInitial),
		"--chain", fixture.chainPath,
		"--chain-signature", fixture.chainSignaturePath,
		"--head-payload", fixture.headPayloadPath,
	)
}

func writeWorkflowCheckpointCLIFixture(t *testing.T) (checkpointCLIFixture, ed25519.PrivateKey) {
	t.Helper()
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	helperPath := os.Getenv("MPC_WORKFLOW_HELPER")
	if helperPath == "" {
		helperPath = filepath.Join(t.TempDir(), "mpc-workflow-helper")
		build := exec.Command("go", "build", "-o", helperPath, "./internal/mpcceremony/testdata/workflowhelper")
		build.Dir = filepath.Clean(filepath.Join(repoRoot, "..", ".."))
		if output, buildErr := build.CombinedOutput(); buildErr != nil {
			t.Fatalf("build workflow helper: %v\n%s", buildErr, output)
		}
	}
	commandPath := filepath.Join(t.TempDir(), "mpc-ceremony")
	buildCommand := exec.Command("go", "build", "-o", commandPath, "./cmd/mpc-ceremony")
	buildCommand.Dir = filepath.Clean(filepath.Join(repoRoot, "..", ".."))
	if output, buildErr := buildCommand.CombinedOutput(); buildErr != nil {
		t.Fatalf("build mpc-ceremony command: %v\n%s", buildErr, output)
	}
	workflowRoot := filepath.Join(t.TempDir(), "workflow")
	run := exec.Command(helperPath, workflowRoot)
	run.Dir = filepath.Clean(filepath.Join(repoRoot, "..", ".."))
	run.Env = append(os.Environ(),
		"MPC_CEREMONY_TEST_BINARY="+commandPath,
		"MPC_WORKFLOW_PHASE2_ONE=1",
	)
	if output, runErr := run.CombinedOutput(); runErr != nil {
		t.Fatalf("run workflow helper: %v\n%s", runErr, output)
	}
	ceremonyRoot := filepath.Join(workflowRoot, "ceremony")
	definitionPath := filepath.Join(ceremonyRoot, "ceremony.json")
	definitionSignaturePath := filepath.Join(ceremonyRoot, "ceremony.sig")
	coordinatorPublicKeyPath := filepath.Join(workflowRoot, "identity-keys", "trusted-coordinator.ed25519.public.hex")
	var definition mpcceremony.CeremonyDefinition
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, definitionPath), &definition); err != nil {
		t.Fatal(err)
	}
	coordinatorKey := readCheckpointTestKey(t, filepath.Join(workflowRoot, "identity-keys", "coordinator.ed25519.private.hex"))
	participantKey := readCheckpointTestKey(t, filepath.Join(workflowRoot, "identity-keys", "participant-01.ed25519.private.hex"))
	return checkpointCLIFixture{
		executable: commandPath,
		trustArgs: []string{
			"--ceremony", definitionPath,
			"--ceremony-signature", definitionSignaturePath,
			"--coordinator-public-key-file", coordinatorPublicKeyPath,
		},
		definition: definition, coordinatorKey: coordinatorKey, root: ceremonyRoot,
		chainPath:          filepath.Join(ceremonyRoot, "phase1", "chain-0000.json"),
		chainSignaturePath: filepath.Join(ceremonyRoot, "phase1", "chain-0000.sig"),
		headPayloadPath:    filepath.Join(ceremonyRoot, filepath.FromSlash(definition.Phase1Genesis.Name)),
	}, participantKey
}

func readCheckpointTestKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(strings.TrimSpace(string(mustReadTestFile(t, path))))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("read test key %s: decoded %d bytes, err %v", path, len(seed), err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func prepareAndSignReceiptCheckpoint(t *testing.T, fixture checkpointCLIFixture, participantKey ed25519.PrivateKey, cp1Path, cp1SignaturePath string, handoff mpcceremony.TransferHandoff, handoffBytes []byte, phase mpcceremony.Phase, activeChainPath, activeChainSignaturePath, activeHeadPath string) (string, string) {
	t.Helper()
	var cp1 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp1Path), &cp1); err != nil {
		t.Fatal(err)
	}
	slot := cp1.Submissions[len(cp1.Submissions)-1]
	receipt, err := mpcceremony.NewTransferReceipt(handoff, handoffBytes, mpcceremony.ReceiptReceiver, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	receiptDir := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID)
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath, receiptSignaturePath := filepath.Join(receiptDir, "receipt.json"), filepath.Join(receiptDir, "receipt.sig")
	receiptBytes, receiptSignatureBytes, err := mpcceremony.SignRecord(receipt, fixture.definition.Roster[0].Identity.KeyID, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, receiptPath, receiptBytes, 0o600)
	writeDecisionTestFile(t, receiptSignaturePath, receiptSignatureBytes, 0o600)
	receiptRef, err := checkpointArtifactRef(fixture.root, receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receiptSignatureRef, err := checkpointArtifactRef(fixture.root, receiptSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	cp1Bytes, err := mpcceremony.MarshalCanonical(cp1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := mpcceremony.SubmissionEnvelopeV1{
		Schema: mpcceremony.SubmissionEnvelopeSchemaV1, Workflow: cp1.Workflow,
		CeremonyID: cp1.CeremonyID, Definition: cp1.Definition, RelayReleaseID: cp1.RelayReleaseID,
		SubmitterID: slot.IdentityID, SubmitterKeyID: fixture.definition.Roster[0].Identity.KeyID,
		SubmitterRole: mpcceremony.SubmissionRoleParticipant, Kind: slot.Kind, Phase: slot.Phase, Index: slot.Index,
		ParentCheckpointSHA256:     slot.BasisCheckpointSHA256,
		AllocationCheckpointSHA256: mpcceremony.NewDigest(cp1Bytes).SHA256,
		ParentHeadID:               slot.ParentHeadID,
		AttemptID:                  slot.AttemptID, ManifestKey: slot.ManifestKey,
		Payloads: checkpointSortedArtifacts(receiptRef, receiptSignatureRef),
	}
	envelopePath, envelopeSignaturePath := filepath.Join(receiptDir, "envelope.json"), filepath.Join(receiptDir, "envelope.sig")
	envelopeBytes, envelopeSignatureBytes, err := mpcceremony.SignSubmissionEnvelope(fixture.definition, cp1, slot, envelope, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, envelopePath, envelopeBytes, 0o600)
	writeDecisionTestFile(t, envelopeSignaturePath, envelopeSignatureBytes, 0o600)
	envelopeRefs, err := checkpointPairRefs(fixture.root, envelopePath, envelopeSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(slot.ManifestKey))
	manifestBytes := []byte(`{"kind":"receipt","complete":true}`)
	writeDecisionTestFile(t, manifestPath, manifestBytes, 0o600)
	manifestRef, err := checkpointArtifactRef(fixture.root, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	ack := mpcceremony.SubmissionAcknowledgementV1{
		Schema: mpcceremony.SubmissionAcknowledgementSchemaV1, Workflow: cp1.Workflow,
		CeremonyID: cp1.CeremonyID, Definition: cp1.Definition, RelayReleaseID: cp1.RelayReleaseID,
		CoordinatorID: fixture.definition.Coordinator.ID, CoordinatorKeyID: fixture.definition.Coordinator.KeyID,
		SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
		Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256:     envelope.ParentCheckpointSHA256,
		AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256,
		ParentHeadID:               envelope.ParentHeadID,
		AttemptID:                  envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Envelope: envelopeRefs, Manifest: manifestRef, Result: mpcceremony.SubmissionAccepted,
	}
	ackDir := filepath.Join(fixture.root, "acknowledgements")
	if err := os.MkdirAll(ackDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ackPath, ackSignaturePath := filepath.Join(ackDir, string(phase)+"-receipt-real.json"), filepath.Join(ackDir, string(phase)+"-receipt-real.sig")
	ackBytes, ackSignatureBytes, err := mpcceremony.SignSubmissionAcknowledgement(fixture.definition, cp1, slot, envelope, envelopeRefs, manifestRef, ack, ed25519.PrivateKey(fixture.coordinatorKey))
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, ackPath, ackBytes, 0o600)
	writeDecisionTestFile(t, ackSignaturePath, ackSignatureBytes, 0o600)
	args := checkpointReceiptEvidenceArgs(fixture, cp1Path, cp1SignaturePath, envelopePath, envelopeSignaturePath, manifestPath, ackPath, ackSignaturePath, phase, activeChainPath, activeChainSignaturePath, activeHeadPath)
	packet := filepath.Join(fixture.root, "prepared", "signed-"+string(phase)+"-receipt")
	result := runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", packet))
	keyPath := filepath.Join(filepath.Dir(fixture.root), "identity-keys", "coordinator.ed25519.private.hex")
	signaturePath := filepath.Join(fixture.root, "state", "signed-"+string(phase)+"-receipt.sig")
	runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "sign"}, args...),
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", signaturePath))
	return result.Outputs["checkpoint"], signaturePath
}

func assertChangedCheckpointEvidenceFails(t *testing.T, executable string, args []string, relativePath, label string) {
	t.Helper()
	path := filepath.Join(argsValueForTest(t, args, "--artifact-root"), filepath.FromSlash(relativePath))
	original := mustReadTestFile(t, path)
	changed := append([]byte(nil), original...)
	changed[len(changed)/2] ^= 1
	writeDecisionTestFile(t, path, changed, 0o600)
	assertCheckpointExecutableFails(t, executable, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...),
		"--out-dir", filepath.Join(argsValueForTest(t, args, "--artifact-root"), "prepared", "cp3-tampered-"+label)), "")
	writeDecisionTestFile(t, path, original, 0o600)
}

func argsValueForTest(t *testing.T, args []string, name string) string {
	t.Helper()
	for i := range args {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("missing argument %s", name)
	return ""
}

func mustRelativeTestPath(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func checkpointActivePhaseArgs(phase mpcceremony.Phase, chainPath, chainSignaturePath, headPath string) []string {
	if phase == mpcceremony.Phase1 {
		return []string{"--chain", chainPath, "--chain-signature", chainSignaturePath, "--head-payload", headPath}
	}
	return []string{"--phase2-chain", chainPath, "--phase2-chain-signature", chainSignaturePath, "--phase2-head-payload", headPath}
}

func checkpointOutboundEvidenceArgs(fixture checkpointCLIFixture, cp0Path, cp0SignaturePath, handoffPath, handoffSignaturePath string, phase mpcceremony.Phase, activeChainPath, activeChainSignaturePath, activeHeadPath string) []string {
	kind := mpcceremony.CheckpointPhase1OutboundPublished
	attemptID := strings.Repeat("a", 32)
	if phase == mpcceremony.Phase2 {
		kind = mpcceremony.CheckpointPhase2OutboundPublished
		attemptID = strings.Repeat("c", 32)
	}
	args := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root,
		"--relay-release-id", "role-images-test",
		"--transition", string(kind),
		"--previous-checkpoint", cp0Path,
		"--previous-checkpoint-signature", cp0SignaturePath,
		"--transition-record", handoffPath,
		"--transition-record-signature", handoffSignaturePath,
		"--attempt-id", attemptID,
		"--manifest-key", "submissions/receipt/"+attemptID+"/manifest.json",
	)
	args = append(args, checkpointActivePhaseArgs(phase, activeChainPath, activeChainSignaturePath, activeHeadPath)...)
	if phase == mpcceremony.Phase2 {
		args = append(args, "--chain", fixture.chainPath, "--chain-signature", fixture.chainSignaturePath, "--head-payload", fixture.headPayloadPath)
	}
	return args
}

func checkpointReceiptEvidenceArgs(fixture checkpointCLIFixture, cp1Path, cp1SignaturePath, envelopePath, envelopeSignaturePath, manifestPath, ackPath, ackSignaturePath string, phase mpcceremony.Phase, activeChainPath, activeChainSignaturePath, activeHeadPath string) []string {
	kind := mpcceremony.CheckpointPhase1ReceiptAccepted
	nextAttemptID := strings.Repeat("b", 32)
	if phase == mpcceremony.Phase2 {
		kind = mpcceremony.CheckpointPhase2ReceiptAccepted
		nextAttemptID = strings.Repeat("d", 32)
	}
	args := append(append([]string{}, fixture.trustArgs...),
		"--artifact-root", fixture.root,
		"--relay-release-id", "role-images-test",
		"--transition", string(kind),
		"--previous-checkpoint", cp1Path,
		"--previous-checkpoint-signature", cp1SignaturePath,
		"--transition-record", envelopePath,
		"--transition-record-signature", envelopeSignaturePath,
		"--manifest", manifestPath,
		"--acknowledgement", ackPath,
		"--acknowledgement-signature", ackSignaturePath,
		"--next-attempt-id", nextAttemptID,
		"--next-manifest-key", "submissions/candidate/"+nextAttemptID+"/manifest.json",
	)
	args = append(args, checkpointActivePhaseArgs(phase, activeChainPath, activeChainSignaturePath, activeHeadPath)...)
	if phase == mpcceremony.Phase2 {
		args = append(args, "--chain", fixture.chainPath, "--chain-signature", fixture.chainSignaturePath, "--head-payload", fixture.headPayloadPath)
	}
	return args
}

func prepareAndSignInitialCheckpoint(t *testing.T, fixture checkpointCLIFixture) (string, string) {
	t.Helper()
	packet := filepath.Join(fixture.root, "prepared", "signed-cp0")
	result := runCheckpointCommandCLI(t, append(append([]string{"--format", "json", "checkpoint", "prepare"}, checkpointInitialEvidenceArgs(fixture)...), "--out-dir", packet))
	keyPath := filepath.Join(fixture.root, "coordinator-key-for-cp0.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	signaturePath := filepath.Join(fixture.root, "state", "signed-cp0.sig")
	if err := os.MkdirAll(filepath.Dir(signaturePath), 0o700); err != nil {
		t.Fatal(err)
	}
	args := append(checkpointInitialEvidenceArgs(fixture),
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", signaturePath,
	)
	runCheckpointCommandCLI(t, append([]string{"--format", "json", "checkpoint", "sign"}, args...))
	return result.Outputs["checkpoint"], signaturePath
}

func prepareAndSignOutboundCheckpoint(t *testing.T, fixture checkpointCLIFixture, cp0Path, cp0SignaturePath string, phase mpcceremony.Phase, activeChainPath, activeChainSignaturePath, activeHeadPath string) (string, string, mpcceremony.TransferHandoff, []byte) {
	t.Helper()
	var cp0 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp0Path), &cp0); err != nil {
		t.Fatal(err)
	}
	state := cp0.Phase1
	if phase == mpcceremony.Phase2 {
		if cp0.Phase2 == nil {
			t.Fatal("phase2 outbound parent has no phase2 state")
		}
		state = *cp0.Phase2
	}
	handoff, err := mpcceremony.NewTransferHandoff(
		fixture.definition, phase, 1, state.HeadRecordID,
		[]mpcceremony.ArtifactRef{state.HeadPayload}, fixture.definition.Coordinator, fixture.definition.Roster[0].Identity,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(fixture.root, "custody", string(phase)+"-valid-outbound.json")
	handoffSignaturePath := filepath.Join(fixture.root, "custody", string(phase)+"-valid-outbound.sig")
	if err := os.MkdirAll(filepath.Dir(handoffPath), 0o700); err != nil {
		t.Fatal(err)
	}
	handoffBytes, handoffSignatureBytes, err := mpcceremony.SignRecord(handoff, fixture.definition.Coordinator.KeyID, ed25519.PrivateKey(fixture.coordinatorKey))
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, handoffPath, handoffBytes, 0o600)
	writeDecisionTestFile(t, handoffSignaturePath, handoffSignatureBytes, 0o600)
	args := checkpointOutboundEvidenceArgs(fixture, cp0Path, cp0SignaturePath, handoffPath, handoffSignaturePath, phase, activeChainPath, activeChainSignaturePath, activeHeadPath)
	packet := filepath.Join(fixture.root, "prepared", "signed-"+string(phase)+"-outbound")
	result := runCheckpointFixtureCommand(t, fixture, append(append([]string{"--format", "json", "checkpoint", "prepare"}, args...), "--out-dir", packet))
	keyPath := filepath.Join(fixture.root, "coordinator-key-for-cp1.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	signaturePath := filepath.Join(fixture.root, "state", "signed-"+string(phase)+"-outbound.sig")
	signArgs := append(args,
		"--checkpoint", result.Outputs["checkpoint"], "--signing-request", result.Outputs["signing_request"],
		"--coordinator-signing-key", keyPath, "--out", signaturePath,
	)
	runCheckpointFixtureCommand(t, fixture, append([]string{"--format", "json", "checkpoint", "sign"}, signArgs...))
	return result.Outputs["checkpoint"], signaturePath, handoff, handoffBytes
}

func runCheckpointCommandCLI(t *testing.T, args []string) CommandResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	var result CommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func runCheckpointFixtureCommand(t *testing.T, fixture checkpointCLIFixture, args []string) CommandResult {
	t.Helper()
	if fixture.executable != "" {
		return runCheckpointCommandExecutable(t, fixture.executable, args)
	}
	return runCheckpointCommandCLI(t, args)
}

func runCheckpointCommandExecutable(t *testing.T, executable string, args []string) CommandResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := exec.Command(executable, args...)
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		t.Fatalf("run %s: %v, stdout = %q, stderr = %q", executable, err, stdout.String(), stderr.String())
	}
	var result CommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %s output: %v, stdout = %q, stderr = %q", executable, err, stdout.String(), stderr.String())
	}
	return result
}

func assertCheckpointExecutableFails(t *testing.T, executable string, args []string, want string) {
	t.Helper()
	output, err := exec.Command(executable, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("command unexpectedly succeeded: %s", output)
	}
	if !strings.Contains(string(output), want) {
		t.Fatalf("error %q does not contain %q", output, want)
	}
}

func assertCheckpointCommandFails(t *testing.T, args []string, want string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code == 0 {
		t.Fatalf("command unexpectedly succeeded: %s", stdout.String())
	}
	if combined := stdout.String() + stderr.String(); !strings.Contains(combined, want) {
		t.Fatalf("error %q does not contain %q", combined, want)
	}
}
