// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"proof-tool/internal/mpcceremony"
)

func TestSubmissionSignAuthenticatesReceiptSlotAndAncestry(t *testing.T) {
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
	base := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID)
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath, signaturePath := filepath.Join(base, "receipt.json"), filepath.Join(base, "receipt.sig")
	receiptBytes, signatureBytes, err := mpcceremony.SignRecord(receipt, fixture.definition.Roster[0].Identity.KeyID, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, receiptPath, receiptBytes, 0o600)
	writeDecisionTestFile(t, signaturePath, signatureBytes, 0o600)
	keyPath := filepath.Join(fixture.root, "participant.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(participantKey.Seed())+"\n"), 0o600)
	out := filepath.Join(fixture.root, "participant-envelope")
	args := append(append([]string{"--format", "json", "submission", "sign"}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--checkpoint", cp1Path, "--checkpoint-signature", cp1SignaturePath,
		"--attempt-id", slot.AttemptID, "--participant-signing-key", keyPath,
		"--receipt", receiptPath, "--receipt-signature", signaturePath, "--out-dir", out)
	result := runCheckpointCommandCLI(t, args)
	envelopeBytes := mustReadTestFile(t, result.Outputs["envelope"])
	envelopeSignature := mustReadTestFile(t, result.Outputs["envelope_signature"])
	if _, err := mpcceremony.VerifySignedSubmissionEnvelope(fixture.definition, cp1, slot, envelopeBytes, envelopeSignature); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "envelope.json")); err != nil {
		t.Fatal(err)
	}
	runCheckpointCommandCLI(t, args) // byte-identical retry is idempotent
	writeDecisionTestFile(t, filepath.Join(out, "envelope.sig"), []byte("conflict"), 0o600)
	assertCheckpointCommandFails(t, args, "conflicting or incomplete")
}

func TestSubmissionSignFailurePublishesNothing(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	cp0Path, cp0SignaturePath := prepareAndSignInitialCheckpoint(t, fixture)
	cp1Path, cp1SignaturePath, _, _ := prepareAndSignOutboundCheckpoint(t, fixture, cp0Path, cp0SignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	var cp1 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp1Path), &cp1); err != nil {
		t.Fatal(err)
	}
	slot := cp1.Submissions[len(cp1.Submissions)-1]
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	keyPath := filepath.Join(fixture.root, "participant.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(key.Seed())+"\n"), 0o600)
	out := filepath.Join(fixture.root, "must-not-exist")
	args := append(append([]string{"--format", "json", "submission", "sign"}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--checkpoint", cp1Path, "--checkpoint-signature", cp1SignaturePath,
		"--attempt-id", slot.AttemptID, "--participant-signing-key", keyPath,
		"--receipt", filepath.Join(fixture.root, "missing.json"), "--receipt-signature", filepath.Join(fixture.root, "missing.sig"), "--out-dir", out)
	assertCheckpointCommandFails(t, args, "no such file")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed signing published output: %v", err)
	}
}

func TestSubmissionAcceptCreatesAtomicReceiptAcknowledgementAndCheckpoint(t *testing.T) {
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
	base := filepath.Join(fixture.root, "submissions", "receipt", slot.AttemptID)
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath, receiptSignaturePath := filepath.Join(base, "receipt.json"), filepath.Join(base, "receipt.sig")
	receiptBytes, receiptSignature, err := mpcceremony.SignRecord(receipt, fixture.definition.Roster[0].Identity.KeyID, participantKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, receiptPath, receiptBytes, 0o600)
	writeDecisionTestFile(t, receiptSignaturePath, receiptSignature, 0o600)
	participantKeyPath := filepath.Join(fixture.root, "participant.hex")
	writeDecisionTestFile(t, participantKeyPath, []byte(hex.EncodeToString(participantKey.Seed())+"\n"), 0o600)
	envelopeDir := filepath.Join(base, "signed-envelope")
	signArgs := append(append([]string{"--format", "json", "submission", "sign"}, fixture.trustArgs...), "--artifact-root", fixture.root, "--checkpoint", cp1Path, "--checkpoint-signature", cp1SignaturePath, "--attempt-id", slot.AttemptID, "--participant-signing-key", participantKeyPath, "--receipt", receiptPath, "--receipt-signature", receiptSignaturePath, "--out-dir", envelopeDir)
	runCheckpointCommandCLI(t, signArgs)
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(slot.ManifestKey))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, manifestPath, []byte(`{"complete":true}`), 0o600)
	coordinatorKeyPath := filepath.Join(fixture.root, "coordinator-accept.hex")
	writeDecisionTestFile(t, coordinatorKeyPath, []byte(hex.EncodeToString(ed25519.PrivateKey(fixture.coordinatorKey).Seed())+"\n"), 0o600)
	nextAttempt := strings.Repeat("b", 32)
	out := filepath.Join(fixture.root, "acceptance")
	args := append(append([]string{"--format", "json", "submission", "accept"}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test", "--transition", string(mpcceremony.CheckpointPhase1ReceiptAccepted),
		"--previous-checkpoint", cp1Path, "--previous-checkpoint-signature", cp1SignaturePath,
		"--chain", fixture.chainPath, "--chain-signature", fixture.chainSignaturePath, "--head-payload", fixture.headPayloadPath,
		"--transition-record", filepath.Join(envelopeDir, "envelope.json"), "--transition-record-signature", filepath.Join(envelopeDir, "envelope.sig"),
		"--manifest", manifestPath, "--next-attempt-id", nextAttempt, "--next-manifest-key", "submissions/candidate/"+nextAttempt+"/manifest.json",
		"--coordinator-signing-key", coordinatorKeyPath, "--out-dir", out)
	result := runCheckpointCommandCLI(t, args)
	if result.Sequence != 2 {
		t.Fatalf("sequence = %d", result.Sequence)
	}
	checkpointBytes, signatureBytes := mustReadTestFile(t, result.Outputs["checkpoint"]), mustReadTestFile(t, result.Outputs["checkpoint_signature"])
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: fixture.trustArgs[1], DefinitionSignaturePath: fixture.trustArgs[3], CoordinatorPublicKeyPath: fixture.trustArgs[5]})
	if err != nil {
		t.Fatal(err)
	}
	definitionBytes, definitionSignature := mustReadTestFile(t, fixture.trustArgs[1]), mustReadTestFile(t, fixture.trustArgs[3])
	checkpoint, err := mpcceremony.VerifySignedCheckpoint(trusted.Definition, definitionBytes, definitionSignature, checkpointBytes, signatureBytes)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Transition.Kind != mpcceremony.CheckpointPhase1ReceiptAccepted || checkpoint.Transition.Acknowledgement == nil {
		t.Fatalf("checkpoint transition = %#v", checkpoint.Transition)
	}
	runCheckpointCommandCLI(t, args) // byte-identical retry
}

func TestSubmissionCandidateSignAndAcceptReplaysMathematics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("full candidate replay requires Linux executable identity")
	}
	fixture, participantKey := writeWorkflowCheckpointCLIFixture(t)
	cp0Path, cp0SignaturePath := prepareAndSignInitialCheckpoint(t, fixture)
	cp1Path, cp1SignaturePath, handoff, handoffBytes := prepareAndSignOutboundCheckpoint(t, fixture, cp0Path, cp0SignaturePath, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	cp2Path, cp2SignaturePath := prepareAndSignReceiptCheckpoint(t, fixture, participantKey, cp1Path, cp1SignaturePath, handoff, handoffBytes, mpcceremony.Phase1, fixture.chainPath, fixture.chainSignaturePath, fixture.headPayloadPath)
	var cp2 mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, cp2Path), &cp2); err != nil {
		t.Fatal(err)
	}
	var slot mpcceremony.CheckpointSubmissionSlot
	for _, candidate := range cp2.Submissions {
		if candidate.Kind == mpcceremony.CheckpointSubmissionCandidate && candidate.Status == mpcceremony.CheckpointSubmissionAllocated {
			slot = candidate
		}
	}
	if slot.AttemptID == "" {
		t.Fatal("candidate slot missing")
	}
	chainPath := filepath.Join(fixture.root, "phase1", "chain-0001.json")
	chainSignaturePath := filepath.Join(fixture.root, "phase1", "chain-0001.sig")
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: fixture.trustArgs[1], DefinitionSignaturePath: fixture.trustArgs[3], CoordinatorPublicKeyPath: fixture.trustArgs[5]})
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := mpcceremony.LoadSignedChainExact(trusted, mpcceremony.PhaseTranscriptPaths{RootDir: fixture.root, ChainPath: chainPath, ChainSignaturePath: chainSignaturePath})
	if err != nil {
		t.Fatal(err)
	}
	accepted := chain.Records[len(chain.Records)-1]
	candidateDir := filepath.Join(fixture.root, "candidate-for-submit")
	if err := os.Mkdir(candidateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		ref  mpcceremony.ArtifactRef
		name string
	}{{accepted.OutputPayload, "contribution.bin"}, {accepted.Attestation, "attestation.json"}, {accepted.AttestationSignature, "attestation.sig"}, {accepted.Erasure, "erasure.json"}, {accepted.ErasureSignature, "erasure.sig"}} {
		writeDecisionTestFile(t, filepath.Join(candidateDir, item.name), mustReadTestFile(t, filepath.Join(fixture.root, filepath.FromSlash(item.ref.Name))), 0o600)
	}
	participantKeyPath := filepath.Join(filepath.Dir(fixture.root), "identity-keys", "participant-01.ed25519.private.hex")
	envelopeDir := filepath.Join(fixture.root, "candidate-envelope")
	signArgs := append(append([]string{"--format", "json", "submission", "sign"}, fixture.trustArgs...), "--artifact-root", fixture.root, "--checkpoint", cp2Path, "--checkpoint-signature", cp2SignaturePath, "--attempt-id", slot.AttemptID, "--participant-signing-key", participantKeyPath, "--candidate-dir", candidateDir, "--out-dir", envelopeDir)
	runCheckpointFixtureCommand(t, fixture, signArgs)
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(slot.ManifestKey))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, manifestPath, []byte(`{"complete":true}`), 0o600)
	coordinatorKeyPath := filepath.Join(filepath.Dir(fixture.root), "identity-keys", "coordinator.ed25519.private.hex")
	out := filepath.Join(fixture.root, "candidate-acceptance")
	args := append(append([]string{"--format", "json", "submission", "accept"}, fixture.trustArgs...),
		"--artifact-root", fixture.root, "--relay-release-id", "role-images-test", "--transition", string(mpcceremony.CheckpointPhase1CandidateAccepted),
		"--previous-checkpoint", cp2Path, "--previous-checkpoint-signature", cp2SignaturePath,
		"--chain", chainPath, "--chain-signature", chainSignaturePath, "--head-payload", filepath.Join(fixture.root, filepath.FromSlash(accepted.OutputPayload.Name)),
		"--transition-record", filepath.Join(envelopeDir, "envelope.json"), "--transition-record-signature", filepath.Join(envelopeDir, "envelope.sig"),
		"--manifest", manifestPath, "--coordinator-signing-key", coordinatorKeyPath, "--out-dir", out)
	result := runCheckpointFixtureCommand(t, fixture, args)
	if result.Sequence != 3 {
		t.Fatalf("sequence = %d", result.Sequence)
	}
	var checkpoint mpcceremony.Checkpoint
	if err := mpcceremony.UnmarshalCanonical(mustReadTestFile(t, result.Outputs["checkpoint"]), &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.Transition.Kind != mpcceremony.CheckpointPhase1CandidateAccepted || checkpoint.Phase1.AcceptedCount != 1 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
}
