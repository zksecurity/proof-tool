// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
)

type checkpointCLIFixture struct {
	trustArgs          []string
	checkpoint0Path    string
	checkpoint0SigPath string
	checkpoint1Path    string
	checkpoint1SigPath string
	definition         mpcceremony.CeremonyDefinition
	checkpoint0        mpcceremony.Checkpoint
	checkpoint1        mpcceremony.Checkpoint
	checkpoint0Bytes   []byte
	checkpoint0Sig     []byte
	coordinatorKey     []byte
	root               string
	chainPath          string
	chainSignaturePath string
	headPayloadPath    string
}

func TestInspectCheckpointAndTransition(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)

	checkpointArgs := append(
		append([]string{"--format", "json", "inspect", "checkpoint"}, fixture.trustArgs...),
		"--checkpoint", fixture.checkpoint1Path,
		"--checkpoint-signature", fixture.checkpoint1SigPath,
	)
	result := runCheckpointCLI(t, checkpointArgs)
	inspection := result.CheckpointInspection
	if inspection == nil || inspection.Schema != checkpointInspectionSchema ||
		inspection.CeremonyID != fixture.definition.CeremonyID || inspection.Sequence != 1 ||
		inspection.Transition.Kind != mpcceremony.CheckpointPhase1OutboundPublished ||
		inspection.Digest != mpcceremony.NewDigest(mustReadTestFile(t, fixture.checkpoint1Path)) ||
		len(inspection.Submissions) != 1 {
		t.Fatalf("checkpoint inspection = %#v", inspection)
	}

	transitionArgs := checkpointTransitionArgs(fixture)
	result = runCheckpointCLI(t, transitionArgs)
	transition := result.CheckpointTransitionInspection
	if transition == nil || transition.Schema != checkpointTransitionInspectionSchema ||
		transition.PreviousSequence != 0 || transition.Sequence != 1 ||
		transition.PreviousCheckpointDigest != mpcceremony.NewDigest(fixture.checkpoint0Bytes) ||
		transition.PreviousSignatureDigest != mpcceremony.NewDigest(fixture.checkpoint0Sig) ||
		transition.Checkpoint.Sequence != 1 {
		t.Fatalf("transition inspection = %#v", transition)
	}
}

func TestInspectCheckpointTransitionRejectsWrongParentSignatureReference(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	checkpoint := fixture.checkpoint1
	checkpoint.PreviousCheckpoint.Signature.Digest = mpcceremony.NewDigest([]byte("different detached signature"))
	checkpointBytes, checkpointSignature, err := mpcceremony.SignRecord(
		checkpoint,
		fixture.definition.Coordinator.KeyID,
		fixture.coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, fixture.checkpoint1Path, checkpointBytes, 0o600)
	writeDecisionTestFile(t, fixture.checkpoint1SigPath, checkpointSignature, 0o600)

	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), checkpointTransitionArgs(fixture), &stdout, &stderr, workflowExecutor{}); code == 0 {
		t.Fatalf("transition with wrong parent signature reference accepted: %s", stdout.String())
	}
	if !strings.Contains(stdout.String()+stderr.String(), "does not bind the exact previous checkpoint signature") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestInspectCheckpointRejectsTamperedSignatureWithoutProjection(t *testing.T) {
	fixture := writeCheckpointCLIFixture(t)
	writeDecisionTestFile(t, fixture.checkpoint1SigPath, append(mustReadTestFile(t, fixture.checkpoint1SigPath), '\n'), 0o600)
	args := append(
		append([]string{"--format", "json", "inspect", "checkpoint"}, fixture.trustArgs...),
		"--checkpoint", fixture.checkpoint1Path,
		"--checkpoint-signature", fixture.checkpoint1SigPath,
	)
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code == 0 {
		t.Fatalf("tampered checkpoint signature accepted: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "checkpoint_inspection") {
		t.Fatalf("unauthenticated checkpoint projection emitted: %s", stdout.String())
	}
}

func checkpointTransitionArgs(fixture checkpointCLIFixture) []string {
	return append(
		append([]string{"--format", "json", "inspect", "checkpoint-transition"}, fixture.trustArgs...),
		"--previous-checkpoint", fixture.checkpoint0Path,
		"--previous-checkpoint-signature", fixture.checkpoint0SigPath,
		"--checkpoint", fixture.checkpoint1Path,
		"--checkpoint-signature", fixture.checkpoint1SigPath,
	)
}

func runCheckpointCLI(t *testing.T, args []string) CommandResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	var result CommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("result = %#v", result)
	}
	return result
}

func writeCheckpointCLIFixture(t *testing.T) checkpointCLIFixture {
	t.Helper()
	root := t.TempDir()
	definition, _, coordinatorKey := decisionSignFixture(t)
	definitionBytes, definitionSignature, err := mpcceremony.SignRecord(
		definition,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	phaseID, err := mpcceremony.ComputePhaseID(definition.CeremonyID, mpcceremony.Phase1, definition.Phase1Genesis, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := mpcceremony.NewChain(definition.CeremonyID, mpcceremony.Phase1, phaseID, definition.Phase1Genesis)
	if err != nil {
		t.Fatal(err)
	}
	chainBytes, chainSignature, err := mpcceremony.SignRecord(chain, definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}
	definitionRefs := mpcceremony.SignedArtifactRefs{
		Record:    checkpointCLIArtifact("ceremony.json", definitionBytes),
		Signature: checkpointCLIArtifact("ceremony.sig", definitionSignature),
	}
	chainRefs := mpcceremony.SignedArtifactRefs{
		Record:    checkpointCLIArtifact("phase1/chain-0000.json", chainBytes),
		Signature: checkpointCLIArtifact("phase1/chain-0000.sig", chainSignature),
	}
	accepted := []mpcceremony.ArtifactRef{
		definitionRefs.Record,
		definitionRefs.Signature,
		definition.Phase1Genesis,
		chainRefs.Record,
		chainRefs.Signature,
	}
	sortCheckpointCLIArtifacts(accepted)
	cp0 := mpcceremony.Checkpoint{
		Schema:          mpcceremony.CheckpointSchema,
		Workflow:        mpcceremony.StorageFirstWorkflowV1,
		CeremonyID:      definition.CeremonyID,
		Definition:      definitionRefs,
		AssurancePolicy: definition.AssurancePolicy,
		RelayReleaseID:  "role-images-test",
		Sequence:        0,
		Transition:      mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointInitial},
		Phase1: mpcceremony.CheckpointPhaseState{
			Phase: mpcceremony.Phase1, AcceptedCount: 0,
			HeadRecordID: mpcceremony.NewDigest([]byte("phase1 genesis head")).SHA256,
			HeadPayload:  definition.Phase1Genesis, Chain: chainRefs,
		},
		AcceptedArtifacts: accepted,
		Submissions:       []mpcceremony.CheckpointSubmissionSlot{},
	}
	cp0Bytes, cp0Signature, err := mpcceremony.SignRecord(cp0, definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}

	handoffBytes := []byte("canonical outbound handoff")
	handoffSignature := []byte("detached outbound handoff signature")
	handoff := mpcceremony.SignedArtifactRefs{
		Record:    checkpointCLIArtifact("custody/outbound.json", handoffBytes),
		Signature: checkpointCLIArtifact("custody/outbound.sig", handoffSignature),
	}
	cp0Ref := mpcceremony.SignedArtifactRefs{
		Record:    checkpointCLIArtifact("state/checkpoint-0000.json", cp0Bytes),
		Signature: checkpointCLIArtifact("state/checkpoint-0000.sig", cp0Signature),
	}
	cp1 := cp0
	cp1.Sequence = 1
	cp1.PreviousCheckpoint = &cp0Ref
	cp1.Transition = mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1OutboundPublished, Phase: mpcceremony.Phase1,
		Index: 1, ParticipantID: definition.Phase1Policy.Participants[0],
		AttemptID: strings.Repeat("a", 32), Record: &handoff,
	}
	cp1.AcceptedArtifacts = append(append([]mpcceremony.ArtifactRef(nil), cp0.AcceptedArtifacts...), handoff.Record, handoff.Signature)
	sortCheckpointCLIArtifacts(cp1.AcceptedArtifacts)
	cp1.Submissions = []mpcceremony.CheckpointSubmissionSlot{{
		Kind: mpcceremony.CheckpointSubmissionReceipt, Phase: mpcceremony.Phase1, Index: 1,
		IdentityID: definition.Phase1Policy.Participants[0], AttemptID: strings.Repeat("a", 32),
		ManifestKey:           "submissions/receipt/" + strings.Repeat("a", 32) + "/manifest.json",
		BasisCheckpointSHA256: cp0Ref.Record.Digest.SHA256,
		ParentHeadID:          cp0.Phase1.HeadRecordID, Status: mpcceremony.CheckpointSubmissionAllocated,
	}}
	cp1Bytes, cp1Signature, err := mpcceremony.SignRecord(cp1, definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}

	ceremonyPath := filepath.Join(root, "ceremony.json")
	ceremonySignaturePath := filepath.Join(root, "ceremony.sig")
	coordinatorPublicKeyPath := filepath.Join(root, "coordinator-public-key.hex")
	cp0Path := filepath.Join(root, "checkpoint-0000.json")
	cp0SigPath := filepath.Join(root, "checkpoint-0000.sig")
	cp1Path := filepath.Join(root, "checkpoint-0001.json")
	cp1SigPath := filepath.Join(root, "checkpoint-0001.sig")
	writeDecisionTestFile(t, ceremonyPath, definitionBytes, 0o600)
	writeDecisionTestFile(t, ceremonySignaturePath, definitionSignature, 0o600)
	writeDecisionTestFile(t, coordinatorPublicKeyPath, []byte(definition.Coordinator.Ed25519PublicKeyHex+"\n"), 0o600)
	writeDecisionTestFile(t, cp0Path, cp0Bytes, 0o600)
	writeDecisionTestFile(t, cp0SigPath, cp0Signature, 0o600)
	writeDecisionTestFile(t, cp1Path, cp1Bytes, 0o600)
	writeDecisionTestFile(t, cp1SigPath, cp1Signature, 0o600)
	chainPath := filepath.Join(root, filepath.FromSlash(chainRefs.Record.Name))
	chainSignaturePath := filepath.Join(root, filepath.FromSlash(chainRefs.Signature.Name))
	headPayloadPath := filepath.Join(root, filepath.FromSlash(definition.Phase1Genesis.Name))
	if err := os.MkdirAll(filepath.Dir(chainPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, chainPath, chainBytes, 0o600)
	writeDecisionTestFile(t, chainSignaturePath, chainSignature, 0o600)
	writeDecisionTestFile(t, headPayloadPath, []byte("genesis"), 0o600)

	return checkpointCLIFixture{
		trustArgs: []string{
			"--ceremony", ceremonyPath,
			"--ceremony-signature", ceremonySignaturePath,
			"--coordinator-public-key-file", coordinatorPublicKeyPath,
		},
		checkpoint0Path: cp0Path, checkpoint0SigPath: cp0SigPath,
		checkpoint1Path: cp1Path, checkpoint1SigPath: cp1SigPath,
		definition: definition, checkpoint0: cp0, checkpoint1: cp1,
		checkpoint0Bytes: cp0Bytes, checkpoint0Sig: cp0Signature,
		coordinatorKey: append([]byte(nil), coordinatorKey...),
		root:           root, chainPath: chainPath, chainSignaturePath: chainSignaturePath, headPayloadPath: headPayloadPath,
	}
}

func checkpointCLIArtifact(name string, contents []byte) mpcceremony.ArtifactRef {
	return mpcceremony.ArtifactRef{Name: name, Digest: mpcceremony.NewDigest(contents)}
}

func sortCheckpointCLIArtifacts(values []mpcceremony.ArtifactRef) {
	slices.SortFunc(values, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
