package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	m "proof-tool/internal/mpcceremony"
)

func TestCheckpointV4CircuitClassification(t *testing.T) {
	for _, tc := range []struct {
		math  bool
		kinds []m.CheckpointTransitionKind
	}{
		{true, []m.CheckpointTransitionKind{m.CheckpointInitial, m.CheckpointPhase1CandidateAccepted, m.CheckpointPhase2CandidateAccepted, m.CheckpointPhase1Sealed, m.CheckpointPhase2Initialized, m.CheckpointFinalCandidateRecorded}},
		{false, []m.CheckpointTransitionKind{m.CheckpointPhase1OutboundPublished, m.CheckpointPhase2OutboundPublished, m.CheckpointPhase1ReceiptAccepted, m.CheckpointPhase2ReceiptAccepted, m.CheckpointDeliveryRetired, m.CheckpointDeliveryReallocated, m.CheckpointContributionRejected, m.CheckpointPhase1Closed, m.CheckpointPhase2Closed, m.CheckpointPhase1BeaconRecorded, m.CheckpointPhase2BeaconRecorded, m.CheckpointFinalReleaseRecorded, m.CheckpointEnrollmentRecorded, m.CheckpointMirrorRecorded, m.CheckpointWitnessRecorded, m.CheckpointBeaconEvidenceRecorded, m.CheckpointAuditRecorded, m.CheckpointIncidentRecorded, m.CheckpointAborted, m.CheckpointRestarted}},
	} {
		for _, kind := range tc.kinds {
			if got, err := checkpointNeedsCircuitV4(kind); err != nil || got != tc.math {
				t.Fatalf("%s: %v %v", kind, got, err)
			}
		}
	}
	if _, err := checkpointNeedsCircuitV4("future-transition"); err == nil {
		t.Fatal("unknown transition silently skips circuit verification")
	}
}

func TestCheckpointV4ClosedTreesAndDiagnosticGrammar(t *testing.T) {
	root, private := t.TempDir(), t.TempDir()
	for _, name := range []string{"final/candidate", "final/release", "checkpoints"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"candidate-alias": filepath.Join(root, "final/candidate"), "release-alias": filepath.Join(root, "final/release"), "private-alias": private} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	o := CheckpointOptionsV4{ArtifactRoot: root, ProposalPath: filepath.Join(root, "proposal.json"), OutPath: filepath.Join(root, "checkpoints/new.sig"), RejectedCandidateDir: private}
	if err := validateCheckpointPathsV4(o); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "final/candidate/new"), filepath.Join(root, "final/release/new"), filepath.Join(private, "new"), filepath.Join(root, "candidate-alias/new"), filepath.Join(root, "release-alias/new"), filepath.Join(root, "private-alias/new")} {
		for _, proposal := range []bool{false, true} {
			bad := o
			if proposal {
				bad.ProposalPath = path
			} else {
				bad.OutPath = path
			}
			if err := validateCheckpointPathsV4(bad); err == nil {
				t.Fatalf("closed-tree path accepted: %s", path)
			}
		}
	}
	bad := o
	bad.RejectedCandidateDir = filepath.Join(root, "checkpoints")
	if err := validateCheckpointPathsV4(bad); err == nil {
		t.Fatal("private candidate allowed in public root")
	}
	for _, action := range []string{"prepare-v4", "sign-v4", "verify-stored-v4"} {
		args := []string{"checkpoint", action, "--proposal", "/private/operator/path"}
		message := redactCLIError("checkpoint "+action+" --proposal /private/operator/path", args)
		if !strings.Contains(message, action) || !strings.Contains(message, "--proposal") || strings.Contains(message, "/private/operator/path") {
			t.Fatalf("grammar/privacy: %s", message)
		}
	}
}

func TestCheckpointV4CLIInitialPrepareSignInspectAndMutation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("approved executable identity is tested in Linux Docker")
	}
	root := t.TempDir()
	executable := filepath.Join(root, "mpc-ceremony")
	if out, err := exec.Command("go", "build", "-o", executable, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	d, _, key := decisionSignFixture(t)
	d.AssurancePolicy.ExternalSecurityAuditSignoffs = 0
	writeJSON := func(path string, v any) []byte {
		t.Helper()
		b, err := m.MarshalCanonical(v)
		if err != nil {
			t.Fatal(err)
		}
		writeDecisionTestFile(t, path, b, 0o600)
		return b
	}
	participants := filepath.Join(root, "participants.json")
	policy := filepath.Join(root, "policy.json")
	keyPath := filepath.Join(root, "coordinator-private.hex")
	writeJSON(participants, m.InitParticipants{Coordinator: d.Coordinator, ReleaseSigner: d.ReleaseSigner, Auditors: d.Auditors, Roster: d.Roster})
	writeJSON(policy, m.InitPolicy{Phase1Policy: d.Phase1Policy, Phase2Policy: d.Phase2Policy, BeaconPolicy: d.BeaconPolicy, AssurancePolicy: d.AssurancePolicy})
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(key)), 0o600)
	initArgs := []string{"--format", "json", "init", "--mode", "rehearsal", "--key-version", "rehearsal-tiny-v1", "--participants", participants, "--policy", policy,
		"--coordinator-key-id", d.Coordinator.KeyID, "--coordinator-signing-key", keyPath, "--created-at", "2026-09-16T00:00:00Z"}
	legacyRoot := filepath.Join(root, "legacy")
	legacy := runCheckpointCommandExecutable(t, executable, append(append([]string{}, initArgs...), "--out-dir", legacyRoot))
	var legacyDefinition m.CeremonyDefinition
	if err := m.UnmarshalCanonical(mustReadTestFile(t, legacy.Outputs["ceremony"]), &legacyDefinition); err != nil {
		t.Fatal(err)
	}
	if legacyDefinition.Schema != m.DefinitionSchemaV3 || legacyDefinition.ReleaseVerification != "" {
		t.Fatal("default init changed released semantics")
	}
	artifactRoot := filepath.Join(root, "v4")
	created := runCheckpointCommandExecutable(t, executable, append(append([]string{}, initArgs...), "--out-dir", artifactRoot, "--release-verification", m.CoordinatorReplayReleaseV1))
	d = m.CeremonyDefinition{}
	if err := m.UnmarshalCanonical(mustReadTestFile(t, created.Outputs["ceremony"]), &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != m.DefinitionSchemaV4 {
		t.Fatal("explicit V4 option did not bind new schema")
	}
	assertCheckpointExecutableFails(t, executable, append(append([]string{}, initArgs...), "--out-dir", filepath.Join(root, "invalid"), "--release-verification", "skip-checks"), "must be coordinator-full-replay-v1")
	ref := func(name string) m.ArtifactRef {
		return m.ArtifactRef{Name: name, Digest: m.NewDigest(mustReadTestFile(t, filepath.Join(artifactRoot, name)))}
	}
	pair := func(name string) m.SignedArtifactRefs {
		return m.SignedArtifactRefs{Record: ref(name + ".json"), Signature: ref(name + ".sig")}
	}
	definition, chainRefs := pair("ceremony"), pair("phase1/chain-0000")
	var chain m.Chain
	if err := m.UnmarshalCanonical(mustReadTestFile(t, filepath.Join(artifactRoot, chainRefs.Record.Name)), &chain); err != nil {
		t.Fatal(err)
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := chain.HeadPayload()
	if err != nil {
		t.Fatal(err)
	}
	refs := []m.ArtifactRef{definition.Record, definition.Signature, chainRefs.Record, chainRefs.Signature, payload}
	slices.SortFunc(refs, func(a, b m.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	proposal := m.CheckpointV4{Schema: m.CheckpointSchemaV4, Workflow: m.StorageFirstWorkflowV2, CeremonyID: d.CeremonyID, Definition: definition, AssurancePolicy: d.AssurancePolicy, ReleaseVerification: m.CoordinatorReplayReleaseV1,
		Transition: m.CheckpointTransitionV4{Kind: m.CheckpointInitial, Evidence: []m.ArtifactRef{}}, Progress: m.CheckpointProgressV4{Phase1: m.CheckpointPhaseState{Phase: m.Phase1, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}}, AcceptedArtifacts: refs, Deliveries: []m.DeliverySlotV2{}}
	proposalPath, checkedPath, signaturePath := filepath.Join(artifactRoot, "proposal.json"), filepath.Join(artifactRoot, "checked.json"), filepath.Join(artifactRoot, "checked.sig")
	data := writeJSON(proposalPath, proposal)
	trustArgs := []string{"--ceremony", created.Outputs["ceremony"], "--ceremony-signature", created.Outputs["ceremony_signature"], "--coordinator-public-key-file", created.Outputs["coordinator_public_key"], "--artifact-root", artifactRoot}
	prepare := append([]string{"--format", "json", "checkpoint", "prepare-v4"}, trustArgs...)
	prepare = append(prepare, "--proposal", proposalPath, "--out", checkedPath)
	runCheckpointCommandExecutable(t, executable, prepare)
	if !bytes.Equal(data, mustReadTestFile(t, checkedPath)) {
		t.Fatal("prepare normalized exact proposal")
	}
	sign := append([]string{"--format", "json", "checkpoint", "sign-v4"}, trustArgs...)
	sign = append(sign, "--proposal", checkedPath, "--coordinator-signing-key", keyPath, "--out", signaturePath)
	signed := runCheckpointCommandExecutable(t, executable, sign)
	if !strings.Contains(signed.Summary, "not the published current head") {
		t.Fatal("signature implies publication")
	}
	inspect := append([]string{"--format", "json", "checkpoint", "verify-stored-v4"}, trustArgs...)
	inspect = append(inspect, "--checkpoint", checkedPath, "--checkpoint-signature", signaturePath)
	result := runCheckpointCommandExecutable(t, executable, inspect)
	projection := result.CheckpointInspectionV4
	if projection == nil || projection.Depth != "checkpoint-structure" || projection.ArtifactsVerified || projection.MathematicsReplayed || projection.GlobalFreshnessVerified {
		t.Fatalf("overclaim: %+v", projection)
	}
	assertCheckpointExecutableFails(t, executable, sign, "fresh operational artifact")
	// Sign again only after rereading every required byte, not a saved success marker.
	genesis := filepath.Join(artifactRoot, payload.Name)
	original := mustReadTestFile(t, genesis)
	bad := bytes.Clone(original)
	bad[0] ^= 1
	writeDecisionTestFile(t, genesis, bad, 0o600)
	failedOutput := filepath.Join(artifactRoot, "must-not-exist.sig")
	badSign := append([]string{"checkpoint", "sign-v4"}, trustArgs...)
	badSign = append(badSign, "--proposal", checkedPath, "--coordinator-signing-key", filepath.Join(root, "MISSING-KEY"), "--out", failedOutput)
	out, err := exec.Command(executable, badSign...).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "differs from its exact committed bytes") {
		t.Fatalf("mutation not rejected before key: %v %s", err, out)
	}
	if _, err := os.Stat(failedOutput); !os.IsNotExist(err) {
		t.Fatalf("failed signing wrote output: %v", err)
	}
	// Structural sync is intentionally narrower and does not reread genesis.
	runCheckpointCommandExecutable(t, executable, inspect)
	writeDecisionTestFile(t, genesis, original, 0o600)
	wrongKey := filepath.Join(root, "other-private.hex")
	writeDecisionTestFile(t, wrongKey, []byte(hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)))), 0o600)
	wrongSign := append([]string{"checkpoint", "sign-v4"}, trustArgs...)
	wrongSign = append(wrongSign, "--proposal", checkedPath, "--coordinator-signing-key", wrongKey, "--out", failedOutput)
	assertCheckpointExecutableFails(t, executable, wrongSign, "not the authenticated coordinator key")
	assertCheckpointExecutableFails(t, executable, append(append([]string{}, badSign...), "--rejected-candidate-dir", root), "only contribution-rejected requires")
	oldTrust := append([]string{}, trustArgs...)
	oldTrust[1], oldTrust[3] = legacy.Outputs["ceremony"], legacy.Outputs["ceremony_signature"]
	oldInspect := append([]string{"checkpoint", "verify-stored-v4"}, oldTrust...)
	oldInspect = append(oldInspect, "--checkpoint", checkedPath, "--checkpoint-signature", signaturePath)
	assertCheckpointExecutableFails(t, executable, oldInspect, "require definition v4")
	legacyInspect := append([]string{"checkpoint", "verify-stored"}, trustArgs...)
	legacyInspect = append(legacyInspect, "--checkpoint", checkedPath, "--checkpoint-signature", signaturePath)
	if out, err := exec.Command(executable, legacyInspect...).CombinedOutput(); err == nil {
		t.Fatalf("legacy verifier accepted V4: %s", out)
	}
	for _, badData := range [][]byte{append(bytes.Clone(data), '\n'), bytes.Replace(data, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)} {
		writeDecisionTestFile(t, checkedPath, badData, 0o600)
		out, err := exec.Command(executable, badSign...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "canonical") {
			t.Fatalf("bad proposal reached key: %v %s", err, out)
		}
	}
}
