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
		{false, []m.CheckpointTransitionKind{m.CheckpointPhase1CandidateAllocated, m.CheckpointPhase2CandidateAllocated, m.CheckpointDeliveryRetired, m.CheckpointDeliveryReallocated, m.CheckpointContributionRejected, m.CheckpointPhase1Closed, m.CheckpointPhase2Closed, m.CheckpointPhase1BeaconRecorded, m.CheckpointPhase2BeaconRecorded, m.CheckpointReleaseReviewRecorded, m.CheckpointFinalReleaseRecorded, m.CheckpointEnrollmentRecorded, m.CheckpointMirrorRecorded, m.CheckpointWitnessRecorded, m.CheckpointAuditRecorded, m.CheckpointIncidentRecorded, m.CheckpointAborted, m.CheckpointRestarted}},
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

func TestCheckpointRejectCandidateV4ParserRequiresPrivateCandidate(t *testing.T) {
	root := t.TempDir()
	args := []string{"checkpoint", "reject-candidate-v4",
		"--ceremony", filepath.Join(root, "ceremony.json"), "--ceremony-signature", filepath.Join(root, "ceremony.sig"), "--coordinator-public-key-file", filepath.Join(root, "coordinator.hex"),
		"--artifact-root", root, "--checkpoint", filepath.Join(root, "checkpoint.json"), "--checkpoint-signature", filepath.Join(root, "checkpoint.sig"),
		"--attempt-id", strings.Repeat("a", 32), "--coordinator-signing-key", filepath.Join(root, "private.hex"), "--out-dir", filepath.Join(root, "out"),
	}
	if _, err := parseInvocation(args); err == nil || !strings.Contains(err.Error(), "--rejected-candidate-dir") {
		t.Fatalf("missing private candidate accepted: %v", err)
	}
	args = append(args, "--rejected-candidate-dir", filepath.Join(root, "private"))
	invocation, err := parseInvocation(args)
	if err != nil || invocation.Command != CommandCheckpointRejectCandidateV4 {
		t.Fatalf("direct rejection did not parse: %q %v", invocation.Command, err)
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
	checkContributionInventoryExecutableV4(t, executable, artifactRoot, d, chain)
	head, err := chain.HeadRecordID()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := chain.HeadPayload()
	if err != nil {
		t.Fatal(err)
	}
	refs := []m.ArtifactRef{definition.Record, definition.Signature, d.Circuit.R1CS, chainRefs.Record, chainRefs.Signature, payload}
	slices.SortFunc(refs, func(a, b m.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	proposal := m.CheckpointV4{Schema: m.CheckpointSchemaV4, Workflow: m.StorageFirstWorkflowV2, CeremonyID: d.CeremonyID, Definition: definition, AssurancePolicy: d.AssurancePolicy, ReleaseVerification: m.CoordinatorReplayReleaseV1,
		Transition: m.CheckpointTransitionV4{Kind: m.CheckpointInitial, Evidence: []m.ArtifactRef{}}, Progress: m.CheckpointProgressV4{Phase1: m.CheckpointPhaseState{Phase: m.Phase1, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}}, AcceptedArtifacts: refs, Deliveries: []m.DeliverySlotV2{}}
	proposalPath, checkedPath, signaturePath := filepath.Join(artifactRoot, "proposal.json"), filepath.Join(artifactRoot, "checked.json"), filepath.Join(artifactRoot, "checked.sig")
	data := writeJSON(proposalPath, proposal)
	trustArgs := []string{"--ceremony", created.Outputs["ceremony"], "--ceremony-signature", created.Outputs["ceremony_signature"], "--coordinator-public-key-file", created.Outputs["coordinator_public_key"], "--artifact-root", artifactRoot}
	initialDir := filepath.Join(artifactRoot, "checkpoints", "initial")
	if err := os.MkdirAll(filepath.Dir(initialDir), 0o700); err != nil {
		t.Fatal(err)
	}
	initialize := append([]string{"--format", "json", "checkpoint", "initialize-v4"}, trustArgs...)
	initialize = append(initialize, "--coordinator-signing-key", keyPath, "--out-dir", initialDir)
	initialized := runCheckpointCommandExecutable(t, executable, initialize)
	if !bytes.Equal(data, mustReadTestFile(t, initialized.Outputs["checkpoint"])) || initialized.Sequence != 0 {
		t.Fatal("initialize-v4 did not derive the exact only valid initial checkpoint")
	}
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
	discoverArgs := append([]string{"--format", "json", "checkpoint", "inspect-signed-v4"}, trustArgs...)
	discoverArgs = append(discoverArgs, "--checkpoint", checkedPath, "--checkpoint-signature", signaturePath)
	discovered := runCheckpointCommandExecutable(t, executable, discoverArgs).CheckpointDiscoveryV4
	if discovered == nil || discovered.Schema != "proof-tool-mpc-checkpoint-discovery-v4" || discovered.Depth != "signed-checkpoint-discovery" || discovered.AncestryVerified || discovered.ArtifactsVerified || discovered.MathematicsReplayed || discovered.GlobalFreshnessVerified || discovered.Discovery.Sequence != 0 || len(discovered.Discovery.VerificationDependencies) != 0 || discovered.CheckpointRefs != projection.CheckpointRefs {
		t.Fatalf("discovery overclaim or wrong head: %+v", discovered)
	}
	enrollmentArgs := append([]string{"--format", "json", "checkpoint", "inspect-enrollments-v4"}, trustArgs...)
	enrollmentArgs = append(enrollmentArgs, "--checkpoint", checkedPath, "--checkpoint-signature", signaturePath)
	enrollments := runCheckpointCommandExecutable(t, executable, enrollmentArgs).EnrollmentMetadataV4
	if enrollments == nil || enrollments.Schema != "proof-tool-mpc-enrollment-metadata-v4" || enrollments.Depth != "committed-enrollment-signatures" || !enrollments.EnrollmentSignaturesVerified || enrollments.DisclosureContentsVerified || enrollments.CompleteRosterVerified || enrollments.GlobalFreshnessVerified || enrollments.Metadata.Checkpoint != projection.CheckpointRefs || len(enrollments.Metadata.Enrollments) != 0 {
		t.Fatalf("empty enrollment set overclaim or wrong head: %+v", enrollments)
	}
	disclosurePath := filepath.Join(artifactRoot, "enrollments", "participant-01", "disclosure.txt")
	if err := os.MkdirAll(filepath.Dir(disclosurePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, disclosurePath, []byte("Single-process CLI fixture; no independence claim.\n"), 0o600)
	disclosure := ref("enrollments/participant-01/disclosure.txt")
	participant := d.Roster[0].Identity
	enrollment, err := m.NewEnrollmentRecord(d, mustReadTestFile(t, created.Outputs["ceremony"]), participant, m.EnrollmentParticipant, 1, disclosure, "2026-09-16T00:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	enrollmentBytes, enrollmentSignature, err := m.SignRecord(enrollment, participant.KeyID, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	enrollmentPath := filepath.Join(artifactRoot, "enrollments", "participant-01", "record.json")
	enrollmentSignaturePath := filepath.Join(artifactRoot, "enrollments", "participant-01", "record.sig")
	writeDecisionTestFile(t, enrollmentPath, enrollmentBytes, 0o600)
	writeDecisionTestFile(t, enrollmentSignaturePath, enrollmentSignature, 0o600)
	recordedDir := filepath.Join(artifactRoot, "checkpoints", "participant-enrollment")
	record := append([]string{"--format", "json", "checkpoint", "record-v4"}, trustArgs...)
	record = append(record,
		"--checkpoint", initialized.Outputs["checkpoint"], "--checkpoint-signature", initialized.Outputs["checkpoint_signature"],
		"--transition", string(m.CheckpointEnrollmentRecorded), "--record", enrollmentPath, "--record-signature", enrollmentSignaturePath,
		"--evidence", disclosurePath, "--coordinator-signing-key", keyPath, "--out-dir", recordedDir,
	)
	recorded := runCheckpointCommandExecutable(t, executable, record)
	if recorded.Sequence != 1 {
		t.Fatalf("record-v4 sequence = %d, want 1", recorded.Sequence)
	}
	recordedInspect := append([]string{"--format", "json", "checkpoint", "verify-stored-v4"}, trustArgs...)
	recordedInspect = append(recordedInspect, "--checkpoint", recorded.Outputs["checkpoint"], "--checkpoint-signature", recorded.Outputs["checkpoint_signature"])
	if got := runCheckpointCommandExecutable(t, executable, recordedInspect).CheckpointInspectionV4; got == nil || got.Checkpoint.Transition.Kind != m.CheckpointEnrollmentRecorded {
		t.Fatalf("recorded enrollment did not authenticate: %+v", got)
	}
	// A rejection intentionally records opaque candidate bytes. The dummy files
	// below are not valid records or signatures; the direct rejection command
	// must still bind their exact fixed five-file inventory to the active turn.
	attemptID := strings.Repeat("a", 32)
	allocationDir := filepath.Join(artifactRoot, "checkpoints", "allocation")
	allocate := append([]string{"--format", "json", "checkpoint", "allocate-v4"}, trustArgs...)
	allocate = append(allocate,
		"--checkpoint", recorded.Outputs["checkpoint"], "--checkpoint-signature", recorded.Outputs["checkpoint_signature"],
		"--attempt-id", attemptID, "--allocated-at", "2026-09-16T00:00:01Z", "--coordinator-signing-key", keyPath, "--out-dir", allocationDir,
	)
	allocated := runCheckpointCommandExecutable(t, executable, allocate)
	privateCandidate := filepath.Join(root, "private-rejected-candidate")
	if err := os.MkdirAll(privateCandidate, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"attestation.json": "intentionally invalid attestation", "attestation.sig": "invalid signature", "contribution.bin": "unverified candidate bytes", "erasure.json": "intentionally invalid cleanup", "erasure.sig": "invalid signature",
	} {
		writeDecisionTestFile(t, filepath.Join(privateCandidate, name), []byte(contents), 0o600)
	}
	rejectionDir := filepath.Join(artifactRoot, "checkpoints", "rejected")
	reject := append([]string{"--format", "json", "checkpoint", "reject-candidate-v4"}, trustArgs...)
	reject = append(reject,
		"--checkpoint", allocated.Outputs["checkpoint"], "--checkpoint-signature", allocated.Outputs["checkpoint_signature"],
		"--attempt-id", attemptID, "--rejected-candidate-dir", privateCandidate, "--coordinator-signing-key", keyPath, "--out-dir", rejectionDir,
	)
	rejected := runCheckpointCommandExecutable(t, executable, reject)
	if rejected.Sequence != 3 || !strings.Contains(rejected.Summary, "fresh contribution") {
		t.Fatalf("unexpected rejection result: %+v", rejected)
	}
	var rejectedCheckpoint m.CheckpointV4
	if err := m.UnmarshalCanonical(mustReadTestFile(t, rejected.Outputs["checkpoint"]), &rejectedCheckpoint); err != nil {
		t.Fatal(err)
	}
	if rejectedCheckpoint.Transition.Kind != m.CheckpointContributionRejected || rejectedCheckpoint.Transition.AttemptID != attemptID || rejectedCheckpoint.Transition.NextAttemptID != "" || rejectedCheckpoint.Transition.Contribution == nil || len(rejectedCheckpoint.Transition.Contribution.Files) != 5 {
		t.Fatalf("direct rejection did not retain the exact terminal allocation: %+v", rejectedCheckpoint.Transition)
	}
	// Repeating the exact operation from the same authenticated parent is
	// idempotent: it must reproduce the same signed child, not invent another
	// transition. A caller that has advanced to the rejection checkpoint will
	// observe that the allocation is no longer active there.
	rejectedAgain := runCheckpointCommandExecutable(t, executable, append(reject[:len(reject)-2], "--out-dir", filepath.Join(artifactRoot, "checkpoints", "rejected-again")))
	for _, name := range []string{"checkpoint", "checkpoint_signature"} {
		if !bytes.Equal(mustReadTestFile(t, rejected.Outputs[name]), mustReadTestFile(t, rejectedAgain.Outputs[name])) {
			t.Fatalf("exact rejection replay changed %s bytes", name)
		}
	}
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
