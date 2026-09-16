package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/cpu"

	m "proof-tool/internal/mpcceremony"
)

func evidenceArgsV4(command Command) []string {
	a := []string{"--ceremony", "ceremony.json", "--ceremony-signature", "ceremony.sig", "--coordinator-public-key-file", "coordinator.hex", "--artifact-root", "root", "--checkpoint", "root/head.json", "--checkpoint-signature", "root/head.sig"}
	switch command {
	case CommandOpsPrepareBundleV4:
		return append(a, "--assembled-at", "2026-09-16T00:00:00Z", "--out", "root/operational/evidence-bundle.json")
	case CommandOpsSignBundleV4:
		return append(a, "--operational-bundle", "root/operational/evidence-bundle.json", "--coordinator-signing-key", "private.hex", "--reviewed", "--reviewed-sha256", strings.Repeat("a", 64), "--out", "root/operational/evidence-bundle.sig")
	case CommandReleaseReviewV4:
		return append(a, "--operational-bundle", "root/operational/evidence-bundle.json", "--operational-bundle-signature", "root/operational/evidence-bundle.sig", "--released-at", "2026-09-16T00:00:00Z", "--out", "report.json")
	default:
		return append(a, "--inventory-out", "inventory.json")
	}
}

func TestEvidenceV4ParsersRequireExactInputs(t *testing.T) {
	for _, command := range []Command{CommandOpsPrepareBundleV4, CommandOpsSignBundleV4, CommandReleaseReviewV4, CommandCheckpointVerifyReleaseV4} {
		t.Run(string(command), func(t *testing.T) {
			a := evidenceArgsV4(command)
			if _, err := parseEvidenceV4(command, a); err != nil {
				t.Fatal(err)
			}
			invocation, err := parseInvocation(append(strings.Split(string(command), " "), a...))
			if err != nil || invocation.Command != command {
				t.Fatalf("dispatch: %+v %v", invocation, err)
			}
			for i := 0; i < len(a); i++ {
				if !strings.HasPrefix(a[i], "--") {
					continue
				}
				end := i + 2
				if a[i] == "--reviewed" {
					end = i + 1
				}
				missing := append(append([]string{}, a[:i]...), a[end:]...)
				if _, err := parseEvidenceV4(command, missing); err == nil {
					t.Fatalf("accepted missing %s", a[i])
				}
			}
			for _, mixed := range []string{"--candidate-bundle", "--transcript-root", "--proposal", "--review-report"} {
				if _, err := parseEvidenceV4(command, append(append([]string{}, a...), mixed, "file")); err == nil {
					t.Fatalf("accepted unrelated or unsigned-authority input %s", mixed)
				}
			}
		})
	}
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if err := validateBundleReviewV4(EvidenceOptionsV4{Reviewed: true, ReviewedSHA256: hash}); err == nil {
			t.Fatal("accepted invalid reviewed hash", hash)
		}
	}
}

func TestEvidenceV4OutputPathsAndCollisions(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"operational", "final/candidate/nested", "final/release", "reports"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []Command{CommandOpsPrepareBundleV4, CommandOpsSignBundleV4, CommandReleaseReviewV4, CommandCheckpointVerifyReleaseV4} {
		o := EvidenceOptionsV4{ArtifactRoot: root, OutPath: filepath.Join(root, "reports/report.json")}
		if command == CommandOpsPrepareBundleV4 {
			o.OutPath = filepath.Join(root, m.OperationalEvidenceBundleFile)
		}
		if command == CommandOpsSignBundleV4 {
			o.OutPath = filepath.Join(root, m.OperationalEvidenceSignatureFile)
		}
		if err := validateEvidenceOutputV4(command, o); err != nil {
			t.Fatal(command, err)
		}
		writeDecisionTestFile(t, o.OutPath, []byte("retain"), 0600)
		if err := validateEvidenceOutputV4(command, o); err == nil {
			t.Fatal("collision accepted", command)
		}
		if err := os.Remove(o.OutPath); err != nil {
			t.Fatal(err)
		}
		if command == CommandOpsPrepareBundleV4 {
			sig := filepath.Join(root, m.OperationalEvidenceSignatureFile)
			writeDecisionTestFile(t, sig, []byte("retain existing signature"), 0600)
			if err := validateEvidenceOutputV4(command, o); err == nil {
				t.Fatal("existing signature was ignored")
			}
			if err := os.Remove(sig); err != nil {
				t.Fatal(err)
			}
		}
		for _, bad := range []string{"final/candidate/report.json", "final/candidate/nested/report.json", "final/release/report.json", "missing/report.json"} {
			o.OutPath = filepath.Join(root, bad)
			if err := validateEvidenceOutputV4(command, o); err == nil {
				t.Fatal("unsafe output accepted", command, bad)
			}
		}
	}
	if err := os.Symlink(filepath.Join(root, "final/candidate"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceOutputV4(CommandReleaseReviewV4, EvidenceOptionsV4{ArtifactRoot: root, OutPath: filepath.Join(root, "alias/nested/report.json")}); err == nil {
		t.Fatal("closed-tree alias accepted")
	}
	if err := os.Rename(filepath.Join(root, "operational"), filepath.Join(root, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "original"), filepath.Join(root, "operational")); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceOutputV4(CommandOpsPrepareBundleV4, EvidenceOptionsV4{ArtifactRoot: root, OutPath: filepath.Join(root, m.OperationalEvidenceBundleFile)}); err == nil {
		t.Fatal("bundle parent alias accepted")
	}
}

func TestEvidenceV4RejectsLegacyDefinitionBeforeOutput(t *testing.T) {
	root := t.TempDir()
	d, _, key := decisionSignFixture(t)
	trustArgs := writeInspectionTrustFixture(t, root, d, key)
	for _, command := range []Command{CommandOpsPrepareBundleV4, CommandOpsSignBundleV4, CommandReleaseReviewV4, CommandCheckpointVerifyReleaseV4} {
		a := evidenceArgsV4(command)
		copy(a[:6], trustArgs[:6])
		o, err := parseEvidenceV4(command, a)
		if err != nil {
			t.Fatal(err)
		}
		_, err = executeEvidenceV4(command, o)
		if err == nil || !strings.Contains(err.Error(), "require definition v4") {
			t.Fatalf("%s: %v", command, err)
		}
	}
}

func inventoryReportFixtureV4(t *testing.T) ReleaseInventoryReportV4 {
	t.Helper()
	ref := func(name string) m.ArtifactRef { return m.ArtifactRef{Name: name, Digest: m.NewDigest([]byte(name))} }
	release, err := m.NewFinalReleaseEvidenceV4(m.NewDigest([]byte("ceremony")).SHA256, m.SignedArtifactRefs{Record: ref("checkpoints/final.json"), Signature: ref("checkpoints/final.sig")}, m.NewDigest([]byte("candidate")).SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return ReleaseInventoryReportV4{Schema: "proof-tool-mpc-release-inventory-report-v4", Release: release, ManifestSHA256: m.NewDigest([]byte("manifest")).SHA256,
		PackagePrefix: m.FinalReleasePackagePrefixV4, Artifacts: []m.ArtifactRef{ref("a.json"), ref("b.sig")}, Depth: "final-package", ArtifactsVerified: true, CoordinatorReplayClaimBound: true}
}

func TestEvidenceV4InventoryStrictCanonicalClaims(t *testing.T) {
	original := inventoryReportFixtureV4(t)
	raw, err := m.MarshalCanonical(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReleaseInventoryReportV4
	if err := m.UnmarshalCanonical(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ReleaseInventoryReportV4){
		func(r *ReleaseInventoryReportV4) { r.Schema = "unknown" },
		func(r *ReleaseInventoryReportV4) { r.Depth = "checkpoint-structure" },
		func(r *ReleaseInventoryReportV4) { r.PackagePrefix = "other/" },
		func(r *ReleaseInventoryReportV4) { r.Release.ReleaseID = m.NewDigest([]byte("other")).SHA256 },
		func(r *ReleaseInventoryReportV4) { r.ManifestSHA256 = strings.Repeat("a", 64) },
		func(r *ReleaseInventoryReportV4) { r.Artifacts = nil },
		func(r *ReleaseInventoryReportV4) { r.Artifacts[1] = r.Artifacts[0] },
		func(r *ReleaseInventoryReportV4) { r.Artifacts[0], r.Artifacts[1] = r.Artifacts[1], r.Artifacts[0] },
		func(r *ReleaseInventoryReportV4) { r.Artifacts[1].Name = "final/release/b.sig" },
		func(r *ReleaseInventoryReportV4) { r.Artifacts[1].Name = "z:stream" },
		func(r *ReleaseInventoryReportV4) { r.ArtifactsVerified = false },
		func(r *ReleaseInventoryReportV4) { r.CoordinatorReplayClaimBound = false },
		func(r *ReleaseInventoryReportV4) { r.MathematicsReplayed = true },
		func(r *ReleaseInventoryReportV4) { r.GlobalFreshnessVerified = true },
		func(r *ReleaseInventoryReportV4) { r.ProductionAuthorized = true },
		func(r *ReleaseInventoryReportV4) { r.Published = true },
	}
	for i, mutate := range mutations {
		changed := original
		changed.Artifacts = append([]m.ArtifactRef{}, original.Artifacts...)
		mutate(&changed)
		// json.Marshal deliberately bypasses Validate to construct invalid input.
		b, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.UnmarshalCanonical(b, &decoded); err == nil {
			t.Fatal("accepted inventory mutation", i)
		}
	}
	for _, b := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)} {
		if err := m.UnmarshalCanonical(b, &decoded); err == nil {
			t.Fatal("noncanonical or unknown field accepted")
		}
	}
}

func TestEvidenceV4LargeInventoryReportKeepsDedicatedBound(t *testing.T) {
	if testing.Short() {
		t.Skip("large local report format boundary")
	}
	report := inventoryReportFixtureV4(t)
	report.Artifacts = make([]m.ArtifactRef, 32000)
	for i := range report.Artifacts {
		report.Artifacts[i] = m.ArtifactRef{Name: fmt.Sprintf("files/%05d-%s", i, strings.Repeat("a", 470)), Digest: m.NewDigest([]byte("file"))}
	}
	raw, err := m.MarshalCanonical(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxOperationalRecordBytes || len(raw) > maxEvidenceReportV4Bytes {
		t.Fatalf("report size %d does not exercise the dedicated bound", len(raw))
	}
	var decoded ReleaseInventoryReportV4
	if err := m.UnmarshalCanonical(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Artifacts) != len(report.Artifacts) {
		t.Fatal("large inventory lost artifacts")
	}
}

// This exercises the actual CLI (including executable identity) on real tiny
// artifacts produced by the library workflow helper. The two reviewed binaries
// have distinct ARM64 feature variants in the signed allowlist. It is not a
// released role journey, live cloud test or fresh beacon run.
func TestEvidenceV4CommandsOnRealArtifacts(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || !cpu.ARM64.HasATOMICS {
		t.Skip("real tiny Linux ARM64 v8.1 command integration")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "workflow")
	cli := filepath.Join(t.TempDir(), "mpc-ceremony")
	buildCLI := exec.Command("go", "build", "-o", cli, "./cmd/mpc-ceremony")
	buildCLI.Dir = repo
	buildCLI.Env = append(os.Environ(), "GOARM64=v8.1")
	if b, err := buildCLI.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, b)
	}
	build := exec.Command("go", "build", "-o", helper, "./internal/mpcceremony/testdata/workflowhelper")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOARM64=v8.0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, b)
	}
	runRoot := filepath.Join(t.TempDir(), "run")
	run := exec.Command(helper, runRoot)
	run.Dir = repo
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "MPC_WORKFLOW_") && !strings.HasPrefix(e, "MPC_CEREMONY_TEST_") && !strings.HasPrefix(e, "PROOF_TOOL_TEST_") {
			run.Env = append(run.Env, e)
		}
	}
	run.Env = append(run.Env, "MPC_WORKFLOW_CHECKPOINT_V4=1", "PROOF_TOOL_TEST_ZERO_ASSURANCE=1", "MPC_WORKFLOW_V4_MIRROR=0", "MPC_WORKFLOW_RETAIN_REVIEW=1")
	run.Env = append(run.Env, "MPC_WORKFLOW_ALLOWED_CLI="+cli)
	if b, err := run.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, b)
	}
	snapshots, err := filepath.Glob(filepath.Join(runRoot, "review-dependencies-*"))
	if err != nil || len(snapshots) != 1 {
		t.Fatal("missing retained public review branch", snapshots, err)
	}
	root := snapshots[0]
	trust := m.TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(runRoot, "ceremony/coordinator-public-key.hex")}
	read := func(p string) []byte {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var transcript m.FinalTranscript
	if err := m.UnmarshalCanonical(read(filepath.Join(root, m.FinalReleasePackagePrefixV4, m.FinalTranscriptFile)), &transcript); err != nil {
		t.Fatal(err)
	}
	review := transcript.ReleaseReview
	if review == nil {
		t.Fatal("missing review")
	}
	o := EvidenceOptionsV4{InspectDefinitionOptions: InspectDefinitionOptions{CeremonyPath: trust.DefinitionPath, CeremonySignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyPath}, ArtifactRoot: root,
		CheckpointPath: filepath.Join(root, review.ReviewCheckpoint.Record.Name), CheckpointSignaturePath: filepath.Join(root, review.ReviewCheckpoint.Signature.Name),
		BundlePath: filepath.Join(root, m.OperationalEvidenceBundleFile), BundleSignaturePath: filepath.Join(root, m.OperationalEvidenceSignatureFile), ReleasedAt: review.ReleasedAt,
		CoordinatorSigningKey: filepath.Join(runRoot, "identity-keys/coordinator.ed25519.private.hex"), Reviewed: true}
	execute := func(c Command, o EvidenceOptionsV4) (CommandResult, error) {
		args := append([]string{"--format", "json"}, strings.Split(string(c), " ")...)
		args = append(args, "--ceremony", o.CeremonyPath, "--ceremony-signature", o.CeremonySignaturePath, "--coordinator-public-key-file", o.CoordinatorPublicKeyFile, "--artifact-root", o.ArtifactRoot, "--checkpoint", o.CheckpointPath, "--checkpoint-signature", o.CheckpointSignaturePath)
		switch c {
		case CommandOpsPrepareBundleV4:
			args = append(args, "--assembled-at", o.AssembledAt, "--out", o.OutPath)
		case CommandOpsSignBundleV4:
			args = append(args, "--operational-bundle", o.BundlePath, "--coordinator-signing-key", o.CoordinatorSigningKey, "--reviewed-sha256", o.ReviewedSHA256, "--out", o.OutPath)
			if o.Reviewed {
				args = append(args, "--reviewed")
			}
		case CommandReleaseReviewV4:
			args = append(args, "--operational-bundle", o.BundlePath, "--operational-bundle-signature", o.BundleSignaturePath, "--released-at", o.ReleasedAt, "--out", o.OutPath)
		case CommandCheckpointVerifyReleaseV4:
			args = append(args, "--inventory-out", o.OutPath)
		}
		var stderr bytes.Buffer
		process := exec.Command(cli, args...)
		process.Stderr = &stderr
		b, err := process.Output()
		if err != nil {
			return CommandResult{}, fmt.Errorf("CLI: %w: %s %s", err, b, stderr.Bytes())
		}
		var result CommandResult
		if err := json.Unmarshal(b, &result); err != nil {
			return result, fmt.Errorf("result: %w: %s", err, b)
		}
		return result, nil
	}
	metadataResult, err := execute(CommandCheckpointInspectEnrollmentsV4, o)
	if err != nil {
		t.Fatal(err)
	}
	metadata := metadataResult.EnrollmentMetadataV4
	if metadata == nil || len(metadata.Metadata.Enrollments) == 0 || metadata.Metadata.Checkpoint != review.ReviewCheckpoint || !metadata.EnrollmentSignaturesVerified || metadata.DisclosureContentsVerified || metadata.CompleteRosterVerified || metadata.GlobalFreshnessVerified {
		t.Fatalf("committed enrollment inspection: %+v", metadata)
	}
	structure := metadataResult.CheckpointInspectionV4
	if structure == nil || structure.CheckpointRefs != metadata.Metadata.Checkpoint || len(structure.Commitments.Enrollments) != len(metadata.Metadata.Enrollments) || structure.Depth != "checkpoint-structure" || structure.ArtifactsVerified || structure.MathematicsReplayed || structure.GlobalFreshnessVerified {
		t.Fatal("missing or overclaimed combined structure")
	}
	for n, item := range metadata.Metadata.Enrollments {
		if item.Refs != structure.Commitments.Enrollments[n] {
			t.Fatal("combined enrollment set mismatch")
		}
	}
	// A committed signature is required on every read; a previous inspection
	// cannot substitute for missing or changed bytes.
	committedSignature := filepath.Join(root, metadata.Metadata.Enrollments[0].Refs.Signature.Name)
	signatureBytes := read(committedSignature)
	if err := os.Remove(committedSignature); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(CommandCheckpointInspectEnrollmentsV4, o); err == nil {
		t.Fatal("missing committed enrollment signature accepted")
	}
	writeDecisionTestFile(t, committedSignature, []byte("changed"), 0o600)
	if _, err := execute(CommandCheckpointInspectEnrollmentsV4, o); err == nil {
		t.Fatal("changed committed enrollment signature accepted")
	}
	writeDecisionTestFile(t, committedSignature, signatureBytes, 0o600)
	original := read(o.BundlePath)
	var bundle m.OperationalEvidenceBundle
	if err := m.UnmarshalCanonical(original, &bundle); err != nil {
		t.Fatal(err)
	}
	o.AssembledAt = bundle.AssembledAt
	// Only known files inside this fresh test directory are replaced.
	for _, p := range []string{o.BundlePath, o.BundleSignaturePath} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	// Appending one byte keeps this test ELF executable runnable while making its
	// exact digest unapproved. No production artifact is changed.
	approvedCLI := cli
	cli = filepath.Join(t.TempDir(), "unapproved-cli")
	writeDecisionTestFile(t, cli, append(read(approvedCLI), 0), 0700)
	unapproved := o
	unapproved.OutPath = o.BundleSignaturePath
	unapproved.CoordinatorSigningKey = filepath.Join(root, "MISSING-KEY")
	unapproved.ReviewedSHA256 = fmt.Sprintf("%x", sha256.Sum256(original))
	_, unapprovedErr := execute(CommandOpsSignBundleV4, unapproved)
	cli = approvedCLI
	if unapprovedErr == nil || !strings.Contains(unapprovedErr.Error(), "running software") {
		t.Fatal("unapproved executable did not fail at software gate", unapprovedErr)
	}
	if _, err := os.Lstat(unapproved.OutPath); !os.IsNotExist(err) {
		t.Fatal("unapproved executable wrote output")
	}
	o.OutPath = o.BundlePath
	prepared, err := execute(CommandOpsPrepareBundleV4, o)
	if err != nil || !bytes.Equal(read(o.BundlePath), original) {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.EvidenceInspectionV4.SourceCheckpoint != review.ReviewCheckpoint {
		t.Fatal("source head not exposed")
	}
	if _, err := execute(CommandOpsPrepareBundleV4, o); err == nil {
		t.Fatal("bundle overwrite accepted")
	}
	o.OutPath = o.BundleSignaturePath
	o.ReviewedSHA256 = fmt.Sprintf("%x", sha256.Sum256(original))
	bad := o
	bad.ReviewedSHA256 = strings.Repeat("0", 64)
	bad.CoordinatorSigningKey = filepath.Join(root, "MISSING-KEY")
	if _, err := execute(CommandOpsSignBundleV4, bad); err == nil || !strings.Contains(err.Error(), "changed since owner review") {
		t.Fatal("review mismatch did not precede key access", err)
	}
	bad = o
	bad.CoordinatorSigningKey = filepath.Join(runRoot, "identity-keys/participant-01.ed25519.private.hex")
	if _, err := execute(CommandOpsSignBundleV4, bad); err == nil || !strings.Contains(err.Error(), "not the authenticated coordinator") {
		t.Fatal("wrong key accepted", err)
	}
	target := filepath.Join(root, bundle.Phase1.AcceptedHeads[0].AcceptedChainPrefix.Record.Name)
	saved := read(target)
	writeDecisionTestFile(t, target, append(bytes.Clone(saved), '\n'), 0600)
	bad.CoordinatorSigningKey = filepath.Join(root, "MISSING-KEY")
	_, rejected := execute(CommandOpsSignBundleV4, bad)
	writeDecisionTestFile(t, target, saved, 0600)
	if rejected == nil || strings.Contains(rejected.Error(), "MISSING-KEY") {
		t.Fatal("changed evidence did not fail before key access", rejected)
	}
	if _, err := os.Lstat(o.OutPath); !os.IsNotExist(err) {
		t.Fatal("failed signing wrote output")
	}
	if _, err := execute(CommandOpsSignBundleV4, o); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(CommandOpsSignBundleV4, o); err == nil {
		t.Fatal("signature overwrite accepted")
	}
	// Generic bundle commands cannot select this checkpoint and must stay closed.
	if _, err := executeOpsPrepareBundle(OpsPrepareBundleOptions{CeremonyPath: trust.DefinitionPath, CeremonySignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyPath, EvidenceRoot: root, OutDir: filepath.Join(root, "operational")}); err == nil || !strings.Contains(err.Error(), "prepare-bundle-v4") {
		t.Fatal("legacy bundle prepare accepted V4", err)
	}
	if _, err := executeOpsSign(OpsSignOptions{OpsExportSigningOptions: OpsExportSigningOptions{RecordType: "evidence-bundle", RecordPath: o.BundlePath, CeremonyPath: trust.DefinitionPath, CeremonySignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyPath}, Reviewed: true, ReviewedSHA256: o.ReviewedSHA256, EvidenceRoot: root, SigningKey: "MISSING-KEY", OutPath: filepath.Join(root, "never.sig")}); err == nil || !strings.Contains(err.Error(), "sign-bundle-v4") {
		t.Fatal("legacy bundle sign accepted V4", err)
	}
	if _, err := executeOpsExportSigning(OpsExportSigningOptions{RecordType: "evidence-bundle", RecordPath: o.BundlePath, CeremonyPath: trust.DefinitionPath, CeremonySignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyPath, OutDir: filepath.Join(root, "never-export")}); err == nil || !strings.Contains(err.Error(), "sign-bundle-v4") {
		t.Fatal("legacy bundle export accepted V4", err)
	}
	if _, err := executeOpsImportSignature(OpsImportSignatureOptions{RecordType: "evidence-bundle", CanonicalPath: o.BundlePath, CeremonyPath: trust.DefinitionPath, CeremonySignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyPath, OutPath: filepath.Join(root, "never-import.sig")}); err == nil || !strings.Contains(err.Error(), "sign-bundle-v4") {
		t.Fatal("legacy bundle signature import accepted V4", err)
	}
	o.OutPath = filepath.Join(root, "review-report.json")
	writeDecisionTestFile(t, o.BundlePath, append(bytes.Clone(original), '\n'), 0600)
	_, rejected = execute(CommandReleaseReviewV4, o)
	writeDecisionTestFile(t, o.BundlePath, original, 0600)
	if rejected == nil {
		t.Fatal("changed signed bundle accepted for review")
	}
	if _, err := execute(CommandReleaseReviewV4, o); err != nil {
		t.Fatal(err)
	}
	want, err := m.MarshalCanonical(*review)
	if err != nil || !bytes.Equal(read(o.OutPath), want) {
		t.Fatal("review report differs from verified exact review", err)
	}
	files, err := filepath.Glob(filepath.Join(root, "checkpoints/*-release.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing exact release checkpoint", files, err)
	}
	o.CheckpointPath, o.CheckpointSignaturePath = files[0], strings.TrimSuffix(files[0], ".json")+".sig"
	o.OutPath = filepath.Join(root, "inventory-report.json")
	result, err := execute(CommandCheckpointVerifyReleaseV4, o)
	if err != nil {
		t.Fatal(err)
	}
	var inventory ReleaseInventoryReportV4
	if err := m.UnmarshalCanonical(read(o.OutPath), &inventory); err != nil {
		t.Fatal(err)
	}
	if !inventory.ArtifactsVerified || !inventory.CoordinatorReplayClaimBound || inventory.MathematicsReplayed || inventory.GlobalFreshnessVerified || inventory.ProductionAuthorized || inventory.Published || len(inventory.Artifacts) <= 5 || inventory.Release.ReleaseID != result.ReleaseID {
		t.Fatal("incorrect verification claims")
	}
	tampered := bytes.Replace(read(o.OutPath), []byte(`"published":false`), []byte(`"published":true`), 1)
	var invalid ReleaseInventoryReportV4
	if err := m.UnmarshalCanonical(tampered, &invalid); err == nil {
		t.Fatal("inventory overclaim accepted")
	}
	// A later released checkpoint is not eligible for preparing another bundle.
	bad = o
	bad.OutPath = filepath.Join(root, "unused-report.json")
	if _, err := execute(CommandReleaseReviewV4, bad); err == nil {
		t.Fatal("released head accepted for pre-release review")
	}
	for _, a := range inventory.Artifacts {
		if strings.HasPrefix(a.Name, inventory.PackagePrefix) {
			t.Fatal("inventory names not package-relative")
		}
	}
	// A verified metadata chain is insufficient when even one package byte changed.
	packageFile := filepath.Join(root, m.FinalReleasePackagePrefixV4, m.NativeVerifyingKeyFile)
	saved = read(packageFile)
	corrupt := bytes.Clone(saved)
	corrupt[len(corrupt)-1] ^= 1
	writeDecisionTestFile(t, packageFile, corrupt, 0600)
	o.OutPath = filepath.Join(root, "must-not-exist.json")
	_, rejected = execute(CommandCheckpointVerifyReleaseV4, o)
	writeDecisionTestFile(t, packageFile, saved, 0600)
	if rejected == nil {
		t.Fatal("corrupted full package accepted")
	}
	if _, err := os.Lstat(o.OutPath); !os.IsNotExist(err) {
		t.Fatal("failed verification wrote inventory")
	}
}
