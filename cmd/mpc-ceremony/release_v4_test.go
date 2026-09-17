package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestReleaseV4ExecutableAuthenticatesBeforeDispatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("approved executable identity is tested in Linux Docker")
	}
	root := t.TempDir()
	executable := filepath.Join(root, "mpc-ceremony")
	build := exec.Command("go", "build", "-o", executable, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	software, err := mpcceremony.SoftwareBindingFromExecutableFileForMode(executable, proofToolVersion, mpcceremony.ModeRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	d, _, key := decisionSignFixture(t)
	d.Mode, d.Software = mpcceremony.ModeRehearsal, software
	d.AssurancePolicy.ExternalSecurityAuditSignoffs = 0
	writeDefinition := func(v4 bool) {
		t.Helper()
		d.Schema, d.ReleaseVerification = mpcceremony.DefinitionSchemaV3, ""
		if v4 {
			d.Schema, d.ReleaseVerification = mpcceremony.DefinitionSchemaV4, "coordinator-full-replay-v1"
		}
		d, err = mpcceremony.FinalizeCeremonyDefinition(d)
		if err != nil {
			t.Fatal(err)
		}
		db, sig, err := mpcceremony.SignRecord(d, d.Coordinator.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		writeDecisionTestFile(t, filepath.Join(root, "ceremony.json"), db, 0o600)
		writeDecisionTestFile(t, filepath.Join(root, "ceremony.sig"), sig, 0o600)
	}
	writeDecisionTestFile(t, filepath.Join(root, "coordinator.hex"), []byte(d.Coordinator.Ed25519PublicKeyHex), 0o600)
	writeDecisionTestFile(t, filepath.Join(root, "release.hex"), []byte(d.ReleaseSigner.Ed25519PublicKeyHex), 0o600)
	trust := []string{"--ceremony", filepath.Join(root, "ceremony.json"), "--ceremony-signature", filepath.Join(root, "ceremony.sig"), "--coordinator-public-key-file", filepath.Join(root, "coordinator.hex")}
	common := append([]string{"release", "sign"}, trust...)
	common = append(common, "--operational-evidence-root", root, "--operational-bundle", filepath.Join(root, "bundle.json"), "--operational-bundle-signature", filepath.Join(root, "bundle.sig"),
		"--release-signing-key", filepath.Join(root, "MISSING-KEY"), "--signature-key-id", d.ReleaseSigner.KeyID, "--released-at", "2026-09-16T00:00:00Z", "--release-dir", filepath.Join(root, "output"))
	v4args := append(append([]string{}, common...), "--review-checkpoint", filepath.Join(root, "head.json"), "--review-checkpoint-signature", filepath.Join(root, "head.sig"))
	writeDefinition(false)
	assertCheckpointExecutableFails(t, executable, v4args, "requires definition v4")
	for _, command := range []Command{CommandOpsPrepareBundleV4, CommandOpsSignBundleV4, CommandReleaseReviewV4, CommandCheckpointVerifyReleaseV4} {
		args := evidenceArgsV4(command)
		copy(args[:6], trust)
		assertCheckpointExecutableFails(t, executable, append(strings.Split(string(command), " "), args...), "require definition v4")
	}
	legacy := append(append([]string{}, common...), "--candidate-bundle", root)
	for _, flag := range []string{"--transcript-root", "--phase1-chain", "--phase1-chain-signature", "--phase1-close", "--phase1-close-signature", "--phase1-beacon", "--phase1-beacon-signature", "--phase1-seal", "--phase1-seal-signature", "--phase2-chain", "--phase2-chain-signature", "--phase2-close", "--phase2-close-signature", "--phase2-beacon", "--phase2-beacon-signature"} {
		legacy = append(legacy, flag, root)
	}
	writeDefinition(true)
	assertCheckpointExecutableFails(t, executable, legacy, "requires --review-checkpoint")
	verify := append([]string{"release", "verify"}, trust...)
	verify = append(verify, "--keys-dir", root, "--manifest-public-key-file", filepath.Join(root, "release.hex"), "--signature-key-id", "wrong-key")
	assertCheckpointExecutableFails(t, executable, verify, "release signer id differs from signed definition")
	writeDecisionTestFile(t, filepath.Join(root, "ceremony.sig"), []byte("{}"), 0o600)
	output, err := exec.Command(executable, v4args...).CombinedOutput()
	if err == nil || strings.Contains(string(output), "review checkpoint:") {
		t.Fatalf("signature not checked before dispatch: %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(root, "output")); !os.IsNotExist(err) {
		t.Fatalf("failed command wrote output: %v", err)
	}
}

func releaseSignV4Args() []string {
	return []string{"--ceremony", "ceremony.json", "--ceremony-signature", "ceremony.sig", "--coordinator-public-key-file", "key.hex",
		"--operational-evidence-root", "evidence", "--operational-bundle", "evidence/bundle.json", "--operational-bundle-signature", "evidence/bundle.sig",
		"--release-signing-key", "private.hex", "--signature-key-id", "release-key", "--released-at", "2026-09-16T00:00:00Z", "--release-dir", "release"}
}

func TestReleaseV4ParserRequiresPairAndRejectsMixedLegacy(t *testing.T) {
	base := releaseSignV4Args()
	for _, extra := range [][]string{nil, {"--review-checkpoint", "evidence/head.json"}, {"--review-checkpoint-signature", "evidence/head.sig"}} {
		if _, err := parseReleaseSign(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatalf("incomplete shape accepted: %v", extra)
		}
	}
	args := append(base, "--review-checkpoint", "evidence/head.json", "--review-checkpoint-signature", "evidence/head.sig")
	if _, err := parseReleaseSign(args); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--candidate-bundle", "--audit-report", "--audit-signature", "--transcript-root",
		"--phase1-chain", "--phase1-chain-signature", "--phase1-close", "--phase1-close-signature", "--phase1-beacon", "--phase1-beacon-signature", "--phase1-seal", "--phase1-seal-signature",
		"--phase2-chain", "--phase2-chain-signature", "--phase2-close", "--phase2-close-signature", "--phase2-beacon", "--phase2-beacon-signature"} {
		t.Run(flag, func(t *testing.T) {
			if _, err := parseReleaseSign(append(append([]string{}, args...), flag, "legacy-file")); err == nil || !strings.Contains(err.Error(), "legacy") {
				t.Fatalf("mixed shape: %v", err)
			}
		})
	}
}

func TestReleaseV4MetadataFailureBeforeKeyOrOutput(t *testing.T) {
	root := t.TempDir()
	head, sig, bundle, bundleSig := filepath.Join(root, "head.json"), filepath.Join(root, "head.sig"), filepath.Join(root, "bundle.json"), filepath.Join(root, "bundle.sig")
	for _, path := range []string{head, sig, bundle, bundleSig} {
		writeDecisionTestFile(t, path, []byte("{}"), 0o600)
	}
	o := ReleaseSignOptions{ReviewCheckpointPath: head, ReviewSignaturePath: sig, OperationalEvidenceRoot: root,
		OperationalBundlePath: bundle, OperationalSignaturePath: bundleSig, ReleaseSigningKey: filepath.Join(root, "MISSING-KEY"),
		ReleasedAt: "2026-09-16T00:00:00Z", ReleaseDir: filepath.Join(root, "output")}
	for _, tc := range []struct {
		name, path string
		size       int64
	}{
		{"checkpoint", head, maxOperationalRecordBytes + 1}, {"signature", sig, 4097}, {"bundle", bundle, maxOperationalRecordBytes + 1}, {"bundle signature", bundleSig, 4097},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.OpenFile(tc.path, os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tc.size); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = executeReleaseSignV4(o, mpcceremony.TrustPaths{}, "unused")
			if err == nil || strings.Contains(err.Error(), "MISSING-KEY") {
				t.Fatalf("metadata not rejected before key: %v", err)
			}
			if _, err := os.Stat(o.ReleaseDir); !os.IsNotExist(err) {
				t.Fatalf("unexpected output: %v", err)
			}
			writeDecisionTestFile(t, tc.path, []byte("{}"), 0o600)
		})
	}
}
