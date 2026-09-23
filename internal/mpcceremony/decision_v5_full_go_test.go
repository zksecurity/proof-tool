package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is a local, single-process control-flow test. It uses real contribution
// math and a complete signed release, but does not establish independent
// operators, custody, erasure, publication, or mainnet readiness.
func TestProductionModeV5FullPackageGO(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("complete local signed production-mode GO fixture requires Linux")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	for _, keyVersion := range []string{KeyVersionRehearsal, KeyVersionRehearsalK11} {
		t.Run(keyVersion, func(t *testing.T) {
			outputRoot := filepath.Join(t.TempDir(), "ceremony-run")
			helper := filepath.Join(t.TempDir(), "workflow")
			build := exec.Command("go", "build", "-trimpath", "-o", helper, "./internal/mpcceremony/testdata/workflowhelper")
			build.Dir = repo
			build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOAMD64=v1")
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build clean production fixture: %v\n%s", err, output)
			}
			run := exec.Command(helper, outputRoot)
			run.Dir = repo
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "MPC_WORKFLOW_") || strings.HasPrefix(entry, "MPC_CEREMONY_TEST_") || strings.HasPrefix(entry, "PROOF_TOOL_TEST_") {
					continue
				}
				run.Env = append(run.Env, entry)
			}
			run.Env = append(run.Env, "MPC_WORKFLOW_CHECKPOINT_V4=1", "MPC_WORKFLOW_PRODUCTION_GO=1", "PROOF_TOOL_TEST_ZERO_ASSURANCE=1", "MPC_WORKFLOW_RETAIN_REVIEW=1")
			if keyVersion == KeyVersionRehearsalK11 {
				run.Env = append(run.Env, "MPC_WORKFLOW_K11=1")
			}
			output, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("complete signed fixture: %v\n%s", err, output)
			}
			matches, err := filepath.Glob(filepath.Join(outputRoot, "review-dependencies-*"))
			if err != nil || len(matches) != 1 {
				t.Fatalf("retained verified release snapshot: %v, %d matches", err, len(matches))
			}
			root := matches[0]
			trust := TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(outputRoot, "identity-keys", "trusted-coordinator.ed25519.public.hex")}
			trusted, err := LoadSignedDefinition(trust)
			if err != nil {
				t.Fatal(err)
			}
			d := trusted.Definition
			if d.Mode != ModeProduction || d.Circuit.KeyVersion != keyVersion {
				t.Fatalf("signed definition mode/circuit: %s / %s", d.Mode, d.Circuit.KeyVersion)
			}
			heads, err := filepath.Glob(filepath.Join(root, "checkpoints", "*-release.json"))
			if err != nil || len(heads) != 1 {
				t.Fatalf("signed final release checkpoint: %v, %d matches", err, len(heads))
			}
			name := strings.TrimSuffix(strings.TrimPrefix(heads[0], root+string(filepath.Separator)), ".json")
			ref := func(suffix string) ArtifactRef {
				t.Helper()
				path := filepath.Join(root, name+suffix)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return ArtifactRef{Name: name + suffix, Digest: NewDigest(raw)}
			}
			head := SignedArtifactRefs{Record: ref(".json"), Signature: ref(".sig")}
			release, _, err := VerifyFinalReleaseCheckpointV4(trust, root, head)
			if err != nil {
				t.Fatal(err)
			}
			_, decision := decisionFixtureV3(t, keyVersion)
			decision.CeremonyID = d.CeremonyID
			decision.AssurancePolicy = cloneAssurancePolicy(d.AssurancePolicy)
			decision.CircuitRehearsal.Circuit = d.Circuit
			decision.SourceRelease.SourceCommit = d.Software.SourceCommit
			decision.Release, err = NewFinalReleaseEvidenceV4(d.CeremonyID, head, release.Candidate.CandidateID)
			if err != nil {
				t.Fatal(err)
			}
			decision, err = NewProductionDecisionV3(decision)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := decisionExternalArtifactsV3(decision)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range refs {
				path := filepath.Join(root, r.Name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("public fixture"), 0600); err != nil || NewDigest([]byte("public fixture")) != r.Digest {
					t.Fatalf("write exact external fixture evidence %s: %v", r.Name, err)
				}
			}
			raw, err := MarshalCanonical(decision)
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifyProductionDecisionEvidenceV4Options{Trust: trust, ArtifactRoot: root, DecisionBytes: raw}
			if _, err := VerifyProductionDecisionEvidenceV4(opts); err != nil {
				t.Fatalf("verify complete GO evidence: %v", err)
			}
			coordinatorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x81}, 32))
			releaseKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x82}, 32))
			coordinatorSig, err := SignProductionDecisionV4(opts, DecisionSignerCoordinator, d.Coordinator.ID, coordinatorKey)
			if err != nil {
				t.Fatal(err)
			}
			releaseSig, err := SignProductionDecisionV4(opts, DecisionSignerRelease, d.ReleaseSigner.ID, releaseKey)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyProductionDecisionV4(VerifyProductionDecisionV4Options{VerifyProductionDecisionEvidenceV4Options: opts, SignatureBytes: [][]byte{coordinatorSig, releaseSig}})
			if err != nil || verified.Decision.Decision != DecisionGO || len(verified.VerifiedSigners) != 2 {
				t.Fatalf("signed full-package GO: %v", err)
			}
		})
	}
}
