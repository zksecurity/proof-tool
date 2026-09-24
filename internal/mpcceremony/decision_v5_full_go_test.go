package mpcceremony

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This local single-process test exercises a complete signed V5 package and
// production-mode GO control flow. It does not establish independent review,
// custody, erasure, publication, or readiness to use the keys in production.
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
			run.Env = append(run.Env, "MPC_WORKFLOW_CHECKPOINT_V4=1", "MPC_WORKFLOW_PRODUCTION_GO=1", "PROOF_TOOL_TEST_ZERO_ASSURANCE=1")
			if keyVersion == KeyVersionRehearsalK11 {
				run.Env = append(run.Env, "MPC_WORKFLOW_K11=1")
			}
			output, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("complete signed fixture: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "V5 complete production-mode GO passed") || !strings.Contains(string(output), "V4 final release checkpoint passed") {
				t.Fatalf("missing complete signed GO confirmation: %s", output)
			}
			trust := TrustPaths{DefinitionPath: filepath.Join(outputRoot, "ceremony", "ceremony.json"), DefinitionSignaturePath: filepath.Join(outputRoot, "ceremony", "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(outputRoot, "identity-keys", "trusted-coordinator.ed25519.public.hex")}
			trusted, err := LoadSignedDefinition(trust)
			if err != nil {
				t.Fatal(err)
			}
			if trusted.Definition.Mode != ModeProduction || trusted.Definition.Circuit.KeyVersion != keyVersion {
				t.Fatalf("signed definition mode/circuit: %s / %s", trusted.Definition.Mode, trusted.Definition.Circuit.KeyVersion)
			}
		})
	}
}
