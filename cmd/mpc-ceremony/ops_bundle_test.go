package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareBundleExplainsMissingEvidenceWithoutWriting(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinator := decisionSignFixture(t)
	trust := writeInspectionTrustFixture(t, root, definition, coordinator)
	out := filepath.Join(root, "fresh-bundle")
	o, err := parseOpsPrepareBundle(append(trust, "--evidence-root", root, "--out-dir", out))
	if err != nil {
		t.Fatal(err)
	}
	_, err = executeOpsPrepareBundle(o)
	if err == nil || !strings.Contains(err.Error(), "phase1 closure") || !strings.Contains(err.Error(), "phase2 closure") || !strings.Contains(err.Error(), "signed enrollment") {
		t.Fatalf("missing actionable diagnostics: %v", err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("incomplete preparation wrote an export")
	}
	o.CoordinatorPublicKeyFile = filepath.Join(root, "untrusted-missing-key")
	if _, err := executeOpsPrepareBundle(o); err == nil || strings.Contains(err.Error(), "evidence preparation incomplete") {
		t.Fatal("scanned before authenticating trust", err)
	}
}

func TestPrepareBundleCommandHelpAndRequiredInputs(t *testing.T) {
	if _, err := parseOpsPrepareBundle(nil); err == nil {
		t.Fatal("missing trust accepted")
	}
	if _, err := parseInvocation([]string{"ops", "prepare-bundle", "--help"}); err == nil {
		t.Fatal("expected help request")
	}
}
