package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestBundleExportPreservesExistingEvidence(t *testing.T) {
	for _, existing := range []bool{false, true} {
		root := t.TempDir()
		out := filepath.Join(root, "operational")
		if existing {
			if err := os.Mkdir(out, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "receipt.json"), []byte("original receipt"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		bundle, request, err := writeEvidenceBundleExport(root, out, []byte("bundle"), []byte("request"))
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]string{bundle: "bundle", request: "request"} {
			got, err := os.ReadFile(path)
			if err != nil || string(got) != want {
				t.Fatalf("%s: %q %v", path, got, err)
			}
		}
		if existing {
			got, err := os.ReadFile(filepath.Join(out, "receipt.json"))
			if err != nil || string(got) != "original receipt" {
				t.Fatal("receipt changed", err)
			}
		}
		if _, _, err := writeEvidenceBundleExport(root, out, []byte("replacement"), []byte("replacement")); err == nil {
			t.Fatal("overwrite accepted")
		}
	}
}

func TestBundleExportRejectsCollisionsAndUnsafePaths(t *testing.T) {
	for _, name := range []string{"evidence-bundle.json", "evidence-bundle.sig", "signing-request.json"} {
		for _, symlink := range []bool{false, true} {
			root := t.TempDir()
			out := filepath.Join(root, "operational")
			if err := os.Mkdir(out, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(out, name)
			var err error
			if symlink {
				err = os.Symlink(filepath.Join(root, "missing"), path)
			} else {
				err = os.WriteFile(path, []byte("keep"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := writeEvidenceBundleExport(root, out, []byte("bundle"), []byte("request")); err == nil {
				t.Fatal("collision accepted", name)
			}
			entries, err := os.ReadDir(out)
			if err != nil || len(entries) != 1 {
				t.Fatal("collision wrote outputs", err)
			}
		}
	}
	root, outside := t.TempDir(), t.TempDir()
	if _, _, err := writeEvidenceBundleExport(root, outside, []byte("bundle"), []byte("request")); err == nil {
		t.Fatal("wrong release path accepted")
	}
	if err := os.Symlink(outside, filepath.Join(root, "operational")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeEvidenceBundleExport(root, filepath.Join(root, "operational"), []byte("bundle"), []byte("request")); err == nil {
		t.Fatal("symlink directory accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside evidence root", err)
	}
}

func TestBundleExportConcurrentPreparationsDoNotMix(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "operational")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, value := range []string{"first", "second"} {
		wg.Go(func() {
			_, _, err := writeEvidenceBundleExport(root, out, []byte(value), []byte(value))
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful preparations: %d", success)
	}
	bundle, err := os.ReadFile(filepath.Join(out, "evidence-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(filepath.Join(out, "signing-request.json"))
	if err != nil || string(bundle) != string(request) {
		t.Fatal("mixed concurrent outputs", err)
	}
}
