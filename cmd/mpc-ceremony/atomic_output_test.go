package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicOutputDirectoryIsIdempotentAndClosed(t *testing.T) {
	out := filepath.Join(t.TempDir(), "result")
	files := map[string][]byte{"checkpoint.json": []byte("checkpoint"), "checkpoint.sig": []byte("signature")}
	if err := writeAtomicOutputDir(out, files); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicOutputDir(out, files); err != nil {
		t.Fatalf("byte-identical retry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "checkpoint.sig"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicOutputDir(out, files); err == nil || !strings.Contains(err.Error(), "conflicting or incomplete") {
		t.Fatalf("conflicting retry = %v", err)
	}
}

func TestAtomicOutputFailureDoesNotPublishDirectory(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "result")
	if err := writeAtomicOutputDir(out, map[string][]byte{"nested/file": []byte("invalid")}); err == nil {
		t.Fatal("invalid nested output succeeded")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("failed output was published: %v", err)
	}
}
