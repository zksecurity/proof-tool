package mpcceremony

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV4ChecksumMaximumBound(t *testing.T) {
	var data strings.Builder
	names := make([]string, maxReleaseReviewArtifactsV4+5)
	hash := strings.Repeat("a", 64)
	for i := range names {
		prefix := fmt.Sprintf("z/%08d/", i)
		name := prefix + strings.Repeat("a", 250) + "/"
		name += strings.Repeat("b", 512-len(name))
		names[i] = name
		fmt.Fprintf(&data, "%s  %s\n", hash, name)
	}
	raw := []byte(data.String())
	if len(raw) != maxReleaseChecksumsV4Bytes || len(raw) <= maxSignedRecordBytes {
		t.Fatalf("checksum maximum size %d does not match dedicated bound %d", len(raw), maxReleaseChecksumsV4Bytes)
	}
	file := filepath.Join(t.TempDir(), ReleaseChecksumsFile)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readRegularBounded(file, maxReleaseChecksumsV4Bytes)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseChecksumsExact(loaded, ReleaseChecksumsFile, names)
	if err != nil || len(entries) != len(names) {
		t.Fatalf("maximum checksum inventory: %d, %v", len(entries), err)
	}
	if _, err := readRegularBounded(file, maxSignedRecordBytes); err == nil {
		t.Fatal("legacy checksum bound widened")
	}
	if err := os.Truncate(file, maxReleaseChecksumsV4Bytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(file, maxReleaseChecksumsV4Bytes); err == nil {
		t.Fatal("oversized checksum file accepted")
	}
}

func TestExactChecksumParserRejectsInventoryChanges(t *testing.T) {
	hash := strings.Repeat("a", 64)
	line := func(name string) string { return hash + "  " + name + "\n" }
	for _, raw := range []string{line("a"), line("a") + line("b") + line("c"), line("a") + line("a"), line("a") + line("c"), line("b") + line("a"), line("../a") + line("b")} {
		if _, err := parseChecksumsExact([]byte(raw), ReleaseChecksumsFile, []string{"a", "b"}); err == nil {
			t.Fatal("changed inventory accepted")
		}
	}
	if _, err := parseChecksumsExact([]byte(line("a")+line("b")), ReleaseChecksumsFile, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
}
