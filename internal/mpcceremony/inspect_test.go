// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func inspectTestRef(name string, size int64) ArtifactRef {
	return ArtifactRef{
		Name: name,
		Digest: Digest{
			SHA256:     "sha256:" + strings.Repeat("ab", 32),
			Blake2b256: "blake2b256:" + strings.Repeat("cd", 32),
			Size:       size,
		},
	}
}

func TestMissingChainArtifactsReportsAbsentAndWrongSize(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "phase1"), 0o700); err != nil {
		t.Fatal(err)
	}
	present := filepath.Join(root, "phase1", "genesis.bin")
	if err := os.WriteFile(present, []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(root, "phase1", "contribution-0001.bin")
	if err := os.WriteFile(truncated, []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}

	chain := Chain{
		Phase:   Phase1,
		Genesis: inspectTestRef("phase1/genesis.bin", 8),
		Records: []ChainRecord{
			{OutputPayload: inspectTestRef("phase1/contribution-0001.bin", 8)},
			{OutputPayload: inspectTestRef("phase1/contribution-0002.bin", 8)},
		},
	}
	missing := missingChainArtifacts(root, chain)
	if len(missing) != 2 {
		t.Fatalf("missing = %v, want wrong-size and absent entries", missing)
	}
	if !strings.Contains(missing[0], "contribution-0001.bin") || !strings.Contains(missing[0], "size 3") {
		t.Fatalf("wrong-size entry = %q", missing[0])
	}
	if missing[1] != "phase1/contribution-0002.bin" {
		t.Fatalf("absent entry = %q", missing[1])
	}
}

func TestMissingChainArtifactsRejectsEscapingNames(t *testing.T) {
	t.Parallel()
	chain := Chain{
		Phase:   Phase2,
		Records: []ChainRecord{{OutputPayload: inspectTestRef("../outside.bin", 8)}},
	}
	missing := missingChainArtifacts(t.TempDir(), chain)
	if len(missing) != 1 || !strings.Contains(missing[0], "unresolvable") {
		t.Fatalf("missing = %v, want one unresolvable entry", missing)
	}
}

func TestInspectCeremonyRequiresTranscriptRoot(t *testing.T) {
	t.Parallel()
	_, err := InspectCeremony(InspectCeremonyOptions{
		Trust: TrustPaths{
			DefinitionPath:           "ceremony.json",
			DefinitionSignaturePath:  "ceremony.sig",
			CoordinatorPublicKeyPath: "coordinator.hex",
		},
	})
	if err == nil {
		t.Fatal("inspect accepted an empty transcript root")
	}
}
