package mpcceremony

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

func TestPhase2ReplayLoaderBindsBytesConsumed(t *testing.T) {
	circuit := compileEngineCircuit(t)
	phase1, err := ContributePhase1(circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	commons, err := SealPhase1(circuit.Binding.DomainSize, bytes.Repeat([]byte{0x31}, contributionChallengeSize), []*gnarkmpc.Phase1{phase1})
	if err != nil {
		t.Fatal(err)
	}
	genesis, _, err := InitializePhase2(circuit, commons)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ContributePhase2(circuit, commons, nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := ContributePhase2(circuit, commons, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "contribution.bin")
	shape := contributionPhase2Shape(circuit.Binding.Phase2Shape)
	digest, err := WritePhase2FileNoReplace(path, first, shape)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{Records: []ChainRecord{{
		PreviousPayload: ArtifactRef{Name: "genesis.bin", Digest: NewDigest(serializeEngineArtifact(t, genesis))},
		OutputPayload:   ArtifactRef{Name: "contribution.bin", Digest: modelDigest(digest)},
	}}}
	load := phase2FileLoader(root, chain, shape, nil)
	if _, err := load(0); err != nil {
		t.Fatalf("original authenticated contribution: %v", err)
	}
	// Both files are valid contributions from the same genesis. Replacing the
	// authenticated file must fail even though its mathematics remain valid.
	if err := os.WriteFile(path, serializeEngineArtifact(t, replacement), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(0); err == nil || !strings.Contains(err.Error(), "digest differs") {
		t.Fatalf("replacement accepted or wrong refusal: %v", err)
	}
	if err := os.WriteFile(path, serializeEngineArtifact(t, first), 0600); err != nil {
		t.Fatal(err)
	}
	chain.Records[0].PreviousPayload.Digest = NewDigest([]byte("different predecessor"))
	if _, err := load(0); err == nil || !strings.Contains(err.Error(), "predecessor") {
		t.Fatalf("changed predecessor accepted or wrong refusal: %v", err)
	}
}
