package mpcceremony

import (
	"path/filepath"
	"testing"
)

func TestFinalReplayPathsV4UsesExactCheckpoint(t *testing.T) {
	pair := func(name string) *SignedArtifactRefs {
		return &SignedArtifactRefs{Record: ArtifactRef{Name: name + ".json"}, Signature: ArtifactRef{Name: name + ".sig"}}
	}
	p := CheckpointProgressV4{
		Phase1Closure: pair("phase1/closure/record"), Phase1Beacon: pair("phase1/beacon/record"), Phase1Seal: pair("phase1/seal/record"),
		Phase2Closure: pair("phase2/closure/record"), Phase2Beacon: pair("phase2/beacon/record"),
	}
	p.Phase1.Chain = *pair("phase1/chain-0002")
	phase2 := p.Phase1
	phase2.Chain = *pair("phase2/chain-0003")
	p.Phase2 = &phase2
	root := t.TempDir()
	trust := TrustPaths{DefinitionPath: "trusted-definition", DefinitionSignaturePath: "trusted-signature"}
	got, err := finalReplayPathsV4(trust, "trusted-key", root, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase1ChainPath != filepath.Join(root, "phase1/chain-0002.json") || got.Phase2ChainSignaturePath != filepath.Join(root, "phase2/chain-0003.sig") || got.DefinitionPath != trust.DefinitionPath || got.CoordinatorPublicKeyHex != "trusted-key" {
		t.Fatalf("replay inputs changed: %+v", got)
	}
	for _, missing := range []string{"phase1 closure", "phase1 beacon", "phase1 seal", "phase2", "phase2 closure", "phase2 beacon"} {
		t.Run(missing, func(t *testing.T) {
			incomplete := p
			switch missing {
			case "phase1 closure":
				incomplete.Phase1Closure = nil
			case "phase1 beacon":
				incomplete.Phase1Beacon = nil
			case "phase1 seal":
				incomplete.Phase1Seal = nil
			case "phase2":
				incomplete.Phase2 = nil
			case "phase2 closure":
				incomplete.Phase2Closure = nil
			case "phase2 beacon":
				incomplete.Phase2Beacon = nil
			}
			if _, err := finalReplayPathsV4(trust, "trusted-key", root, incomplete); err == nil {
				t.Fatal("accepted incomplete final replay inputs")
			}
		})
	}
}
