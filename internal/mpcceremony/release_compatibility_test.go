package mpcceremony

import (
	"strings"
	"testing"
)

func TestReleasedSignerReplayRequirementsRemainExplicit(t *testing.T) {
	for _, schema := range []string{"proof-tool-mpc-ceremony-definition-v1", "proof-tool-mpc-ceremony-definition-v2"} {
		if err := verifyRequiredReleaseSignerReplay(schema, SignReleaseOptions{}); err != nil {
			t.Fatalf("legacy replay procedure changed for %s: %v", schema, err)
		}
	}
	for _, options := range []SignReleaseOptions{{}, {Replay: &ReplayPaths{}}, {Circuit: &CompiledCircuit{}}} {
		err := verifyRequiredReleaseSignerReplay("proof-tool-mpc-ceremony-definition-v3", options)
		if err == nil || !strings.Contains(err.Error(), "requires independent two-phase replay") {
			t.Fatalf("released v3 accepted missing replay inputs: %v", err)
		}
	}
	// Merely filling the pointers is not replay evidence.
	err := verifyRequiredReleaseSignerReplay("proof-tool-mpc-ceremony-definition-v3", SignReleaseOptions{Replay: &ReplayPaths{}, Circuit: &CompiledCircuit{}})
	if err == nil || !strings.Contains(err.Error(), "release-signer independent replay") {
		t.Fatalf("released v3 skipped actual replay: %v", err)
	}
	for _, schema := range []string{"", "proof-tool-mpc-ceremony-definition-v4", "unknown"} {
		if err := verifyRequiredReleaseSignerReplay(schema, SignReleaseOptions{}); err == nil {
			t.Fatalf("unimplemented schema %q selected legacy behavior", schema)
		}
	}
}
