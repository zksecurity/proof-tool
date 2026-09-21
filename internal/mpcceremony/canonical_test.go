// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import (
	"strings"
	"testing"
)

func canonicalBinding() CircuitBinding {
	return CircuitBinding{
		KeyVersion: KeyVersionDestinationV3,
		R1CS: ArtifactRef{
			Name: "ownership-destination.ccs",
			Digest: Digest{
				SHA256:     CanonicalDestinationV3SHA256,
				Blake2b256: CanonicalDestinationV3Blake2b256,
				Size:       CanonicalDestinationV3Size,
			},
		},
		Constraints: CanonicalDestinationV3Constraints,
	}
}

func TestValidateCanonicalDestinationV3(t *testing.T) {
	if err := ValidateCanonicalDestinationV3(canonicalBinding()); err != nil {
		t.Fatalf("canonical binding rejected: %v", err)
	}

	// The rehearsal circuit is not pinned by this check.
	rehearsal := canonicalBinding()
	rehearsal.KeyVersion = "rehearsal-tiny-v1"
	rehearsal.Constraints = 5
	if err := ValidateCanonicalDestinationV3(rehearsal); err != nil {
		t.Fatalf("non-destination-v3 binding rejected: %v", err)
	}

	// The observed unvendored-build fork: same key version, different circuit.
	unvendored := canonicalBinding()
	unvendored.Constraints = 1791413
	err := ValidateCanonicalDestinationV3(unvendored)
	if err == nil || !strings.Contains(err.Error(), "bootstrap-vendor.sh") {
		t.Fatalf("unvendored constraint count accepted or unhelpful error: %v", err)
	}

	mutations := []func(*CircuitBinding){
		func(b *CircuitBinding) { b.R1CS.Digest.SHA256 = "sha256:" + strings.Repeat("0", 64) },
		func(b *CircuitBinding) { b.R1CS.Digest.Blake2b256 = "blake2b256:" + strings.Repeat("0", 64) },
		func(b *CircuitBinding) { b.R1CS.Digest.Size = CanonicalDestinationV3Size + 1 },
	}
	for i, mutate := range mutations {
		binding := canonicalBinding()
		mutate(&binding)
		if err := ValidateCanonicalDestinationV3(binding); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

// The corrected optimized circuit must remain byte-identical to the reviewed
// upstream CCS even with this fork's ceremony codec and update patches.
func TestCompiledDestinationV3MatchesReviewedUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the production constraint system")
	}
	circuit, err := CompileDestinationV3()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCanonicalDestinationV3(circuit.Binding); err != nil {
		t.Fatal(err)
	}
}
