// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import (
	"strings"
	"testing"
)

func canonicalBinding() CircuitBinding {
	return CircuitBinding{
		KeyVersion: KeyVersionDestinationV2,
		R1CS: ArtifactRef{
			Name: "ownership-destination.ccs",
			Digest: Digest{
				SHA256:     CanonicalDestinationV2SHA256,
				Blake2b256: CanonicalDestinationV2Blake2b256,
				Size:       CanonicalDestinationV2Size,
			},
		},
		Constraints: CanonicalDestinationV2Constraints,
	}
}

func TestValidateCanonicalDestinationV2(t *testing.T) {
	if err := ValidateCanonicalDestinationV2(canonicalBinding()); err != nil {
		t.Fatalf("canonical binding rejected: %v", err)
	}

	// The rehearsal circuit is not pinned by this check.
	rehearsal := canonicalBinding()
	rehearsal.KeyVersion = "rehearsal-tiny-v1"
	rehearsal.Constraints = 5
	if err := ValidateCanonicalDestinationV2(rehearsal); err != nil {
		t.Fatalf("non-destination-v2 binding rejected: %v", err)
	}

	// The observed unvendored-build fork: same key version, different circuit.
	unvendored := canonicalBinding()
	unvendored.Constraints = 1791413
	err := ValidateCanonicalDestinationV2(unvendored)
	if err == nil || !strings.Contains(err.Error(), "bootstrap-vendor.sh") {
		t.Fatalf("unvendored constraint count accepted or unhelpful error: %v", err)
	}

	mutations := []func(*CircuitBinding){
		func(b *CircuitBinding) { b.R1CS.Digest.SHA256 = "sha256:" + strings.Repeat("0", 64) },
		func(b *CircuitBinding) { b.R1CS.Digest.Blake2b256 = "blake2b256:" + strings.Repeat("0", 64) },
		func(b *CircuitBinding) { b.R1CS.Digest.Size = CanonicalDestinationV2Size + 1 },
	}
	for i, mutate := range mutations {
		binding := canonicalBinding()
		mutate(&binding)
		if err := ValidateCanonicalDestinationV2(binding); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}
