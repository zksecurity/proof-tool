// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import "fmt"

// The reviewed identity of the production destination-v2 circuit, as compiled
// from the patched vendor tree that scripts/bootstrap-vendor.sh reconstructs.
//
// A build made without that vendor tree resolves upstream gnark from the
// module cache and compiles a slightly different circuit (observed:
// 1,791,413 constraints instead of 1,789,750), because reviewed patches such
// as the uints constant folding change the constraint system. Nothing about
// such a build fails on its own: init would sign the wrong circuit into the
// ceremony definition and every later stage would coherently verify against
// it. These constants let production init reject that fork at the source
// instead of discovering it after hours of ceremony compute.
//
// Update these values only when the reviewed circuit intentionally changes,
// together with the vendor patches and the release review that approves the
// new identity.
const (
	CanonicalDestinationV2SHA256      = "sha256:b5e629f47321048a6e2f85b3a839c1cf898454b69eef582f54e07d6d647074dc"
	CanonicalDestinationV2Blake2b256  = "blake2b256:bf2243b3f4885357bbad0b6728582f56f0e00cd361e1e8af8a2d0dbe10a9f352"
	CanonicalDestinationV2Size        = int64(129221468)
	CanonicalDestinationV2Constraints = uint64(1789750)
)

// ValidateCanonicalDestinationV2 rejects a compiled destination-v2 circuit
// whose serialized identity differs from the reviewed canonical build. It says
// nothing about other key versions: the rehearsal circuit is deliberately not
// pinned here.
func ValidateCanonicalDestinationV2(binding CircuitBinding) error {
	if binding.KeyVersion != KeyVersionDestinationV2 {
		return nil
	}
	if binding.Constraints != CanonicalDestinationV2Constraints {
		return fmt.Errorf(
			"compiled destination-v2 circuit has %d constraints, want canonical %d; "+
				"rebuild from the patched vendor tree (scripts/bootstrap-vendor.sh, then go build -mod=vendor)",
			binding.Constraints,
			CanonicalDestinationV2Constraints,
		)
	}
	if binding.R1CS.Digest.SHA256 != CanonicalDestinationV2SHA256 ||
		binding.R1CS.Digest.Blake2b256 != CanonicalDestinationV2Blake2b256 ||
		binding.R1CS.Digest.Size != CanonicalDestinationV2Size {
		return fmt.Errorf(
			"compiled destination-v2 R1CS digest %s (%d bytes) does not match the canonical reviewed build; "+
				"rebuild from the patched vendor tree (scripts/bootstrap-vendor.sh, then go build -mod=vendor)",
			binding.R1CS.Digest.SHA256,
			binding.R1CS.Digest.Size,
		)
	}
	return nil
}
