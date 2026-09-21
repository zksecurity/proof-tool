// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import "fmt"

// The reviewed identity of the production destination-v3 circuit, as compiled
// from the patched vendor tree that scripts/bootstrap-vendor.sh reconstructs.
//
// Matches upstream optimized source 191ca9312b8081cfc5fd26581d7e8c2bcefcee73
// and its published v3 manifest's constraint_system_hash. The fork retains its
// ceremony codec/update patches, which must not change this circuit identity.
// A build without the reviewed vendor patches may compile a different circuit;
// reject it before signing a production definition.
//
// Update these values only when the reviewed circuit intentionally changes,
// together with the vendor patches and the release review that approves the
// new identity. Production definition validation calls this function, so the
// invariant is enforced when definitions are created or consumed rather than
// only by the init command.
const (
	CanonicalDestinationV3SHA256      = "sha256:bb0bc9891e4ed73c408f0f5d781040c542753540c6baad44b1419506451d209b"
	CanonicalDestinationV3Blake2b256  = "blake2b256:d1215047c4e53cba141fa1b25debd2b060330baf893ba90a6ac75fac19ca302c"
	CanonicalDestinationV3Size        = int64(101185815)
	CanonicalDestinationV3Constraints = uint64(1444667)
)

// ValidateCanonicalDestinationV3 rejects a compiled destination-v3 circuit
// whose serialized identity differs from the reviewed canonical build. It says
// nothing about other key versions: the rehearsal circuit is deliberately not
// pinned here.
func ValidateCanonicalDestinationV3(binding CircuitBinding) error {
	if binding.KeyVersion != KeyVersionDestinationV3 {
		return nil
	}
	if binding.Constraints != CanonicalDestinationV3Constraints {
		return fmt.Errorf(
			"compiled destination-v3 circuit has %d constraints, want canonical %d; "+
				"rebuild from the patched vendor tree (scripts/bootstrap-vendor.sh, then go build -mod=vendor)",
			binding.Constraints,
			CanonicalDestinationV3Constraints,
		)
	}
	if binding.R1CS.Digest.SHA256 != CanonicalDestinationV3SHA256 ||
		binding.R1CS.Digest.Blake2b256 != CanonicalDestinationV3Blake2b256 ||
		binding.R1CS.Digest.Size != CanonicalDestinationV3Size {
		return fmt.Errorf(
			"compiled destination-v3 R1CS digest %s (%d bytes) does not match the canonical reviewed build; "+
				"rebuild from the patched vendor tree (scripts/bootstrap-vendor.sh, then go build -mod=vendor)",
			binding.R1CS.Digest.SHA256,
			binding.R1CS.Digest.Size,
		)
	}
	return nil
}
