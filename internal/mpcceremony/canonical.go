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
	CanonicalRehearsalSHA256          = "sha256:177ab88ee828ca78f753d7e63342d5c86f3ba4ef19910ad4182d2d648b539519"
	CanonicalRehearsalBlake2b256      = "blake2b256:7b612a945dce98e9f6b4c091f3a1dcbe3fa28cc05514925fa0ccc9359bb1e427"
	CanonicalRehearsalSize            = int64(1046)
	CanonicalRehearsalConstraints     = uint64(5)
	CanonicalRehearsalK11SHA256       = "sha256:fda198668c2fced5fc936ab6bb2ce45ced054eb4a13659272ea2cf0b52383ebd"
	CanonicalRehearsalK11Blake2b256   = "blake2b256:f05f4e72676ac40d8f22b435c057c0d2e5dd06883708be3c5ac0f24d62297728"
	CanonicalRehearsalK11Size         = int64(38601)
	CanonicalRehearsalK11Constraints  = uint64(1030)
)

// ValidateCanonicalCeremonyCircuit pins every circuit permitted in a
// production-mode ceremony or an exact-circuit V5 production decision.
func ValidateCanonicalCeremonyCircuit(binding CircuitBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	switch binding.KeyVersion {
	case KeyVersionDestinationV3:
		return ValidateCanonicalDestinationV3(binding)
	case KeyVersionRehearsal:
		return validateCanonicalTestCircuit(binding, CanonicalRehearsalConstraints, 8,
			CanonicalRehearsalSHA256, CanonicalRehearsalBlake2b256, CanonicalRehearsalSize)
	case KeyVersionRehearsalK11:
		return validateCanonicalTestCircuit(binding, CanonicalRehearsalK11Constraints, 1<<11,
			CanonicalRehearsalK11SHA256, CanonicalRehearsalK11Blake2b256, CanonicalRehearsalK11Size)
	default:
		return fmt.Errorf("unsupported production-mode circuit %q", binding.KeyVersion)
	}
}

func validateCanonicalTestCircuit(binding CircuitBinding, constraints, domain uint64, sha, blake string, size int64) error {
	if binding.Constraints != constraints || binding.DomainSize != domain ||
		binding.R1CS.Digest.SHA256 != sha || binding.R1CS.Digest.Blake2b256 != blake ||
		binding.R1CS.Digest.Size != size {
		return fmt.Errorf("test circuit %q differs from the reviewed canonical R1CS", binding.KeyVersion)
	}
	return nil
}

// ValidateCanonicalDestinationV3 rejects a compiled destination-v3 circuit
// whose serialized identity differs from the reviewed canonical build. The
// production-mode test circuit pins are checked by ValidateCanonicalCeremonyCircuit.
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
