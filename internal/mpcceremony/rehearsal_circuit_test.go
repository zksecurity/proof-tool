package mpcceremony

import (
	"strings"
	"testing"
)

// TestCompileForKeyVersionRejectsUnknown keeps the registry a closed set. An
// unknown key version must be an error rather than a request the definition
// gets to make.
func TestCompileForKeyVersionRejectsUnknown(t *testing.T) {
	for _, keyVersion := range []string{
		"", "ownership", "ownership-destination-v3",
		"rehearsal-tiny-v2", " rehearsal-tiny-v1",
	} {
		if _, err := CompileForKeyVersion(keyVersion); err == nil {
			t.Errorf("CompileForKeyVersion(%q) accepted an unknown circuit", keyVersion)
		}
	}
}

func TestRehearsalCircuitCompilesSmall(t *testing.T) {
	circuit, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatalf("CompileForKeyVersion: %v", err)
	}
	if circuit.Binding.KeyVersion != KeyVersionRehearsal ||
		circuit.Binding.CircuitID != CircuitIDRehearsal {
		t.Fatalf("binding identity is %+v", circuit.Binding)
	}
	// The entire point is a small domain. If the rehearsal circuit ever grew to
	// production scale it would stop being useful and this test should fail
	// rather than quietly cost minutes per contribution.
	if circuit.Binding.DomainSize > 1<<12 {
		t.Fatalf("rehearsal domain is %d, expected something tiny", circuit.Binding.DomainSize)
	}
	if circuit.Binding.Curve != CurveBLS12381 || circuit.Binding.Backend != BackendGroth16 {
		t.Fatalf("rehearsal circuit must use the same curve and backend: %+v", circuit.Binding)
	}
}

// TestCircuitBindingChecksIdentityAsAPair guards the weakness introduced by
// moving from equality with one constant to membership in a set: a definition
// naming one circuit's key version with another's circuit id would otherwise
// satisfy two independent checks while describing nothing that exists.
func TestCircuitBindingChecksIdentityAsAPair(t *testing.T) {
	base, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	mixed := base.Binding
	mixed.CircuitID = CircuitIDDestinationV2
	if err := mixed.Validate(); err == nil {
		t.Fatal("Validate accepted a rehearsal key_version with the destination-v2 circuit_id")
	}

	swapped := base.Binding
	swapped.KeyVersion = KeyVersionDestinationV2
	if err := swapped.Validate(); err == nil {
		t.Fatal("Validate accepted a destination-v2 key_version with the rehearsal circuit_id")
	}
}

// TestProductionRejectsRehearsalCircuit is the guard that restores what the
// membership check gave up. A rehearsal transcript proves nothing about a
// production ceremony, and the definition is the only place that knows the mode.
func TestProductionRejectsRehearsalCircuit(t *testing.T) {
	circuit, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	definition := CeremonyDefinition{
		Schema:  DefinitionSchema,
		Mode:    ModeProduction,
		Circuit: circuit.Binding,
	}
	err = definition.validate(false)
	if err == nil {
		t.Fatal("a production definition accepted the rehearsal circuit")
	}
	if !strings.Contains(err.Error(), KeyVersionDestinationV2) {
		t.Fatalf("error should name the required key version, got: %v", err)
	}
}

// TestRehearsalModeAcceptsRehearsalCircuit confirms the guard is conditional on
// the mode rather than rejecting the circuit outright, which would make the
// whole change pointless.
func TestRehearsalModeAcceptsRehearsalCircuit(t *testing.T) {
	circuit, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	definition := CeremonyDefinition{
		Schema:  DefinitionSchema,
		Mode:    ModeRehearsal,
		Circuit: circuit.Binding,
	}
	// The definition is otherwise empty, so validation fails on later fields.
	// What matters is that it does not fail on the circuit identity.
	err = definition.validate(false)
	if err != nil && strings.Contains(err.Error(), "key_version") {
		t.Fatalf("rehearsal mode rejected the rehearsal circuit: %v", err)
	}
}

// TestK21GateIgnoresRehearsalCircuit is the check that keeps a fast rehearsal
// from ever satisfying a production gate. K21RehearsalEvidence must continue to
// demand the production circuit at domain 2^21 regardless of what the registry
// now knows about.
func TestK21GateIgnoresRehearsalCircuit(t *testing.T) {
	circuit, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	evidence := K21RehearsalEvidence{
		KeyVersion:  circuit.Binding.KeyVersion,
		CircuitID:   circuit.Binding.CircuitID,
		Curve:       circuit.Binding.Curve,
		Backend:     circuit.Binding.Backend,
		Constraints: circuit.Binding.Constraints,
		DomainSize:  circuit.Binding.DomainSize,
	}
	if err := evidence.Validate(); err == nil {
		t.Fatal("the K21 rehearsal gate accepted evidence from the tiny rehearsal circuit")
	}
}
