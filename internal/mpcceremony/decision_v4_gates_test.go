package mpcceremony

import "testing"

func TestDecisionV5PreservesGatesWithExactCircuitRehearsal(t *testing.T) {
	d, x := decisionFixtureV3(t)
	if err := validateProductionDecisionBindingV4(d, x); err != nil {
		t.Fatal(err)
	}
	if len(x.Gates) != len(decisionGatesV3())-2 || x.Gates[5].Gate != GateExactCircuitRehearsal {
		t.Fatal("wrong gate count")
	}
	bad := x
	bad.Gates = append([]ProductionGateResultV3(nil), x.Gates...)
	bad.Gates = append(bad.Gates, ProductionGateResultV3{Gate: GateParticipantIndependent, Status: GatePASS, Evidence: []ArtifactRef{}})
	if _, err := NewProductionDecisionV3(bad); err == nil {
		t.Fatal("removed gate accepted")
	}
	draft := decisionDraftFixtureV3(x)
	draft.Schema = ProductionDecisionDraftSchemaV5
	prepared, err := draft.decision()
	if err != nil || prepared.DecisionID != x.DecisionID {
		t.Fatal("new decision draft round trip failed", err)
	}
}

func TestDecisionV5AcceptsExactProductionModeCircuit(t *testing.T) {
	for _, keyVersion := range []string{KeyVersionDestinationV3, KeyVersionRehearsal, KeyVersionRehearsalK11} {
		t.Run(keyVersion, func(t *testing.T) {
			d, x := decisionFixtureV3(t, keyVersion)
			if err := validateProductionDecisionBindingV4(d, x); err != nil {
				t.Fatal(err)
			}
			wrong := x
			other := *x.CircuitRehearsal
			other.Circuit = decisionFixtureCircuit(t, differentCircuit(keyVersion))
			wrong.CircuitRehearsal = &other
			var err error
			wrong, err = NewProductionDecisionV3(wrong)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateProductionDecisionBindingV4(d, wrong); err == nil {
				t.Fatal("decision for a different canonical circuit was accepted")
			}
			wrong = x
			wrong.CircuitRehearsal = nil
			if _, err := NewProductionDecisionV3(wrong); err == nil {
				t.Fatal("missing exact-circuit evidence accepted")
			}
			wrong = x
			wrong.K21Rehearsal = &K21RehearsalEvidenceV3{Circuit: d.Circuit, Evidence: x.CircuitRehearsal.Evidence}
			if _, err := NewProductionDecisionV3(wrong); err == nil {
				t.Fatal("historical K21 field accepted alongside circuit-neutral evidence")
			}
			d.Mode = ModeRehearsal
			if err := validateProductionDecisionBindingV4(d, x); err == nil {
				t.Fatal("rehearsal-mode definition accepted production decision")
			}
		})
	}
}

func decisionFixtureCircuit(t *testing.T, keyVersion string) CircuitBinding {
	t.Helper()
	circuit, err := CompileForKeyVersion(keyVersion)
	if err != nil {
		t.Fatal(err)
	}
	return circuit.Binding
}

func differentCircuit(keyVersion string) string {
	if keyVersion == KeyVersionRehearsal {
		return KeyVersionRehearsalK11
	}
	return KeyVersionRehearsal
}

func TestHistoricalK21DecisionKeepsItsCircuitRestriction(t *testing.T) {
	_, current := decisionFixtureV3(t)
	old := current
	old.Schema = ProductionDecisionSchemaV4
	old.K21Rehearsal = &K21RehearsalEvidenceV3{Circuit: current.CircuitRehearsal.Circuit, Evidence: current.CircuitRehearsal.Evidence}
	old.CircuitRehearsal = nil
	old.Gates = append([]ProductionGateResultV3(nil), current.Gates...)
	old.Gates[5].Gate = GateK21Rehearsal
	old, err := NewProductionDecisionV3(old)
	if err != nil {
		t.Fatal(err)
	}
	if old.Schema != ProductionDecisionSchemaV4 {
		t.Fatal("historical decision schema changed")
	}
	tiny := *old.K21Rehearsal
	tiny.Circuit = decisionFixtureCircuit(t, KeyVersionRehearsal)
	old.K21Rehearsal = &tiny
	if _, err := NewProductionDecisionV3(old); err == nil {
		t.Fatal("historical K21 decision accepted the tiny circuit")
	}
}
