package mpcceremony

import "testing"

func TestDecisionV4RemovesOnlyTwoGates(t *testing.T) {
	d, x := decisionFixtureV3(t)
	old := x
	d.Schema = DefinitionSchemaV5
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	x.Schema = ProductionDecisionSchemaV4
	x.CeremonyID = d.CeremonyID
	x.Release, err = NewFinalReleaseEvidenceV4(d.CeremonyID, x.Release.FinalReleaseCheckpoint, x.Release.CandidateID)
	if err != nil {
		t.Fatal(err)
	}
	x.Gates = nil
	for _, g := range old.Gates {
		if g.Gate != GateParticipantIndependent && g.Gate != GateLiveTwentyParty {
			x.Gates = append(x.Gates, g)
		}
	}
	x, err = NewProductionDecisionV3(x)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionDecisionBindingV4(d, x); err != nil {
		t.Fatal(err)
	}
	if len(x.Gates) != len(old.Gates)-2 {
		t.Fatal("wrong gate count")
	}
	if err := validateProductionDecisionBindingV4(d, old); err == nil {
		t.Fatal("legacy decision accepted for new definition")
	}
	old.Gates = x.Gates
	if _, err := NewProductionDecisionV3(old); err == nil {
		t.Fatal("legacy decision lost mandatory gates")
	}
	bad := x
	bad.Gates = append([]ProductionGateResultV3(nil), x.Gates...)
	bad.Gates = append(bad.Gates, ProductionGateResultV3{Gate: GateParticipantIndependent, Status: GatePASS, Evidence: []ArtifactRef{}})
	if _, err := NewProductionDecisionV3(bad); err == nil {
		t.Fatal("removed gate accepted")
	}
	draft := decisionDraftFixtureV3(x)
	draft.Schema = ProductionDecisionDraftSchemaV4
	prepared, err := draft.decision()
	if err != nil || prepared.DecisionID != x.DecisionID {
		t.Fatal("new decision draft round trip failed", err)
	}
}
