package mpcceremony

import "testing"

func TestSingleAuditorMinimumBothModes(t *testing.T) {
	for _, mode := range []string{ModeRehearsal, ModeProduction} {
		d := adversarialDefinition(t)
		d.Mode = mode
		d.Auditors = d.Auditors[:1]
		if _, err := FinalizeCeremonyDefinition(d); err != nil {
			t.Fatalf("%s one auditor: %v", mode, err)
		}
		p := InitParticipants{Coordinator: d.Coordinator, ReleaseSigner: d.ReleaseSigner, Auditors: d.Auditors, Roster: d.Roster}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		d.Auditors = nil
		if _, err := FinalizeCeremonyDefinition(d); err == nil {
			t.Fatal("zero auditors accepted")
		}
		p.Auditors = nil
		if err := p.Validate(); err == nil {
			t.Fatal("zero auditors in init accepted")
		}
	}
}
func TestProductionDecisionOneAuditMinimum(t *testing.T) {
	f := newProductionDecisionFixture(t, DecisionGO)
	value := f.decision
	value.DecisionID = ""
	value.Audits = value.Audits[:1]
	value.ExternalAudits = value.ExternalAudits[:1]
	if _, err := NewProductionDecision(value); err != nil {
		t.Fatal(err)
	}
	value.Audits = nil
	if _, err := NewProductionDecision(value); err == nil {
		t.Fatal("zero audits accepted")
	}
	value = f.decision
	value.DecisionID = ""
	value.ExternalAudits = nil
	if _, err := NewProductionDecision(value); err == nil {
		t.Fatal("zero external audits accepted")
	}
}
