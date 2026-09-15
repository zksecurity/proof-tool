package mpcceremony

import (
	"strings"
	"testing"
)

func TestSingleAuditorMinimumBothModes(t *testing.T) {
	for _, mode := range []string{ModeRehearsal, ModeProduction} {
		d := adversarialDefinition(t)
		d.Mode = mode
		if mode == ModeRehearsal {
			assurance := *d.AssurancePolicy
			assurance.ExternalSecurityAuditSignoffs = 0
			d.AssurancePolicy = &assurance
		}
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
		if err := p.Validate(); err != nil {
			t.Fatalf("zero-auditor roster must remain representable until signed policy validation: %v", err)
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

func TestProductionDecisionV2HonorsDisabledAssuranceControls(t *testing.T) {
	legacy := newProductionDecisionFixture(t, DecisionGO)
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	definition.Auditors = nil
	definition.AssurancePolicy = &AssurancePolicy{}
	definition, err := FinalizeCeremonyDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}

	value := legacy.decision
	value.Gates = append([]ProductionGateResult(nil), legacy.decision.Gates...)
	value.Schema = ""
	value.DecisionID = ""
	value.CeremonyID = definition.CeremonyID
	value.AssurancePolicy = &AssurancePolicy{}
	value.Audits = nil
	value.ExternalAudits = nil
	for index := range value.Gates {
		switch value.Gates[index].Gate {
		case GateIndependentAudits, GateExternalAudit, GatePublicWitnessing, GateImmutableMirrors:
			value.Gates[index].Status = GateNotRequired
			value.Gates[index].Evidence = nil
			value.Gates[index].Rationale = "Disabled by the signed assurance policy."
		}
	}
	decision, err := NewProductionDecision(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionDecisionBinding(definition, decision); err != nil {
		t.Fatalf("all-optional decision rejected: %v", err)
	}

	injected := decision
	injected.DecisionID = ""
	injected.Audits = legacy.decision.Audits[:1]
	if _, err = NewProductionDecision(injected); err == nil {
		t.Fatal("audit evidence accepted while ceremony audits were disabled")
	}

	wrongGate := decision
	wrongGate.DecisionID = ""
	for index := range wrongGate.Gates {
		if wrongGate.Gates[index].Gate == GatePublicWitnessing {
			wrongGate.Gates[index] = legacy.decision.Gates[index]
		}
	}
	if _, err = NewProductionDecision(wrongGate); err == nil {
		t.Fatal("enabled-looking witness gate accepted while witnessing was disabled")
	}

	mandatory := decision
	mandatory.DecisionID = ""
	mandatory.Gates = append([]ProductionGateResult(nil), decision.Gates...)
	mandatory.Gates[0] = ProductionGateResult{Gate: GateSignedRelease, Status: GateNotRequired, Rationale: "Attempted bypass."}
	if _, err := NewProductionDecision(mandatory); err == nil {
		t.Fatal("mandatory signed-release gate accepted NOT_REQUIRED")
	}
}

func TestLegacyDecisionCannotDisableOldMandatoryGates(t *testing.T) {
	fixture := newProductionDecisionFixture(t, DecisionGO)
	value := fixture.decision
	value.Schema = ProductionDecisionSchemaV1
	value.AssurancePolicy = nil
	value.DecisionID = ""
	for index := range value.Gates {
		if value.Gates[index].Gate == GatePublicWitnessing {
			value.Gates[index].Status = GateNotRequired
			value.Gates[index].Evidence = nil
			value.Gates[index].Rationale = "Disabled."
		}
	}
	if _, err := NewProductionDecision(value); err == nil || !strings.Contains(err.Error(), "cannot be NOT_REQUIRED") {
		t.Fatalf("legacy NOT_REQUIRED error = %v", err)
	}
}

func TestFinalTranscriptAndAuditVerifierHonorZeroAuditPolicy(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	definition.Auditors = nil
	policy := *definition.AssurancePolicy
	policy.PassingCeremonyAudits = 0
	definition.AssurancePolicy = &policy
	definition, err := FinalizeCeremonyDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	candidate := adversarialCandidate(t, definition)
	if refs, latest, err := verifyPassingAudits(definition, candidate, nil); err != nil || len(refs) != 0 || !latest.IsZero() {
		t.Fatalf("zero-audit verification = refs %v latest %v err %v", refs, latest, err)
	}

	transcript, err := NewFinalTranscript(FinalTranscript{
		CeremonyID:      definition.CeremonyID,
		AssurancePolicy: cloneAssurancePolicy(definition.AssurancePolicy),
		Definition:      candidate.Definition,
		Circuit:         definition.Circuit,
		Phase1:          candidate.Phase1,
		Phase2:          candidate.Phase2,
		Audits:          []ArtifactRef{},
		OperationalEvidence: SignedArtifactRefs{
			Record:    ArtifactRef{Name: "operational/evidence-bundle.json", Digest: NewDigest([]byte("bundle"))},
			Signature: ArtifactRef{Name: "operational/evidence-bundle.sig", Digest: NewDigest([]byte("signature"))},
		},
		ProvingKey:          candidate.ProvingKey,
		VerifyingKey:        candidate.VerifyingKey,
		CardanoVerifyingKey: candidate.CardanoVerifyingKey,
		FinalizedAt:         "2026-07-23T16:00:00Z",
	})
	if err != nil {
		t.Fatalf("zero-audit final transcript rejected: %v", err)
	}
	if transcript.Schema != FinalTranscriptSchema || transcript.AssurancePolicy == nil {
		t.Fatal("zero-audit final transcript did not use policy-bound v2 schema")
	}
}
