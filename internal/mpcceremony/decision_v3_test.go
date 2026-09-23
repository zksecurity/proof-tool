package mpcceremony

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Structural fixture only: no production package, independence or GO outcome
// is established by these known-key records and placeholder evidence hashes.
func decisionFixtureV3(t *testing.T, keyVersion ...string) (CeremonyDefinition, ProductionDecisionV3) {
	t.Helper()
	d := trustedCoordinatorDefinition(t)
	if len(keyVersion) != 0 && keyVersion[0] != d.Circuit.KeyVersion {
		circuit, err := CompileForKeyVersion(keyVersion[0])
		if err != nil {
			t.Fatal(err)
		}
		d.Circuit = circuit.Binding
	}
	d.AssurancePolicy = &AssurancePolicy{}
	d.Auditors = []Identity{}
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(name string) ArtifactRef { return checkpointArtifact("decision/evidence/"+name, "public fixture") }
	release, err := NewFinalReleaseEvidenceV4(d.CeremonyID, checkpointSigned("checkpoints/final-release"), NewDigest([]byte("candidate")).SHA256)
	if err != nil {
		t.Fatal(err)
	}
	x := ProductionDecisionV3{Schema: ProductionDecisionSchemaV5, CeremonyID: d.CeremonyID, AssurancePolicy: cloneAssurancePolicy(d.AssurancePolicy), Release: release, SourceRelease: SourceReleaseEvidenceV4{SourceCommit: d.Software.SourceCommit, VerificationReport: ref("source-release.json")}, Auditors: []DecisionAuditorV3{}, ExternalAudits: []ExternalAuditEvidenceV3{}, CircuitRehearsal: &CircuitRehearsalEvidenceV5{Circuit: d.Circuit, Evidence: ref("circuit.json")}, MainnetDeploymentPlan: ref("deployment.md"), FormalChecklist: ref("checklist.md"), Decision: DecisionGO, DecidedAt: "2026-07-24T12:00:00Z"}
	for _, gate := range decisionGatesV5() {
		g := ProductionGateResultV3{Gate: gate, Status: GatePASS, Evidence: []ArtifactRef{}}
		if optional, enabled := optionalDecisionGateV3(gate, *d.AssurancePolicy); optional && !enabled {
			g.Status = GateNotRequired
			g.Rationale = "Disabled in signed policy"
		} else if !packageDerivedGateV3(gate) {
			g.Evidence = []ArtifactRef{ref(string(gate) + ".txt")}
		}
		if gate == GateSourceRelease {
			g.Evidence = []ArtifactRef{x.SourceRelease.VerificationReport}
		}
		switch gate {
		case GateExactCircuitRehearsal:
			g.Evidence = []ArtifactRef{x.CircuitRehearsal.Evidence}
		case GateMainnetDeploymentPlan:
			g.Evidence = []ArtifactRef{x.MainnetDeploymentPlan}
		case GateFormalChecklist:
			g.Evidence = []ArtifactRef{x.FormalChecklist}
		}
		x.Gates = append(x.Gates, g)
	}
	x, err = NewProductionDecisionV3(x)
	if err != nil {
		t.Fatal(err)
	}
	return d, x
}

func TestDecisionV3CanonicalAndLegacySeparation(t *testing.T) {
	d, x := decisionFixtureV3(t)
	if err := validateProductionDecisionBindingV4(d, x); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCanonical(x)
	if err != nil {
		t.Fatal(err)
	}
	var copy ProductionDecisionV3
	if err := UnmarshalCanonical(raw, &copy); err != nil {
		t.Fatal(err)
	}
	var old ProductionDecision
	if err := UnmarshalCanonical(raw, &old); err == nil {
		t.Fatal("legacy decision accepted v3")
	}
	legacy := adversarialDefinition(t)
	if err := validateProductionDecisionBindingV4(legacy, x); err == nil {
		t.Fatal("old definition accepted v3")
	}
	if err := validateProductionDecisionBinding(d, ProductionDecision{}); err == nil {
		t.Fatal("legacy decision binding accepted definition v4")
	}
	for _, schema := range []string{"", ProductionDecisionSchema, ProductionDecisionSchemaV1} {
		bad := x
		bad.Schema = schema
		if _, err := NewProductionDecisionV3(bad); err == nil {
			t.Fatal("implicit/cross-version schema accepted")
		}
	}
	for _, extra := range []string{`,"uri":"https://example.invalid/?token=secret"`, `,"signed_tag":"old"`, `,"signature_format":"openpgp-primary-key-v4"`} {
		// Unknown fields remain rejected at the top-level too.
		bad := append(bytes.Clone(raw[:len(raw)-1]), []byte(extra+"}")...)
		if err := UnmarshalCanonical(bad, &copy); err == nil {
			t.Fatal("unknown legacy/credential field accepted")
		}
	}
}

func TestDecisionV3ReleaseIDBindsAllInputs(t *testing.T) {
	_, d := decisionFixtureV3(t)
	for _, change := range []func(*FinalReleaseEvidenceV4){
		func(r *FinalReleaseEvidenceV4) { r.CeremonyID = NewDigest([]byte("other")).SHA256 },
		func(r *FinalReleaseEvidenceV4) { r.CandidateID = NewDigest([]byte("other")).SHA256 },
		func(r *FinalReleaseEvidenceV4) { r.FinalReleaseCheckpoint.Record.Digest = NewDigest([]byte("other")) },
		func(r *FinalReleaseEvidenceV4) {
			r.FinalReleaseCheckpoint.Signature.Digest = NewDigest([]byte("other"))
		},
	} {
		r := d.Release
		change(&r)
		if err := r.Validate(); err == nil {
			t.Fatal("changed release retained old ID")
		}
	}
}

func TestDecisionV3RejectsWrongPolicyEvidenceAndGates(t *testing.T) {
	d, x := decisionFixtureV3(t)
	for name, change := range map[string]func(*ProductionDecisionV3){
		"missing-policy":    func(x *ProductionDecisionV3) { x.AssurancePolicy = nil },
		"implicit-auditors": func(x *ProductionDecisionV3) { x.Auditors = nil },
		"implicit-external": func(x *ProductionDecisionV3) { x.ExternalAudits = nil },
		"missing-gate":      func(x *ProductionDecisionV3) { x.Gates = x.Gates[1:] },
		"source-other-file": func(x *ProductionDecisionV3) {
			x.Gates[0].Evidence = []ArtifactRef{checkpointArtifact("decision/evidence/other.json", "x")}
		},
		"source-unscoped": func(x *ProductionDecisionV3) { x.SourceRelease.VerificationReport.Name = "source-release.json" },
		"source-too-large": func(x *ProductionDecisionV3) {
			x.SourceRelease.VerificationReport.Digest.Size = maxSignedRecordBytes + 1
			x.Gates[0].Evidence = []ArtifactRef{x.SourceRelease.VerificationReport}
		},
		"wrong-circuit-domain": func(x *ProductionDecisionV3) { x.CircuitRehearsal.Circuit.DomainSize = 8 },
		"conflicting-report": func(x *ProductionDecisionV3) {
			x.FormalChecklist = checkpointArtifact(x.MainnetDeploymentPlan.Name, "other")
		},
		"private-path": func(x *ProductionDecisionV3) { x.MainnetDeploymentPlan.Name = "keys/signing.hex" },
		"disabled-audit": func(x *ProductionDecisionV3) {
			x.Auditors = []DecisionAuditorV3{{AuditorID: "injected", AuditorKeyID: "key"}}
		},
		"disabled-gate-pass": func(x *ProductionDecisionV3) {
			for i := range x.Gates {
				if x.Gates[i].Gate == GatePublicWitnessing {
					x.Gates[i].Status = GatePASS
				}
			}
		},
		"package-external-list": func(x *ProductionDecisionV3) { x.Gates[1].Evidence = []ArtifactRef{x.SourceRelease.VerificationReport} },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(x)
			var bad ProductionDecisionV3
			_ = json.Unmarshal(raw, &bad)
			change(&bad)
			if _, err := NewProductionDecisionV3(bad); err == nil {
				t.Fatal("invalid decision accepted")
			}
		})
	}
	bad := x
	bad.SourceRelease.SourceCommit = strings.Repeat("ab", 20)
	bad, _ = NewProductionDecisionV3(bad)
	if err := validateProductionDecisionBindingV4(d, bad); err == nil {
		t.Fatal("wrong source commit accepted")
	}
	bad = x
	policy := *x.AssurancePolicy
	policy.PublicWitnessesPerPhase = 1
	bad.AssurancePolicy = &policy
	for i := range bad.Gates {
		if bad.Gates[i].Gate == GatePublicWitnessing {
			bad.Gates[i].Status = GatePASS
			bad.Gates[i].Rationale = ""
		}
	}
	bad, err := NewProductionDecisionV3(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionDecisionBindingV4(d, bad); err == nil {
		t.Fatal("changed signed policy accepted")
	}
}

func TestDecisionV3RequiredSigners(t *testing.T) {
	d, x := decisionFixtureV3(t)
	want := []string{string(DecisionSignerCoordinator) + "\x00" + d.Coordinator.ID, string(DecisionSignerRelease) + "\x00" + d.ReleaseSigner.ID}
	slices.Sort(want)
	if !slices.Equal(requiredDecisionSignersV4(d, x), want) {
		t.Fatal("zero-audit threshold changed")
	}
	if _, err := decisionSignerIdentityV4(d, x, DecisionSignerAuditor, "injected"); err == nil {
		t.Fatal("disabled auditor authorized")
	}
	if _, err := decisionSignerIdentityV4(d, x, DecisionSignerCoordinator, d.ReleaseSigner.ID); err == nil {
		t.Fatal("wrong role authorized")
	}
	a := adversarialIdentity(t, "auditor", 3)
	d.Auditors = []Identity{a}
	x.Auditors = []DecisionAuditorV3{{AuditorID: a.ID, AuditorKeyID: a.KeyID}}
	if len(requiredDecisionSignersV4(d, x)) != 3 {
		t.Fatal("auditor consent omitted")
	}
	if got, err := decisionSignerIdentityV4(d, x, DecisionSignerAuditor, a.ID); err != nil || got != a {
		t.Fatalf("auditor: %v", err)
	}
}

func decisionDraftFixtureV3(x ProductionDecisionV3) ProductionDecisionDraftV3 {
	return ProductionDecisionDraftV3{Schema: ProductionDecisionDraftSchemaV5, CeremonyID: x.CeremonyID, AssurancePolicy: cloneAssurancePolicy(x.AssurancePolicy), Release: FinalReleaseEvidenceDraftV4{FinalReleaseCheckpoint: x.Release.FinalReleaseCheckpoint, CandidateID: x.Release.CandidateID}, SourceRelease: x.SourceRelease, Auditors: x.Auditors, ExternalAudits: x.ExternalAudits, K21Rehearsal: x.K21Rehearsal, CircuitRehearsal: x.CircuitRehearsal, MainnetDeploymentPlan: x.MainnetDeploymentPlan, FormalChecklist: x.FormalChecklist, Gates: x.Gates, Decision: x.Decision, DecidedAt: x.DecidedAt}
}

func TestDecisionV3DraftDerivesIDsAndRejectsImplicitUpgrade(t *testing.T) {
	_, x := decisionFixtureV3(t)
	draft := decisionDraftFixtureV3(x)
	raw, err := MarshalCanonical(draft)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"decision_id"`)) || bytes.Contains(raw, []byte(`"release_id"`)) {
		t.Fatal("draft included derived IDs")
	}
	var decoded ProductionDecisionDraftV3
	if err := UnmarshalCanonical(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	decision, err := decoded.decision()
	if err != nil {
		t.Fatal(err)
	}
	if decision.DecisionID != x.DecisionID || decision.Release.ReleaseID != x.Release.ReleaseID {
		t.Fatal("draft changed exact IDs")
	}
	for _, schema := range []string{"", ProductionDecisionDraftSchema, ProductionDecisionDraftSchemaV1} {
		bad := draft
		bad.Schema = schema
		if err := bad.Validate(); err == nil {
			t.Fatal("implicit/cross-version draft accepted")
		}
	}
	bad := append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"decision_id":"stale"}`)...)
	if err := UnmarshalCanonical(bad, &decoded); err == nil {
		t.Fatal("operator-chosen decision ID accepted")
	}
}
