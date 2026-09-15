package mpcceremony

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefinitionV1RemainsAValidSingletonBinaryPolicy(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.Schema = DefinitionSchemaV1
	definition.Software.Binaries = nil
	definition.AssurancePolicy = nil
	definition.CeremonyID = ""
	id, err := ComputeCeremonyID(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.CeremonyID = id
	if err := definition.Validate(); err != nil {
		t.Fatalf("legacy definition rejected: %v", err)
	}
	if got := definition.Software.AllowedBinaries(); len(got) != 1 || got[0] != definition.Software.primaryBinary() {
		t.Fatalf("legacy binary policy = %#v", got)
	}
}

func TestDefinitionV2RemainsValidWithLegacyAssuranceMinimums(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.Schema = DefinitionSchemaV2
	definition.AssurancePolicy = nil
	definition.CeremonyID = ""
	id, err := ComputeCeremonyID(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.CeremonyID = id
	if err := definition.Validate(); err != nil {
		t.Fatalf("legacy v2 definition rejected: %v", err)
	}

	definition.Auditors = nil
	definition.CeremonyID = ""
	if _, err := ComputeCeremonyID(definition); err == nil {
		t.Fatal("legacy v2 definition unexpectedly allowed zero ceremony auditors")
	}
}

func TestProductionDefinitionRequiresCanonicalDestinationCircuit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CircuitBinding)
	}{
		{
			name: "unvendored constraint count",
			mutate: func(binding *CircuitBinding) {
				binding.Constraints = 1791413
			},
		},
		{
			name: "different R1CS digest",
			mutate: func(binding *CircuitBinding) {
				binding.R1CS.Digest.SHA256 = "sha256:" + strings.Repeat("0", 64)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := adversarialDefinition(t)
			definition.CeremonyID = ""
			test.mutate(&definition.Circuit)
			if _, err := FinalizeCeremonyDefinition(definition); err == nil {
				t.Fatal("production definition with noncanonical destination circuit unexpectedly accepted")
			}
		})
	}
}

func TestProductionDefinitionRequiresMultipleParticipantsInBothPhases(t *testing.T) {
	valid := adversarialDefinition(t)

	oneParticipant := valid
	oneParticipant.CeremonyID = ""
	oneParticipant.Roster = append([]Participant(nil), valid.Roster[:1]...)
	oneParticipant.Phase1Policy = PhasePolicy{
		Participants: []string{valid.Roster[0].Identity.ID},
		Minimum:      1,
	}
	oneParticipant.Phase2Policy = oneParticipant.Phase1Policy
	if _, err := FinalizeCeremonyDefinition(oneParticipant); err == nil {
		t.Fatal("single-participant production ceremony unexpectedly accepted")
	}

	lowMinimum := valid
	lowMinimum.CeremonyID = ""
	lowMinimum.Phase1Policy = clonePhasePolicy(valid.Phase1Policy)
	lowMinimum.Phase1Policy.Minimum = 1
	if _, err := FinalizeCeremonyDefinition(lowMinimum); err == nil {
		t.Fatal("production phase1 minimum 1 unexpectedly accepted")
	}
	lowMinimum = valid
	lowMinimum.CeremonyID = ""
	lowMinimum.Phase2Policy = clonePhasePolicy(valid.Phase2Policy)
	lowMinimum.Phase2Policy.Minimum = 1
	if _, err := FinalizeCeremonyDefinition(lowMinimum); err == nil {
		t.Fatal("production phase2 minimum 1 unexpectedly accepted")
	}

	partialThreshold := valid
	partialThreshold.CeremonyID = ""
	partialThreshold.Phase1Policy = clonePhasePolicy(valid.Phase1Policy)
	partialThreshold.Phase1Policy.Minimum = uint8(len(partialThreshold.Phase1Policy.Participants) - 1)
	if _, err := FinalizeCeremonyDefinition(partialThreshold); err == nil {
		t.Fatal("production minimum below the complete scheduled roster unexpectedly accepted")
	}
}

func TestProductionDefinitionAcceptsSignedCustomBeaconLead(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	definition.BeaconPolicy.MinimumWitnessLeadSeconds = 12
	finalized, err := FinalizeCeremonyDefinition(definition)
	if err != nil {
		t.Fatalf("production definition with signed custom beacon lead rejected: %v", err)
	}
	if got := finalized.BeaconPolicy.MinimumWitnessLeadSeconds; got != 12 {
		t.Fatalf("production beacon lead = %d, want 12", got)
	}

	definition = finalized
	definition.CeremonyID = ""
	definition.BeaconPolicy.MinimumWitnessLeadSeconds = 0
	if _, err := FinalizeCeremonyDefinition(definition); err == nil {
		t.Fatal("production definition with zero beacon lead unexpectedly accepted")
	}
}

func TestRehearsalDefinitionMayUseOneParticipant(t *testing.T) {
	valid := adversarialDefinition(t)
	rehearsal := valid
	rehearsal.CeremonyID = ""
	rehearsal.Mode = ModeRehearsal
	assurance := *rehearsal.AssurancePolicy
	assurance.ExternalSecurityAuditSignoffs = 0
	rehearsal.AssurancePolicy = &assurance
	rehearsal.Roster = append([]Participant(nil), valid.Roster[:1]...)
	rehearsal.Phase1Policy = PhasePolicy{
		Participants: []string{valid.Roster[0].Identity.ID},
		Minimum:      1,
	}
	rehearsal.Phase2Policy = rehearsal.Phase1Policy
	if _, err := FinalizeCeremonyDefinition(rehearsal); err != nil {
		t.Fatalf("single-participant rehearsal rejected: %v", err)
	}
}

func TestDefinitionV3RequiresExplicitSignedAssurancePolicy(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	definition.AssurancePolicy = nil
	if _, err := ComputeCeremonyID(definition); err == nil || !strings.Contains(err.Error(), "requires assurance_policy") {
		t.Fatalf("missing assurance policy error = %v", err)
	}
}

func TestDefinitionV3AllowsEveryOperationalControlToBeDisabled(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	definition.Auditors = nil
	definition.AssurancePolicy = &AssurancePolicy{}
	if _, err := FinalizeCeremonyDefinition(definition); err != nil {
		t.Fatalf("all-optional production definition rejected: %v", err)
	}
}

func TestDefinitionV3CeremonyIDBindsAssurancePolicy(t *testing.T) {
	definition := adversarialDefinition(t)
	original := definition.CeremonyID
	definition.CeremonyID = ""
	policy := *definition.AssurancePolicy
	policy.MirrorsPerAcceptedHead = 0
	definition.AssurancePolicy = &policy
	changed, err := FinalizeCeremonyDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	if changed.CeremonyID == original {
		t.Fatal("changing the signed assurance policy did not change ceremony_id")
	}
}

func TestDefinitionV3AssurancePolicyIsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CeremonyDefinition)
	}{
		{
			name: "audit minimum exceeds roster",
			mutate: func(definition *CeremonyDefinition) {
				definition.AssurancePolicy.PassingCeremonyAudits = uint8(len(definition.Auditors) + 1)
			},
		},
		{
			name: "external audits enabled in rehearsal",
			mutate: func(definition *CeremonyDefinition) {
				definition.Mode = ModeRehearsal
				definition.AssurancePolicy.ExternalSecurityAuditSignoffs = 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := adversarialDefinition(t)
			definition.CeremonyID = ""
			test.mutate(&definition)
			if _, err := FinalizeCeremonyDefinition(definition); err == nil {
				t.Fatal("invalid assurance policy unexpectedly accepted")
			}
		})
	}
}

func TestInitPolicyDoesNotTreatOmissionAsZero(t *testing.T) {
	policy := InitPolicy{
		Phase1Policy: PhasePolicy{Participants: []string{"participant-01"}, Minimum: 1},
		Phase2Policy: PhasePolicy{Participants: []string{"participant-01"}, Minimum: 1},
		BeaconPolicy: adversarialDefinition(t).BeaconPolicy,
	}
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "assurance_policy is required") {
		t.Fatalf("omitted assurance policy error = %v", err)
	}
	policy.AssurancePolicy = &AssurancePolicy{}
	if err := policy.Validate(); err != nil {
		t.Fatalf("explicit zero assurance policy rejected structurally: %v", err)
	}
}

func TestLoadLegacyInitPolicyRestoresOldNonzeroDefaults(t *testing.T) {
	definition := adversarialDefinition(t)
	legacy := legacyInitPolicy{definition.Phase1Policy, definition.Phase2Policy, definition.BeaconPolicy}
	raw, err := MarshalCanonical(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadInitPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := loaded.ResolvedAssurancePolicy(ModeProduction)
	if err != nil {
		t.Fatal(err)
	}
	if policy.PublicWitnessesPerPhase == 0 || policy.MirrorsPerAcceptedHead == 0 ||
		policy.PassingCeremonyAudits == 0 || policy.ExternalSecurityAuditSignoffs == 0 {
		t.Fatalf("legacy policy weakened to zero: %#v", policy)
	}
}

func TestCurrentDefinitionRequiresExplicitEmptyAuditorArray(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.AssurancePolicy.PassingCeremonyAudits = 0
	definition.Auditors = nil
	definition.CeremonyID = ""
	if _, err := ComputeCeremonyID(definition); err == nil || !strings.Contains(err.Error(), "explicit auditors array") {
		t.Fatalf("nil auditors error = %v", err)
	}
	definition.Auditors = []Identity{}
	if _, err := ComputeCeremonyID(definition); err != nil {
		t.Fatalf("explicit empty auditors rejected: %v", err)
	}
}

func TestDefinitionRequiresUniquePublicKeysAcrossAllRoles(t *testing.T) {
	reusePublicKey := func(destination *Identity, source Identity) {
		destination.Ed25519PublicKeyHex = source.Ed25519PublicKeyHex
		destination.PublicKeyFingerprint = source.PublicKeyFingerprint
	}

	tests := []struct {
		name   string
		mutate func(*CeremonyDefinition)
	}{
		{
			name: "release signer and coordinator",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.ReleaseSigner, definition.Coordinator)
			},
		},
		{
			name: "auditor and coordinator",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Auditors[0], definition.Coordinator)
			},
		},
		{
			name: "two auditors",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Auditors[1], definition.Auditors[0])
			},
		},
		{
			name: "participant and coordinator",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Roster[0].Identity, definition.Coordinator)
			},
		},
		{
			name: "participant and release signer",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Roster[0].Identity, definition.ReleaseSigner)
			},
		},
		{
			name: "participant and auditor",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Roster[0].Identity, definition.Auditors[0])
			},
		},
		{
			name: "two participants",
			mutate: func(definition *CeremonyDefinition) {
				reusePublicKey(&definition.Roster[1].Identity, definition.Roster[0].Identity)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := adversarialDefinition(t)
			definition.CeremonyID = ""
			test.mutate(&definition)
			if _, err := FinalizeCeremonyDefinition(definition); err == nil {
				t.Fatal("definition with reused Ed25519 public key unexpectedly accepted")
			}
		})
	}
}
