package mpcceremony

import (
	"strings"
	"testing"
)

func TestRemovedWipeFieldsAreRejected(t *testing.T) {
	definition := adversarialDefinition(t)
	raw, err := MarshalCanonical(definition)
	if err != nil {
		t.Fatal(err)
	}
	withWipe := strings.Replace(string(raw), "{", `{"host_wipe_participants":[],`, 1)
	var parsed CeremonyDefinition
	if err := UnmarshalCanonical([]byte(withWipe), &parsed); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("removed policy accepted: %v", err)
	}
	var bundle OperationalEvidenceBundle
	if err := UnmarshalCanonical([]byte(`{"host_wipes":[]}`), &bundle); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("removed evidence field accepted: %v", err)
	}
}

func TestOldBroadCleanupClaimsAreRejected(t *testing.T) {
	var environment ContributionEnvironment
	if err := UnmarshalCanonical([]byte(`{"swap_disabled":true}`), &environment); err == nil {
		t.Fatal("unscoped swap assertion accepted")
	}
	var cleanup ErasureAttestation
	for _, raw := range []string{`{"no_backup_retained":true}`, `{"ephemeral_storage_destroyed":true}`} {
		if err := UnmarshalCanonical([]byte(raw), &cleanup); err == nil {
			t.Fatal("old broad cleanup assertion accepted")
		}
	}
	contribution := adversarialAttestation(t)
	contribution.Schema = "proof-tool-mpc-contribution-attestation-v1"
	if err := contribution.Validate(); err == nil {
		t.Fatal("old contribution schema accepted")
	}
}
