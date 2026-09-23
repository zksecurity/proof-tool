package mpcceremony

import (
	"bytes"
	"strings"
	"testing"
)

func trustedCoordinatorDefinition(t *testing.T) CeremonyDefinition {
	t.Helper()
	d := adversarialDefinition(t)
	d.Schema = DefinitionSchemaV5
	d.ReleaseVerification = CoordinatorReplayReleaseV1
	d, err := FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDefinitionV5ExplicitTrustPolicyAndDistinctIdentity(t *testing.T) {
	legacy := adversarialDefinition(t)
	if legacy.Schema != DefinitionSchemaV3 {
		t.Fatal("default changed before new workflow is complete")
	}
	d := legacy
	d.Schema = DefinitionSchemaV5
	d.ReleaseVerification = CoordinatorReplayReleaseV1
	d, err := FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	if d.CeremonyID == legacy.CeremonyID {
		t.Fatal("changed trust model reused ceremony identity")
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{DefinitionSchemaV1, DefinitionSchemaV2, DefinitionSchemaV3} {
		changed := d
		changed.Schema = schema
		if _, err := ComputeCeremonyID(changed); err == nil {
			t.Fatalf("%s accepted V5 policy", schema)
		}
	}
	for _, policy := range []string{"", "none", "coordinator-said-so", "signer-optional"} {
		changed := d
		changed.ReleaseVerification = policy
		if _, err := ComputeCeremonyID(changed); err == nil {
			t.Fatalf("policy %q accepted", policy)
		}
	}
	legacyBytes, err := MarshalCanonical(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacyBytes, []byte("release_verification")) {
		t.Fatal("legacy signed bytes gained new field")
	}
	var decoded CeremonyDefinition
	if err := UnmarshalCanonical(legacyBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`""`, `null`, `"coordinator-full-replay-v1"`} {
		raw := append(bytes.Clone(legacyBytes[:len(legacyBytes)-1]), []byte(",\"release_verification\":"+extra+"}")...)
		if err := UnmarshalCanonical(raw, &decoded); err == nil {
			t.Fatal("legacy format accepted a new-version field")
		}
	}
}

func TestDefinitionV5PreservesRequiredSignerAndExplicitAssurance(t *testing.T) {
	d := trustedCoordinatorDefinition(t)
	d.Auditors = []Identity{}
	d.AssurancePolicy = &AssurancePolicy{}
	d, err := FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	missing := d
	missing.AssurancePolicy = nil
	if _, err := ComputeCeremonyID(missing); err == nil {
		t.Fatal("missing assurance treated as zero")
	}
	missing = d
	missing.Auditors = nil
	if _, err := ComputeCeremonyID(missing); err == nil {
		t.Fatal("missing auditors treated as empty")
	}
	missing = d
	missing.ReleaseSigner = Identity{}
	if _, err := ComputeCeremonyID(missing); err == nil {
		t.Fatal("missing release signer accepted")
	}
	missing = d
	missing.ReleaseSigner = d.Coordinator
	if _, err := ComputeCeremonyID(missing); err == nil {
		t.Fatal("coordinator reused as release signer")
	}
	// The new declaration alone cannot take the old signer path.
	if err := verifyRequiredReleaseSignerReplay(d.Schema, SignReleaseOptions{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("V5 fell through into the legacy signing path: %v", err)
	}
	if err := validateCheckpointDefinitionVersion(d, Checkpoint{Schema: CheckpointSchemaV1}); err == nil {
		t.Fatal("V5 fell through to legacy checkpoints")
	}
	if err := validateProductionDecisionBinding(d, ProductionDecision{Schema: ProductionDecisionSchemaV1, CeremonyID: d.CeremonyID}); err == nil {
		t.Fatal("V5 fell through to legacy production decisions")
	}
	if expectedFinalTranscriptSchema(d) != FinalTranscriptSchemaV3 {
		t.Fatal("V5 selected a legacy transcript")
	}
}

func TestDefinitionConstructorExplicitReleaseVerification(t *testing.T) {
	d := adversarialDefinition(t)
	opts := DefinitionOptions{Mode: d.Mode, CreatedAt: d.CreatedAt, SessionNonceHex: d.SessionNonceHex,
		Circuit: d.Circuit, Software: d.Software, Coordinator: d.Coordinator, ReleaseSigner: d.ReleaseSigner,
		Auditors: d.Auditors, Roster: d.Roster, Phase1Policy: d.Phase1Policy, Phase2Policy: d.Phase2Policy,
		BeaconPolicy: d.BeaconPolicy, AssurancePolicy: d.AssurancePolicy, Phase1Genesis: d.Phase1Genesis}
	old, err := NewCeremonyDefinition(opts)
	if err != nil {
		t.Fatal(err)
	}
	want, err := MarshalCanonical(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalCanonical(old)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("default constructor changed released V3 bytes")
	}
	opts.ReleaseVerification = CoordinatorReplayReleaseV1
	current, err := NewCeremonyDefinition(opts)
	if err != nil {
		t.Fatal(err)
	}
	if current.Schema != DefinitionSchemaV5 || current.CeremonyID == old.CeremonyID {
		t.Fatal("explicit replay policy did not select distinct V5 ceremony")
	}
	for _, value := range []string{"none", " ", "coordinator-full-replay-v2"} {
		opts.ReleaseVerification = value
		if _, err := NewCeremonyDefinition(opts); err == nil {
			t.Fatalf("unknown release policy %q accepted", value)
		}
	}
}
