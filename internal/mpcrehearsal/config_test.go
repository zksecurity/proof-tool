// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcrehearsal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestGenerateUsesShortAutomatedBeaconLead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rehearsal")
	if err := Generate(root, minRehearsalParticipants, MinimumBeaconLeadSeconds); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "config", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Beacon struct {
			Lead uint32 `json:"minimum_witness_lead_seconds"`
		} `json:"beacon_policy"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Beacon.Lead != MinimumBeaconLeadSeconds {
		t.Fatalf("beacon lead = %d, want %d", policy.Beacon.Lead, MinimumBeaconLeadSeconds)
	}
}

func TestGenerateCanExerciseExplicitlyDisabledOptionalAssurance(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rehearsal")
	if err := GenerateWithAssurance(root, minRehearsalParticipants, MinimumBeaconLeadSeconds, false); err != nil {
		t.Fatal(err)
	}
	participants, err := mpcceremony.LoadInitParticipants(filepath.Join(root, "config", "participants.json"))
	if err != nil {
		t.Fatal(err)
	}
	if participants.Auditors == nil || len(participants.Auditors) != 0 {
		t.Fatalf("disabled audit roster = %#v, want explicit empty array", participants.Auditors)
	}
	policy, err := mpcceremony.LoadInitPolicy(filepath.Join(root, "config", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if policy.AssurancePolicy == nil || *policy.AssurancePolicy != (mpcceremony.AssurancePolicy{}) {
		t.Fatalf("assurance policy = %#v, want explicit zeroes", policy.AssurancePolicy)
	}
	for _, id := range []string{"auditor-01", "witness-01", "mirror-01"} {
		if _, err := os.Lstat(filepath.Join(root, "keys", id+".ed25519.private.hex")); !os.IsNotExist(err) {
			t.Fatalf("disabled role key %q exists or cannot be inspected: %v", id, err)
		}
	}
}

func TestGenerateRejectsShorterBeaconLead(t *testing.T) {
	err := Generate(filepath.Join(t.TempDir(), "rehearsal"), minRehearsalParticipants, MinimumBeaconLeadSeconds-1)
	if err == nil {
		t.Fatal("short beacon lead was accepted")
	}
}
