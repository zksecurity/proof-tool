// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcrehearsal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

func TestGenerateRejectsShorterBeaconLead(t *testing.T) {
	err := Generate(filepath.Join(t.TempDir(), "rehearsal"), minRehearsalParticipants, MinimumBeaconLeadSeconds-1)
	if err == nil {
		t.Fatal("short beacon lead was accepted")
	}
}
