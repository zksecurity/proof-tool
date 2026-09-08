package mpcceremony

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectPhaseProjectsOnlyAuthenticatedWitnessWindow(t *testing.T) {
	f := newOperationalBundleFixture(t)
	for source, target := range map[string]string{
		f.bundle.Phase1.AcceptedChain.Record.Name:    "phase1/chain-0001.json",
		f.bundle.Phase1.AcceptedChain.Signature.Name: "phase1/chain-0001.sig",
		f.bundle.Phase1.Close.Record.Name:            "phase1/closure/record.json",
		f.bundle.Phase1.Close.Signature.Name:         "phase1/closure/record.sig",
	} {
		raw, err := os.ReadFile(filepath.Join(f.root, source))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.root, target)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	trusted := &TrustedCeremony{Definition: f.definition, CoordinatorPublicKey: f.coordinatorKey.Public().(ed25519.PublicKey)}
	opts := InspectCeremonyOptions{TranscriptRoot: f.root}
	p, _, err := inspectPhase(trusted, nil, opts, Phase1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Closed || p.CloseID == "" || p.ClosedAt == "" || p.BeaconRound == 0 {
		t.Fatal("closure identity omitted")
	}
	round, err := QuicknetRoundTime(p.BeaconRound)
	if err != nil {
		t.Fatal(err)
	}
	deadline := round.Add(-time.Duration(f.definition.BeaconPolicy.MinimumWitnessLeadSeconds) * time.Second)
	if p.BeaconScheduledAt != round.UTC().Format(time.RFC3339Nano) || p.WitnessObservationDeadline != deadline.UTC().Format(time.RFC3339Nano) {
		t.Fatal("incorrect signed observation window")
	}
	path := filepath.Join(f.root, "phase1/closure/record.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectPhase(trusted, nil, opts, Phase1, nil); err == nil {
		t.Fatal("tampered closure produced trusted timing")
	}
}
