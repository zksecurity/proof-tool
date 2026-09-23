package main

import "testing"

func TestProductionInitAcceptsReviewedCircuitChoices(t *testing.T) {
	for _, keyVersion := range []string{"ownership-destination-v3", "rehearsal-tiny-v1", "rehearsal-k11-v1"} {
		args := []string{"--mode", "production", "--key-version", keyVersion,
			"--created-at", "2026-09-23T00:00:00Z", "--participants", "participants.json",
			"--policy", "policy.json", "--coordinator-key-id", "coordinator",
			"--coordinator-signing-key", "coordinator.key", "--out-dir", "ceremony"}
		options, err := parseInit(args)
		if err != nil {
			t.Fatalf("%s: %v", keyVersion, err)
		}
		if options.Mode != "production" || options.KeyVersion != keyVersion {
			t.Fatalf("wrong selection for %s: %+v", keyVersion, options)
		}
	}
}
