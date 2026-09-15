package main

import (
	"testing"
	"time"

	"proof-tool/internal/mpcceremony"
)

func TestLegacyDefinitionUsesOldNonzeroObserverDefaults(t *testing.T) {
	definition := mpcceremony.CeremonyDefinition{Schema: mpcceremony.DefinitionSchemaV2}
	policy := rehearsalAssurance(definition)
	if policy.PublicWitnessesPerPhase != 2 || policy.MirrorsPerAcceptedHead != 2 || policy.PassingCeremonyAudits != 1 {
		t.Fatalf("legacy rehearsal policy = %#v", policy)
	}
	if cloneRehearsalAssurance(definition) != nil {
		t.Fatal("legacy bundle unexpectedly gained a v3 assurance field")
	}
}

func TestTwoInteriorTimestampsSupportsSubsecondAuthenticatedGap(t *testing.T) {
	lower := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	upper := lower.Add(100 * time.Millisecond)
	firstText, secondText, err := twoInteriorTimestamps(lower, upper)
	if err != nil {
		t.Fatal(err)
	}
	first, err := time.Parse(time.RFC3339Nano, firstText)
	if err != nil {
		t.Fatal(err)
	}
	second, err := time.Parse(time.RFC3339Nano, secondText)
	if err != nil {
		t.Fatal(err)
	}
	if !first.After(lower) || !second.After(first) || !upper.After(second) {
		t.Fatalf("timestamps are not strictly interior: %s, %s", firstText, secondText)
	}
}

func TestTwoInteriorTimestampsRejectsUnrepresentableGap(t *testing.T) {
	lower := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	if _, _, err := twoInteriorTimestamps(lower, lower.Add(2*time.Nanosecond)); err == nil {
		t.Fatal("two-nanosecond interval unexpectedly represented two strict interior instants")
	}
}
