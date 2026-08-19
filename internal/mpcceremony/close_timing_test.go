package mpcceremony

import (
	"strings"
	"testing"
	"time"
)

func TestValidateCloseCommitTimeBoundaries(t *testing.T) {
	t.Parallel()

	roundTime := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	const minimumLead uint32 = 300
	definition := CeremonyDefinition{
		Mode:         ModeRehearsal,
		BeaconPolicy: BeaconPolicy{MinimumWitnessLeadSeconds: minimumLead},
	}
	requiredLead := time.Duration(minimumLead)*time.Second + closePublicationSafetyMargin
	closedAt := roundTime.Add(-requiredLead - time.Second)

	if err := validateCloseCommitTime(
		closedAt,
		roundTime.Add(-requiredLead),
		roundTime,
		definition,
	); err != nil {
		t.Fatalf("exact publication boundary rejected: %v", err)
	}
	if err := validateCloseCommitTime(
		closedAt,
		roundTime.Add(-requiredLead+time.Nanosecond),
		roundTime,
		definition,
	); err == nil || !strings.Contains(err.Error(), "below required") {
		t.Fatalf("publication below boundary error = %v, want lead rejection", err)
	}
}

func TestValidateCloseCommitTimeRejectsClockRollbackAndZeroTimes(t *testing.T) {
	t.Parallel()

	roundTime := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	closedAt := roundTime.Add(-time.Hour)
	definition := CeremonyDefinition{
		Mode:         ModeRehearsal,
		BeaconPolicy: BeaconPolicy{MinimumWitnessLeadSeconds: 300},
	}
	if err := validateCloseCommitTime(
		closedAt,
		closedAt.Add(-time.Nanosecond),
		roundTime,
		definition,
	); err == nil || !strings.Contains(err.Error(), "moved backwards") {
		t.Fatalf("clock rollback error = %v, want rollback rejection", err)
	}
	if err := validateCloseCommitTime(
		time.Time{},
		closedAt,
		roundTime,
		definition,
	); err == nil || !strings.Contains(err.Error(), "zero time") {
		t.Fatalf("zero closed_at error = %v, want zero-time rejection", err)
	}
	if err := validateCloseCommitTime(
		closedAt,
		time.Time{},
		roundTime,
		definition,
	); err == nil || !strings.Contains(err.Error(), "zero time") {
		t.Fatalf("zero commit time error = %v, want zero-time rejection", err)
	}
}

func TestValidateCloseCommitTimeReservesProductionWitnessWindow(t *testing.T) {
	t.Parallel()

	roundTime := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	definition := CeremonyDefinition{
		Mode: ModeProduction,
		BeaconPolicy: BeaconPolicy{
			MinimumWitnessLeadSeconds: ProductionMinimumWitnessLeadSeconds,
		},
	}
	requiredLead := time.Duration(
		ProductionMinimumWitnessLeadSeconds+ProductionWitnessObservationWindowSeconds,
	)*time.Second + closePublicationSafetyMargin
	closedAt := roundTime.Add(-requiredLead - time.Second)

	if err := validateCloseCommitTime(
		closedAt,
		roundTime.Add(-requiredLead),
		roundTime,
		definition,
	); err != nil {
		t.Fatalf("production close reserving the witness window rejected: %v", err)
	}
	if err := validateCloseCommitTime(
		closedAt,
		roundTime.Add(-requiredLead+time.Second),
		roundTime,
		definition,
	); err == nil || !strings.Contains(err.Error(), "below required") {
		t.Fatalf("production close without the witness window error = %v, want lead rejection", err)
	}
}
