package mpcceremony

import (
	"testing"
	"time"
)

func TestFirstQuicknetRoundAfterIsStrictlyAfter(t *testing.T) {
	for _, round := range []uint64{1, 2, 1000, 31345533} {
		scheduled, err := QuicknetRoundTime(round)
		if err != nil {
			t.Fatal(err)
		}
		// Landing exactly on a round schedule must advance past it, because the
		// close requires the round to be strictly in the future.
		next, err := FirstQuicknetRoundAfter(scheduled)
		if err != nil {
			t.Fatal(err)
		}
		if next != round+1 {
			t.Fatalf("round %d schedule derived %d, want %d", round, next, round+1)
		}
		nextTime, err := QuicknetRoundTime(next)
		if err != nil {
			t.Fatal(err)
		}
		if !nextTime.After(scheduled) {
			t.Fatalf("derived round %d is not after %s", next, scheduled)
		}
	}
}

func TestFirstQuicknetRoundAfterMidPeriod(t *testing.T) {
	base, err := QuicknetRoundTime(1000)
	if err != nil {
		t.Fatal(err)
	}
	// One second into a three-second period still resolves to the next round.
	next, err := FirstQuicknetRoundAfter(base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next != 1001 {
		t.Fatalf("mid-period derived %d, want 1001", next)
	}
}

func TestFirstQuicknetRoundAfterBeforeGenesis(t *testing.T) {
	round, err := FirstQuicknetRoundAfter(time.Unix(BeaconQuicknetGenesis-3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	if round != 1 {
		t.Fatalf("pre-genesis derived %d, want 1", round)
	}
}

// TestDerivedRoundClearsTheSignedLead is the property the fix exists for: a
// round derived from the post-replay clock must satisfy the same lead check
// that rejects a round an operator named before a multi-hour replay.
func TestDerivedRoundClearsTheSignedLead(t *testing.T) {
	const leadSeconds = 600
	closedAt := time.Unix(BeaconQuicknetGenesis+1_000_000, 0).UTC()
	lead := leadSeconds * time.Second

	round, err := FirstQuicknetRoundAfter(closedAt.Add(lead + closePublicationSafetyMargin))
	if err != nil {
		t.Fatal(err)
	}
	roundTime, err := QuicknetRoundTime(round)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCloseCommitTime(closedAt, closedAt, roundTime, leadSeconds); err != nil {
		t.Fatalf("derived round rejected by the publication guard: %v", err)
	}
	if roundTime.Sub(closedAt) < lead {
		t.Fatalf("derived lead %s is below the signed minimum %s", roundTime.Sub(closedAt), lead)
	}
}

// TestExplicitRoundStaleAfterLongReplayIsRejected reproduces the failure the
// derivation avoids: a round chosen before an hours-long replay is already in
// the past when the closure is published.
func TestExplicitRoundStaleAfterLongReplayIsRejected(t *testing.T) {
	const leadSeconds = 600
	chosenAt := time.Unix(BeaconQuicknetGenesis+1_000_000, 0).UTC()

	// The operator picks a round just past the signed lead, as the only written
	// rule suggests.
	round, err := FirstQuicknetRoundAfter(chosenAt.Add(leadSeconds * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	roundTime, err := QuicknetRoundTime(round)
	if err != nil {
		t.Fatal(err)
	}

	// The replay then takes an hour and forty minutes.
	closedAt := chosenAt.Add(100 * time.Minute)
	if err := validateCloseCommitTime(closedAt, closedAt, roundTime, leadSeconds); err == nil {
		t.Fatal("stale round was accepted after a long replay")
	}

	// Deriving from the post-replay clock instead succeeds on the same timeline.
	derived, err := FirstQuicknetRoundAfter(
		closedAt.Add(leadSeconds*time.Second + closePublicationSafetyMargin),
	)
	if err != nil {
		t.Fatal(err)
	}
	derivedTime, err := QuicknetRoundTime(derived)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCloseCommitTime(closedAt, closedAt, derivedTime, leadSeconds); err != nil {
		t.Fatalf("derived round rejected: %v", err)
	}
}
