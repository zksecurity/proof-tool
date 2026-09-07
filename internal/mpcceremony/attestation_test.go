package mpcceremony

import (
	"testing"
)

func TestErasureAttestationBindsCompletedPostContributionDestruction(t *testing.T) {
	contribution := adversarialAttestation(t)
	erasure, err := NewErasureAttestation(ErasureAttestation{
		CeremonyID:                  contribution.CeremonyID,
		Phase:                       contribution.Phase,
		PhaseID:                     contribution.PhaseID,
		Index:                       contribution.Index,
		ParticipantID:               contribution.ParticipantID,
		ParticipantKeyID:            contribution.ParticipantKeyID,
		ContributionAttestationID:   contribution.AttestationID,
		OutputPayload:               contribution.OutputPayload,
		DestroyedAt:                 "2026-07-23T12:00:01Z",
		ProcessTerminated:           true,
		EphemeralEnvironmentRemoved: true,
		NoDeliberateCopiesConfirmed: true,
		HostRemnantsNotExcluded:     true,
	})
	if err != nil {
		t.Fatalf("new erasure attestation: %v", err)
	}
	if err := ValidateErasureForContribution(contribution, erasure); err != nil {
		t.Fatalf("valid erasure rejected: %v", err)
	}

	notAfter := erasure
	notAfter.DestroyedAt = contribution.ContributedAt
	notAfter, err = NewErasureAttestation(notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateErasureForContribution(contribution, notAfter); err == nil {
		t.Fatal("erasure at contribution time unexpectedly accepted")
	}

	wrongOutput := erasure
	wrongOutput.OutputPayload = ArtifactRef{
		Name:   "phase1/another-output.bin",
		Digest: NewDigest([]byte("another output")),
	}
	wrongOutput, err = NewErasureAttestation(wrongOutput)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateErasureForContribution(contribution, wrongOutput); err == nil {
		t.Fatal("erasure for another output unexpectedly accepted")
	}
}

func TestErasureAttestationRequiresAllNarrowClaims(t *testing.T) {
	contribution := adversarialAttestation(t)
	base := ErasureAttestation{
		CeremonyID:                  contribution.CeremonyID,
		Phase:                       contribution.Phase,
		PhaseID:                     contribution.PhaseID,
		Index:                       contribution.Index,
		ParticipantID:               contribution.ParticipantID,
		ParticipantKeyID:            contribution.ParticipantKeyID,
		ContributionAttestationID:   contribution.AttestationID,
		OutputPayload:               contribution.OutputPayload,
		DestroyedAt:                 "2026-07-23T12:01:00Z",
		ProcessTerminated:           true,
		EphemeralEnvironmentRemoved: true,
		NoDeliberateCopiesConfirmed: true,
		HostRemnantsNotExcluded:     true,
	}
	cases := []struct {
		name   string
		mutate func(*ErasureAttestation)
	}{
		{"process", func(a *ErasureAttestation) { a.ProcessTerminated = false }},
		{"storage", func(a *ErasureAttestation) { a.EphemeralEnvironmentRemoved = false }},
		{"backup", func(a *ErasureAttestation) { a.NoDeliberateCopiesConfirmed = false }},
		{"unassessed host remnants", func(a *ErasureAttestation) { a.HostRemnantsNotExcluded = false }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if _, err := NewErasureAttestation(candidate); err == nil {
				t.Fatal("incomplete erasure claim unexpectedly accepted")
			}
		})
	}
}

func TestCleanupEnvironmentAcknowledgesHostRisk(t *testing.T) {
	e := adversarialAttestation(t).Environment
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.HostRemnantsNotExcluded = false
	if err := e.Validate(); err == nil {
		t.Fatal("environment that omits host-remnant acknowledgement accepted")
	}
}
