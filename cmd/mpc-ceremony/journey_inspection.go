// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import "proof-tool/internal/mpcceremony"

type ExpectedEnrollmentInspection struct {
	Role      mpcceremony.EnrollmentRole `json:"role"`
	RoleIndex int                        `json:"role_index"`
	Identity  mpcceremony.Identity       `json:"identity"`
}

type DefinitionJourneyInspection struct {
	Schema                        string                         `json:"schema"`
	RequiredEnrollments           []ExpectedEnrollmentInspection `json:"required_enrollments"`
	MinimumPublicWitnesses        int                            `json:"minimum_public_witnesses"`
	MinimumMirrorsPerAcceptedHead int                            `json:"minimum_mirrors_per_accepted_head"`
	ObserverRequirementSource     string                         `json:"observer_requirement_source"`
}

type PhaseJourneyInspection struct {
	Phase                      string   `json:"phase"`
	Started                    bool     `json:"started"`
	AcceptedCount              int      `json:"accepted_count"`
	ScheduledTotal             int      `json:"scheduled_total"`
	HeadRecordID               string   `json:"head_record_id"`
	NextParticipantID          string   `json:"next_participant_id,omitempty"`
	Closed                     bool     `json:"closed"`
	CloseID                    string   `json:"close_id,omitempty"`
	ClosedAt                   string   `json:"closed_at,omitempty"`
	BeaconRound                uint64   `json:"beacon_round,omitempty"`
	BeaconScheduledAt          string   `json:"beacon_scheduled_at,omitempty"`
	WitnessObservationDeadline string   `json:"witness_observation_deadline,omitempty"`
	MissingArtifacts           []string `json:"missing_artifacts"`
}

type JourneyInspection struct {
	Schema     string                   `json:"schema"`
	CeremonyID string                   `json:"ceremony_id"`
	Mode       string                   `json:"mode"`
	Depth      string                   `json:"depth"`
	Phases     []PhaseJourneyInspection `json:"phases"`
}

func inspectDefinitionJourney(d mpcceremony.CeremonyDefinition) *DefinitionJourneyInspection {
	r := &DefinitionJourneyInspection{Schema: "proof-tool-mpc-definition-journey-v1", MinimumPublicWitnesses: 2, MinimumMirrorsPerAcceptedHead: 2, ObserverRequirementSource: "operational-bundle verifier minimum; an agreed witness quorum can require more"}
	r.RequiredEnrollments = append(r.RequiredEnrollments, ExpectedEnrollmentInspection{mpcceremony.EnrollmentCoordinator, 1, d.Coordinator}, ExpectedEnrollmentInspection{mpcceremony.EnrollmentReleaseSigner, 1, d.ReleaseSigner})
	for n, id := range d.Auditors {
		r.RequiredEnrollments = append(r.RequiredEnrollments, ExpectedEnrollmentInspection{mpcceremony.EnrollmentAuditor, n + 1, id})
	}
	for n, p := range d.Roster {
		r.RequiredEnrollments = append(r.RequiredEnrollments, ExpectedEnrollmentInspection{mpcceremony.EnrollmentParticipant, n + 1, p.Identity})
	}
	return r
}

func inspectJourney(result mpcceremony.InspectResult) *JourneyInspection {
	r := &JourneyInspection{Schema: "proof-tool-mpc-journey-inspection-v1", CeremonyID: result.CeremonyID, Mode: result.Mode, Depth: result.Depth}
	for _, p := range result.Phases {
		r.Phases = append(r.Phases, PhaseJourneyInspection{Phase: string(p.Phase), Started: p.Started, AcceptedCount: p.AcceptedCount, ScheduledTotal: p.ScheduledTotal, HeadRecordID: p.HeadRecordID, NextParticipantID: p.NextParticipantID, Closed: p.Closed, CloseID: p.CloseID, ClosedAt: p.ClosedAt, BeaconRound: p.BeaconRound, BeaconScheduledAt: p.BeaconScheduledAt, WitnessObservationDeadline: p.WitnessObservationDeadline, MissingArtifacts: append([]string(nil), p.MissingArtifacts...)})
	}
	return r
}
