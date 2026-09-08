package main

import (
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestDefinitionJourneyProjectsEveryRequiredEnrollment(t *testing.T) {
	d, _, _ := decisionSignFixture(t)
	j := inspectDefinitionJourney(d)
	if len(j.RequiredEnrollments) != 2+len(d.Auditors)+len(d.Roster) {
		t.Fatal("omitted required identity")
	}
	if j.RequiredEnrollments[0].Identity != d.Coordinator || j.RequiredEnrollments[1].Identity != d.ReleaseSigner {
		t.Fatal("incorrect coordinator or signer")
	}
	for n, id := range d.Auditors {
		v := j.RequiredEnrollments[2+n]
		if v.Identity != id || v.Role != mpcceremony.EnrollmentAuditor || v.RoleIndex != n+1 {
			t.Fatal("incorrect auditor assignment")
		}
	}
	for n, p := range d.Roster {
		v := j.RequiredEnrollments[2+len(d.Auditors)+n]
		if v.Identity != p.Identity || v.Role != mpcceremony.EnrollmentParticipant || v.RoleIndex != n+1 {
			t.Fatal("incorrect participant assignment")
		}
	}
	if j.MinimumPublicWitnesses != 2 || j.MinimumMirrorsPerAcceptedHead != 2 || j.ObserverRequirementSource == "" {
		t.Fatal("operational verifier minimums omitted")
	}
	d.Auditors[0].DisplayName = "changed"
	if j.RequiredEnrollments[2].Identity.DisplayName == "changed" {
		t.Fatal("projection aliases mutable roster")
	}
}
