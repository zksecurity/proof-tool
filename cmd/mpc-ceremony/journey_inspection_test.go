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
	if j.MinimumPublicWitnesses != 1 || j.MinimumMirrorsPerAcceptedHead != 1 || j.MinimumPassingCeremonyAudits != 1 || j.MinimumExternalAuditSignoffs != 1 || j.ObserverRequirementSource != "signed ceremony assurance_policy" {
		t.Fatal("operational verifier minimums omitted")
	}
	d.Auditors[0].DisplayName = "changed"
	if j.RequiredEnrollments[2].Identity.DisplayName == "changed" {
		t.Fatal("projection aliases mutable roster")
	}
}

func TestDefinitionJourneyProjectsDisabledControlsFromSignedPolicy(t *testing.T) {
	d, _, _ := decisionSignFixture(t)
	d.CeremonyID = ""
	d.Auditors = nil
	d.AssurancePolicy = &mpcceremony.AssurancePolicy{}
	d, err := mpcceremony.FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	j := inspectDefinitionJourney(d)
	if j.MinimumPublicWitnesses != 0 || j.MinimumMirrorsPerAcceptedHead != 0 || j.MinimumPassingCeremonyAudits != 0 || j.MinimumExternalAuditSignoffs != 0 {
		t.Fatalf("disabled policy projection = %#v", j)
	}
	if len(j.RequiredEnrollments) != 2+len(d.Roster) {
		t.Fatal("disabled auditor enrollment remained required")
	}
}
