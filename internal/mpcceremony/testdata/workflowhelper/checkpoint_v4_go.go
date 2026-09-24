package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	m "proof-tool/internal/mpcceremony"
)

// This fixture completes the real signed package and decision APIs in the
// same clean, pinned executable. PASS reports are local test bytes, not claims
// that any independent review or production control actually occurred.
func runProductionGOFixture(root string, trust m.TrustPaths, d m.CeremonyDefinition, head m.SignedArtifactRefs, verifiedRelease *m.VerifyReleaseResult) error {
	if verifiedRelease == nil {
		return fmt.Errorf("missing verified release")
	}
	release, err := m.NewFinalReleaseEvidenceV4(d.CeremonyID, head, verifiedRelease.Candidate.CandidateID)
	if err != nil {
		return err
	}
	makeEvidence := func(name string) (m.ArtifactRef, error) {
		name = "decision/evidence/" + name
		payload := []byte("Single-process fixture evidence; no independent review or production assurance.\n")
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return m.ArtifactRef{}, err
		}
		if err := os.WriteFile(path, payload, 0600); err != nil {
			return m.ArtifactRef{}, err
		}
		return m.ArtifactRef{Name: name, Digest: m.NewDigest(payload)}, nil
	}
	source, err := makeEvidence("source-release.json")
	if err != nil {
		return err
	}
	circuit, err := makeEvidence("circuit.json")
	if err != nil {
		return err
	}
	plan, err := makeEvidence("deployment.md")
	if err != nil {
		return err
	}
	checklist, err := makeEvidence("checklist.md")
	if err != nil {
		return err
	}
	decision := m.ProductionDecisionV3{Schema: m.ProductionDecisionSchemaV5, CeremonyID: d.CeremonyID, AssurancePolicy: d.AssurancePolicy, Release: release, SourceRelease: m.SourceReleaseEvidenceV4{SourceCommit: d.Software.SourceCommit, VerificationReport: source}, Auditors: []m.DecisionAuditorV3{}, ExternalAudits: []m.ExternalAuditEvidenceV3{}, CircuitRehearsal: &m.CircuitRehearsalEvidenceV5{Circuit: d.Circuit, Evidence: circuit}, MainnetDeploymentPlan: plan, FormalChecklist: checklist, Decision: m.DecisionGO, DecidedAt: "2026-07-24T12:00:00Z"}
	for _, gate := range []m.ProductionGate{m.GateSourceRelease, m.GateSignedRelease, m.GateOperationalEvidence, m.GateIndependentAudits, m.GateExternalAudit, m.GateExactCircuitRehearsal, m.GateMainnetDeploymentPlan, m.GateFormalChecklist, m.GateParticipantHost, m.GateParticipantEntropy, m.GateParticipantErasure, m.GatePublicWitnessing, m.GateImmutableMirrors} {
		result := m.ProductionGateResultV3{Gate: gate, Status: m.GatePASS, Evidence: []m.ArtifactRef{}}
		switch gate {
		case m.GateIndependentAudits, m.GateExternalAudit, m.GatePublicWitnessing, m.GateImmutableMirrors:
			result.Status, result.Rationale = m.GateNotRequired, "Disabled in signed fixture policy"
		case m.GateSourceRelease:
			result.Evidence = []m.ArtifactRef{source}
		case m.GateExactCircuitRehearsal:
			result.Evidence = []m.ArtifactRef{circuit}
		case m.GateMainnetDeploymentPlan:
			result.Evidence = []m.ArtifactRef{plan}
		case m.GateFormalChecklist:
			result.Evidence = []m.ArtifactRef{checklist}
		case m.GateSignedRelease, m.GateOperationalEvidence:
		default:
			ref, err := makeEvidence(string(gate) + ".txt")
			if err != nil {
				return err
			}
			result.Evidence = []m.ArtifactRef{ref}
		}
		decision.Gates = append(decision.Gates, result)
	}
	decision, err = m.NewProductionDecisionV3(decision)
	if err != nil {
		return err
	}
	raw, err := m.MarshalCanonical(decision)
	if err != nil {
		return err
	}
	opts := m.VerifyProductionDecisionEvidenceV4Options{Trust: trust, ArtifactRoot: root, DecisionBytes: raw}
	if _, err := m.VerifyProductionDecisionEvidenceV4(opts); err != nil {
		return fmt.Errorf("full GO evidence: %w", err)
	}
	coordinatorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x81}, ed25519.SeedSize))
	releaseKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x82}, ed25519.SeedSize))
	coordinatorSig, err := m.SignProductionDecisionV4(opts, m.DecisionSignerCoordinator, d.Coordinator.ID, coordinatorKey)
	if err != nil {
		return err
	}
	releaseSig, err := m.SignProductionDecisionV4(opts, m.DecisionSignerRelease, d.ReleaseSigner.ID, releaseKey)
	if err != nil {
		return err
	}
	verified, err := m.VerifyProductionDecisionV4(m.VerifyProductionDecisionV4Options{VerifyProductionDecisionEvidenceV4Options: opts, SignatureBytes: [][]byte{coordinatorSig, releaseSig}})
	if err != nil {
		return err
	}
	if verified.Decision.Decision != m.DecisionGO || len(verified.VerifiedSigners) != 2 {
		return fmt.Errorf("signed GO did not retain exact signer threshold")
	}
	fmt.Println("V5 complete production-mode GO passed: signed package, evidence, coordinator and release signatures, exact circuit")
	return nil
}
