package mpcceremony

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testDecisionSignatureV3(t *testing.T, raw []byte, identity Identity, role DecisionSignerRole, seed byte) []byte {
	t.Helper()
	sig, err := SignExact(raw, identity.KeyID, adversarialPrivateKey(seed))
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalCanonical(ProductionDecisionSignature{Schema: ProductionDecisionSignatureSchema, Role: role, SignerID: identity.ID, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecisionV3SignatureThresholdAndExactBytes(t *testing.T) {
	d, x := decisionFixtureV3(t)
	raw, _ := MarshalCanonical(x)
	coord := testDecisionSignatureV3(t, raw, d.Coordinator, DecisionSignerCoordinator, 1)
	release := testDecisionSignatureV3(t, raw, d.ReleaseSigner, DecisionSignerRelease, 2)
	if got, err := verifyDecisionSignaturesV4(d, x, raw, [][]byte{coord, release}); err != nil || len(got) != 2 {
		t.Fatalf("threshold: %v", err)
	}
	for _, sigs := range [][][]byte{nil, {coord}, {release}, {coord, release, coord}} {
		if _, err := verifyDecisionSignaturesV4(d, x, raw, sigs); err == nil {
			t.Fatal("incomplete/duplicate threshold accepted")
		}
	}
	changed := bytes.Clone(raw)
	changed[len(changed)-2] ^= 1
	if _, err := verifyDecisionSignaturesV4(d, x, changed, [][]byte{coord, release}); err == nil {
		t.Fatal("signature reused on changed decision")
	}
	other := adversarialIdentity(t, "outsider", 5)
	extra := testDecisionSignatureV3(t, raw, other, DecisionSignerAuditor, 5)
	if _, err := verifyDecisionSignaturesV4(d, x, raw, [][]byte{coord, release, extra}); err == nil {
		t.Fatal("extra signer accepted")
	}
	a := adversarialIdentity(t, "auditor", 3)
	d.Auditors = []Identity{a}
	x.Auditors = []DecisionAuditorV3{{AuditorID: a.ID, AuditorKeyID: a.KeyID}}
	// Threshold-only test: the full API additionally validates signed policy and
	// re-derives this auditor list from the cryptographically verified package.
	if _, err := verifyDecisionSignaturesV4(d, x, raw, [][]byte{coord, release}); err == nil {
		t.Fatal("missing auditor consent accepted")
	}
	audit := testDecisionSignatureV3(t, raw, a, DecisionSignerAuditor, 3)
	if got, err := verifyDecisionSignaturesV4(d, x, raw, [][]byte{coord, release, audit}); err != nil || len(got) != 3 {
		t.Fatalf("auditor threshold: %v", err)
	}
}

func TestDecisionV3PackageGatesAndExternalBindings(t *testing.T) {
	_, base := decisionFixtureV3(t)
	clone := func() ProductionDecisionV3 {
		raw, _ := json.Marshal(base)
		var x ProductionDecisionV3
		_ = json.Unmarshal(raw, &x)
		return x
	}
	for _, gate := range []ProductionGate{GateSignedRelease, GateOperationalEvidence} {
		for _, status := range []ProductionGateStatus{GateFAIL, GatePENDING} {
			x := clone()
			x.Decision = DecisionNOGO
			for i := range x.Gates {
				if x.Gates[i].Gate == gate {
					x.Gates[i].Status = status
					x.Gates[i].Rationale = "Contradictory fixture"
				}
			}
			if _, err := NewProductionDecisionV3(x); err == nil {
				t.Fatal("contradictory package gate accepted")
			}
		}
	}
	for _, gate := range []ProductionGate{GateSourceRelease, GateK21Rehearsal, GateMainnetDeploymentPlan, GateFormalChecklist} {
		x := clone()
		for i := range x.Gates {
			if x.Gates[i].Gate == gate {
				x.Gates[i].Evidence = []ArtifactRef{checkpointArtifact("decision/evidence/unrelated.txt", "x")}
			}
		}
		if _, err := NewProductionDecisionV3(x); err == nil {
			t.Fatal("gate used unrelated structured evidence")
		}
	}
	x := clone()
	x.Decision = DecisionNOGO
	for i := range x.Gates {
		if x.Gates[i].Gate == GateParticipantHost {
			x.Gates[i].Status = GatePENDING
			x.Gates[i].Rationale = "Host review incomplete"
		}
	}
	if _, err := NewProductionDecisionV3(x); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionV3PackageCandidateAndTimeBinding(t *testing.T) {
	d, x := decisionFixtureV3(t)
	db, _ := MarshalCanonical(d)
	ref := ArtifactRef{Name: "ceremony.json", Digest: NewDigest(db)}
	release := &VerifyReleaseResult{Candidate: CandidateMetadata{CandidateID: x.Release.CandidateID, CeremonyID: d.CeremonyID, Definition: ref}, Transcript: FinalTranscript{FinalizedAt: x.DecidedAt, CeremonyID: d.CeremonyID, Definition: ref}}
	if err := validateDecisionPackageBindingV4(d, x, release); err != nil {
		t.Fatal(err)
	}
	x.DecidedAt = "2026-07-23T12:00:00Z"
	if err := validateDecisionPackageBindingV4(d, x, release); err == nil {
		t.Fatal("decision predates release")
	}
	x.DecidedAt = "2026-07-25T12:00:00Z"
	if err := validateDecisionPackageBindingV4(d, x, release); err != nil {
		t.Fatal(err)
	}
	release.Candidate.CandidateID = NewDigest([]byte("other candidate")).SHA256
	if err := validateDecisionPackageBindingV4(d, x, release); err == nil {
		t.Fatal("wrong candidate accepted")
	}
	if err := validateDecisionPackageBindingV4(d, x, nil); err == nil {
		t.Fatal("nil verified release accepted")
	}
	release.Candidate.CandidateID = x.Release.CandidateID
	for _, change := range []func(*VerifyReleaseResult){
		func(r *VerifyReleaseResult) { r.Candidate.CeremonyID = NewDigest([]byte("other ceremony")).SHA256 },
		func(r *VerifyReleaseResult) { r.Candidate.Definition.Digest = NewDigest([]byte("other definition")) },
		func(r *VerifyReleaseResult) { r.Transcript.CeremonyID = NewDigest([]byte("other ceremony")).SHA256 },
		func(r *VerifyReleaseResult) { r.Transcript.Definition.Name = "another-definition.json" },
	} {
		bad := *release
		change(&bad)
		if err := validateDecisionPackageBindingV4(d, x, &bad); err == nil {
			t.Fatal("mixed ceremony/package accepted")
		}
	}
}

func TestDecisionV3RejectsRehearsalAndAbsentPackage(t *testing.T) {
	d, x := decisionFixtureV3(t)
	rehearsal := d
	rehearsal.Mode = ModeRehearsal
	var err error
	rehearsal, err = FinalizeCeremonyDefinition(rehearsal)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProductionDecisionBindingV4(rehearsal, x); err == nil || !strings.Contains(err.Error(), "production-mode") {
		t.Fatalf("rehearsal mode gate: %v", err)
	}
	root := t.TempDir()
	db, ds, err := SignRecord(d, d.Coordinator.KeyID, adversarialPrivateKey(1))
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(root, "coordinator.hex")}
	if err := os.WriteFile(trust.CoordinatorPublicKeyPath, []byte(d.Coordinator.Ed25519PublicKeyHex+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trust.DefinitionPath, db, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trust.DefinitionSignaturePath, ds, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := MarshalCanonical(x)
	o := VerifyProductionDecisionEvidenceV4Options{Trust: trust, ArtifactRoot: root, DecisionBytes: raw}
	draftRaw, err := MarshalCanonical(decisionDraftFixtureV3(x))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareProductionDecisionV4(trust, root, draftRaw); err == nil {
		t.Fatal("prepared signable decision without package")
	}
	if result, err := VerifyProductionDecisionEvidenceV4(o); err == nil || result.Decision.DecisionID != "" {
		t.Fatal("absent package yielded evidence result")
	}
	if _, err := SignProductionDecisionV4(o, DecisionSignerRelease, d.ReleaseSigner.ID, adversarialPrivateKey(2)); err == nil {
		t.Fatal("signed without package")
	}
	if _, err := VerifyProductionDecisionV4(VerifyProductionDecisionV4Options{VerifyProductionDecisionEvidenceV4Options: o, SignatureBytes: [][]byte{testDecisionSignatureV3(t, raw, d.Coordinator, DecisionSignerCoordinator, 1), testDecisionSignatureV3(t, raw, d.ReleaseSigner, DecisionSignerRelease, 2)}}); err == nil {
		t.Fatal("signatures substituted for missing package")
	}
}

func TestDecisionV3EnabledExternalGateBindsEveryReportAndSignoff(t *testing.T) {
	_, x := decisionFixtureV3(t)
	x.AssurancePolicy.ExternalSecurityAuditSignoffs = 1
	x.ExternalAudits = []ExternalAuditEvidenceV3{{Auditor: adversarialIdentity(t, "external", 9), Report: checkpointArtifact("decision/evidence/external.txt", "report"), Signoff: checkpointArtifact("decision/evidence/external.sig", "signature")}}
	refs := []ArtifactRef{x.ExternalAudits[0].Report, x.ExternalAudits[0].Signoff}
	slices.SortFunc(refs, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	index := -1
	for i := range x.Gates {
		if x.Gates[i].Gate == GateExternalAudit {
			index = i
			x.Gates[i].Status = GatePASS
			x.Gates[i].Evidence = refs
			x.Gates[i].Rationale = ""
		}
	}
	if _, err := NewProductionDecisionV3(x); err != nil {
		t.Fatal(err)
	}
	x.Gates[index].Evidence = refs[:1]
	if _, err := NewProductionDecisionV3(x); err == nil {
		t.Fatal("external gate omitted signoff/report")
	}
}

func TestDecisionV3ExternalEvidenceBytesAndSignoff(t *testing.T) {
	_, x := decisionFixtureV3(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "decision/evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	refs, err := decisionExternalArtifactsV3(x)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if err := os.WriteFile(filepath.Join(root, ref.Name), []byte("public fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.root.Close()
	if _, err := verifyDecisionExternalEvidenceV3(reader, x); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, x.SourceRelease.VerificationReport.Name), []byte("changed report"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDecisionExternalEvidenceV3(reader, x); err == nil {
		t.Fatal("changed source report accepted")
	}
	if err := os.WriteFile(filepath.Join(root, x.SourceRelease.VerificationReport.Name), []byte("public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	a := adversarialIdentity(t, "external", 9)
	key := adversarialPrivateKey(9)
	report := []byte("external audit public report")
	signature, err := SignExact(report, a.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := MarshalCanonical(signature)
	if err != nil {
		t.Fatal(err)
	}
	r := checkpointArtifact("decision/evidence/external.txt", string(report))
	s := checkpointArtifact("decision/evidence/external.sig", string(sig))
	if err := os.WriteFile(filepath.Join(root, r.Name), report, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, s.Name), sig, 0600); err != nil {
		t.Fatal(err)
	}
	x.ExternalAudits = []ExternalAuditEvidenceV3{{Auditor: a, Report: r, Signoff: s}}
	if _, err := verifyDecisionExternalEvidenceV3(reader, x); err != nil {
		t.Fatal(err)
	}
	// Coherently update the report digest; only cryptographic signature checking
	// can reject this mismatch, not an incidental stale artifact hash.
	report = []byte("different external report")
	x.ExternalAudits[0].Report.Digest = NewDigest(report)
	if err := os.WriteFile(filepath.Join(root, r.Name), report, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDecisionExternalEvidenceV3(reader, x); err == nil {
		t.Fatal("external signature accepted another report")
	}
}
