package mpcceremony

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

const (
	ProductionDecisionSchemaV4                     = "proof-tool-mpc-production-decision-v4"
	ProductionDecisionDraftSchemaV4                = "proof-tool-mpc-production-decision-draft-v4"
	ProductionDecisionSchemaV5                     = "proof-tool-mpc-production-decision-v5"
	ProductionDecisionDraftSchemaV5                = "proof-tool-mpc-production-decision-draft-v5"
	ProductionDecisionSchemaV3                     = "proof-tool-mpc-production-decision-v3"
	ProductionDecisionDraftSchemaV3                = "proof-tool-mpc-production-decision-draft-v3"
	GateSourceRelease               ProductionGate = "source-release"
	GateExactCircuitRehearsal       ProductionGate = "exact-circuit-rehearsal"
	DecisionSourceReportV3                         = "decision/evidence/source-release.json"
)

// FinalReleaseEvidenceV4 binds a complete verified package through the exact
// coordinator checkpoint. It is not an operator-selected list of package files.
type FinalReleaseEvidenceV4 struct {
	ReleaseID              string             `json:"release_id"`
	CeremonyID             string             `json:"ceremony_id"`
	FinalReleaseCheckpoint SignedArtifactRefs `json:"final_release_checkpoint"`
	CandidateID            string             `json:"candidate_id"`
}

func NewFinalReleaseEvidenceV4(ceremonyID string, checkpoint SignedArtifactRefs, candidateID string) (FinalReleaseEvidenceV4, error) {
	r := FinalReleaseEvidenceV4{CeremonyID: ceremonyID, FinalReleaseCheckpoint: checkpoint, CandidateID: candidateID}
	var err error
	r.ReleaseID, err = computeFinalReleaseIDV4(r)
	if err != nil {
		return FinalReleaseEvidenceV4{}, err
	}
	return r, r.Validate()
}

func computeFinalReleaseIDV4(r FinalReleaseEvidenceV4) (string, error) {
	r.ReleaseID = ""
	return canonicalHash("proof-tool/mpc-ceremony/signed-release/v2", r)
}

func (r FinalReleaseEvidenceV4) Validate() error {
	for _, id := range []string{r.ReleaseID, r.CeremonyID, r.CandidateID} {
		if err := validateHashID("release binding", id); err != nil {
			return err
		}
	}
	if err := r.FinalReleaseCheckpoint.Validate(); err != nil {
		return err
	}
	for _, ref := range signedArtifacts(&r.FinalReleaseCheckpoint) {
		if err := validatePortableStorageName(ref.Name); err != nil {
			return err
		}
	}
	id, err := computeFinalReleaseIDV4(r)
	if err != nil {
		return err
	}
	if id != r.ReleaseID {
		return errors.New("release ID does not match exact ceremony, checkpoint and candidate")
	}
	return nil
}

type SourceReleaseEvidenceV4 struct {
	SourceCommit       string      `json:"source_commit"`
	VerificationReport ArtifactRef `json:"verification_report"`
}

type DecisionAuditorV3 struct {
	AuditorID    string `json:"auditor_id"`
	AuditorKeyID string `json:"auditor_key_id"`
}

type ExternalAuditEvidenceV3 struct {
	Auditor Identity    `json:"auditor"`
	Report  ArtifactRef `json:"report"`
	Signoff ArtifactRef `json:"signoff"`
}

type K21RehearsalEvidenceV3 struct {
	Circuit  CircuitBinding `json:"circuit"`
	Evidence ArtifactRef    `json:"evidence"`
}

// CircuitRehearsalEvidenceV5 names the exact signed circuit. The report is
// reviewed by decision signers; its content is not inferred from its filename.
type CircuitRehearsalEvidenceV5 struct {
	Circuit  CircuitBinding `json:"circuit"`
	Evidence ArtifactRef    `json:"evidence"`
}

type ProductionGateResultV3 struct {
	Gate      ProductionGate       `json:"gate"`
	Status    ProductionGateStatus `json:"status"`
	Evidence  []ArtifactRef        `json:"evidence"`
	Rationale string               `json:"rationale"`
}

type ProductionDecisionV3 struct {
	Schema                string                      `json:"schema"`
	DecisionID            string                      `json:"decision_id"`
	CeremonyID            string                      `json:"ceremony_id"`
	AssurancePolicy       *AssurancePolicy            `json:"assurance_policy"`
	Release               FinalReleaseEvidenceV4      `json:"release"`
	SourceRelease         SourceReleaseEvidenceV4     `json:"source_release"`
	Auditors              []DecisionAuditorV3         `json:"auditors"`
	ExternalAudits        []ExternalAuditEvidenceV3   `json:"external_audits"`
	K21Rehearsal          *K21RehearsalEvidenceV3     `json:"k21_rehearsal,omitempty"`
	CircuitRehearsal      *CircuitRehearsalEvidenceV5 `json:"circuit_rehearsal,omitempty"`
	MainnetDeploymentPlan ArtifactRef                 `json:"mainnet_deployment_plan"`
	FormalChecklist       ArtifactRef                 `json:"formal_checklist"`
	Gates                 []ProductionGateResultV3    `json:"gates"`
	Decision              ProductionDecisionOutcome   `json:"decision"`
	DecidedAt             string                      `json:"decided_at"`
}

func decisionGatesV3() []ProductionGate {
	return append([]ProductionGate{GateSourceRelease}, requiredProductionGates[:]...)
}

func packageDerivedGateV3(g ProductionGate) bool {
	switch g {
	case GateSignedRelease, GateOperationalEvidence, GateIndependentAudits, GatePublicWitnessing, GateImmutableMirrors:
		return true
	}
	return false
}

func optionalDecisionGateV3(g ProductionGate, p AssurancePolicy) (bool, bool) {
	switch g {
	case GateIndependentAudits:
		return true, p.PassingCeremonyAudits > 0
	case GateExternalAudit:
		return true, p.ExternalSecurityAuditSignoffs > 0
	case GatePublicWitnessing:
		return true, p.PublicWitnessesPerPhase > 0
	case GateImmutableMirrors:
		return true, p.MirrorsPerAcceptedHead > 0
	}
	return false, true
}

func validateDecisionEvidenceRefV3(ref ArtifactRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := validatePortableStorageName(ref.Name); err != nil {
		return err
	}
	if !strings.HasPrefix(ref.Name, "decision/evidence/") {
		return errors.New("decision evidence must be under decision/evidence/")
	}
	if ref.Digest.Size > maxSignedRecordBytes {
		return errors.New("decision evidence exceeds bounded report size")
	}
	return nil
}

func (g ProductionGateResultV3) validate(p AssurancePolicy) error {
	if g.Evidence == nil || len(g.Evidence) > 32 {
		return errors.New("gate evidence must be explicit and bounded")
	}
	if err := validateV4ArtifactSet(g.Evidence, 32); err != nil {
		return err
	}
	for _, ref := range g.Evidence {
		if err := validateDecisionEvidenceRefV3(ref); err != nil {
			return err
		}
	}
	if g.Rationale != strings.TrimSpace(g.Rationale) || len(g.Rationale) > 2048 {
		return errors.New("gate rationale must be trimmed and bounded")
	}
	optional, enabled := optionalDecisionGateV3(g.Gate, p)

	if optional && !enabled {
		if g.Status != GateNotRequired || len(g.Evidence) != 0 || g.Rationale == "" {
			return errors.New("disabled assurance gate must be NOT_REQUIRED with an explanation and no evidence")
		}
		return nil
	}
	if packageDerivedGateV3(g.Gate) && (g.Status != GatePASS || len(g.Evidence) != 0) {
		return errors.New("verified package gate must be PASS with no duplicated evidence")
	}
	switch g.Status {
	case GatePASS:
		if packageDerivedGateV3(g.Gate) {
			if len(g.Evidence) != 0 {
				return errors.New("package-derived gate must not duplicate evidence")
			}
		} else if len(g.Evidence) == 0 {
			return errors.New("external PASS gate needs exact evidence")
		}
	case GateFAIL, GatePENDING:
		if g.Rationale == "" {
			return errors.New("failed/pending gate needs an explanation")
		}
	case GateNotRequired:
		return errors.New("enabled or mandatory gate cannot be NOT_REQUIRED")
	default:
		return errors.New("unsupported gate status")
	}
	return nil
}

func NewProductionDecisionV3(value ProductionDecisionV3) (ProductionDecisionV3, error) {
	// No implicit schema or missing-array upgrade: callers select the new format.
	value.DecisionID = ""
	id, err := computeProductionDecisionIDV3(value)
	if err != nil {
		return ProductionDecisionV3{}, err
	}
	value.DecisionID = id
	return value, value.Validate()
}

func computeProductionDecisionIDV3(value ProductionDecisionV3) (string, error) {
	value.DecisionID = ""
	domain := "proof-tool/mpc-ceremony/production-decision/v3"
	switch value.Schema {
	case ProductionDecisionSchemaV4:
		domain = "proof-tool/mpc-ceremony/production-decision/v4"
	case ProductionDecisionSchemaV5:
		domain = "proof-tool/mpc-ceremony/production-decision/v5"
	}
	return canonicalHash(domain, value)
}

func (d ProductionDecisionV3) Validate() error {

	if (d.Schema != ProductionDecisionSchemaV3 && d.Schema != ProductionDecisionSchemaV4 && d.Schema != ProductionDecisionSchemaV5) || d.AssurancePolicy == nil || d.Auditors == nil || d.ExternalAudits == nil || d.Gates == nil {
		return errors.New("decision v3 requires its explicit schema, policy and arrays")
	}
	if err := validateHashID("decision_id", d.DecisionID); err != nil {
		return err
	}
	id, err := computeProductionDecisionIDV3(d)
	if err != nil {
		return err
	}
	if id != d.DecisionID {
		return errors.New("decision ID differs from exact contents")
	}
	if err := d.Release.Validate(); err != nil {
		return err
	}
	if d.CeremonyID != d.Release.CeremonyID {
		return errors.New("decision and release identify different ceremonies")
	}
	if err := validateHex(d.SourceRelease.SourceCommit, 20); err != nil {
		return err
	}
	if d.SourceRelease.VerificationReport.Name != DecisionSourceReportV3 {
		return errors.New("source report must use its canonical evidence name")
	}
	if len(d.Auditors) > MaxAuditors || len(d.ExternalAudits) > MaxAuditors {
		return errors.New("decision auditor count exceeds maximum")
	}
	if err := d.AssurancePolicy.Validate(ModeProduction, len(d.Auditors)); err != nil {
		return err
	}
	if len(d.Auditors) < int(d.AssurancePolicy.PassingCeremonyAudits) || d.AssurancePolicy.PassingCeremonyAudits == 0 && len(d.Auditors) != 0 || len(d.ExternalAudits) < int(d.AssurancePolicy.ExternalSecurityAuditSignoffs) || d.AssurancePolicy.ExternalSecurityAuditSignoffs == 0 && len(d.ExternalAudits) != 0 {
		return errors.New("decision audit counts differ from signed assurance policy")
	}
	keys := map[string]bool{}
	for i, a := range d.Auditors {
		if err := validateID("auditor_id", a.AuditorID); err != nil {
			return err
		}
		if err := validateID("auditor_key_id", a.AuditorKeyID); err != nil {
			return err
		}
		if i > 0 && d.Auditors[i-1].AuditorID >= a.AuditorID || keys[a.AuditorKeyID] {
			return errors.New("auditors must be sorted and distinct")
		}
		keys[a.AuditorKeyID] = true
	}
	externalKeys := map[string]bool{}
	for i, a := range d.ExternalAudits {
		if err := a.Auditor.Validate(); err != nil {
			return err
		}
		if i > 0 && d.ExternalAudits[i-1].Auditor.ID >= a.Auditor.ID || externalKeys[a.Auditor.PublicKeyFingerprint] || a.Report.Name == a.Signoff.Name {
			return errors.New("external auditors and report/signoff paths must be distinct")
		}
		externalKeys[a.Auditor.PublicKeyFingerprint] = true
		if a.Signoff.Digest.Size > 4096 {
			return errors.New("external signoff exceeds signature size limit")
		}
	}
	if d.Schema == ProductionDecisionSchemaV5 {
		if d.K21Rehearsal != nil || d.CircuitRehearsal == nil {
			return errors.New("decision v5 requires only circuit_rehearsal")
		}
		if err := ValidateCanonicalCeremonyCircuit(d.CircuitRehearsal.Circuit); err != nil {
			return fmt.Errorf("circuit rehearsal: %w", err)
		}
	} else {
		if d.K21Rehearsal == nil || d.CircuitRehearsal != nil {
			return errors.New("historical decision requires only k21_rehearsal")
		}
		b := d.K21Rehearsal.Circuit
		if err := b.Validate(); err != nil {
			return err
		}
		if b.KeyVersion != KeyVersionDestinationV3 || b.DomainSize != 1<<21 {
			return errors.New("production decision requires the exact K21 destination-v3 rehearsal")
		}
	}
	if path.Ext(d.FormalChecklist.Name) != ".md" {
		return errors.New("formal checklist must be Markdown")
	}
	expected := decisionGatesV3()
	switch d.Schema {
	case ProductionDecisionSchemaV4:
		expected = decisionGatesV4()
	case ProductionDecisionSchemaV5:
		expected = decisionGatesV5()
	}
	if len(d.Gates) != len(expected) {
		return errors.New("decision requires every V3 production gate exactly once")
	}
	all := true
	for i, g := range d.Gates {
		if g.Gate != expected[i] {
			return fmt.Errorf("wrong production gate at index %d", i)
		}
		if err := g.validate(*d.AssurancePolicy); err != nil {
			return fmt.Errorf("gate %s: %w", g.Gate, err)
		}
		var bound []ArtifactRef
		switch g.Gate {
		case GateSourceRelease:
			bound = []ArtifactRef{d.SourceRelease.VerificationReport}
		case GateK21Rehearsal:
			bound = []ArtifactRef{d.K21Rehearsal.Evidence}
		case GateExactCircuitRehearsal:
			bound = []ArtifactRef{d.CircuitRehearsal.Evidence}
		case GateMainnetDeploymentPlan:
			bound = []ArtifactRef{d.MainnetDeploymentPlan}
		case GateFormalChecklist:
			bound = []ArtifactRef{d.FormalChecklist}
		case GateExternalAudit:
			bound = []ArtifactRef{}
			for _, audit := range d.ExternalAudits {
				bound = append(bound, audit.Report, audit.Signoff)
			}
			slices.SortFunc(bound, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
		}
		if bound != nil && !slices.Equal(g.Evidence, bound) {
			return fmt.Errorf("gate %s must bind its exact structured evidence", g.Gate)
		}
		all = all && (g.Status == GatePASS || g.Status == GateNotRequired)
	}
	if d.Decision != DecisionGO && d.Decision != DecisionNOGO || d.Decision == DecisionGO && !all || d.Decision == DecisionNOGO && all {
		return errors.New("decision outcome disagrees with gate results")
	}
	if err := validateTimestamp("decided_at", d.DecidedAt); err != nil {
		return err
	}
	_, err = decisionExternalArtifactsV3(d)
	return err
}

func decisionExternalArtifactsV3(d ProductionDecisionV3) ([]ArtifactRef, error) {
	refs := []ArtifactRef{d.SourceRelease.VerificationReport, d.MainnetDeploymentPlan, d.FormalChecklist}
	if d.Schema == ProductionDecisionSchemaV5 {
		refs = append(refs, d.CircuitRehearsal.Evidence)
	} else {
		refs = append(refs, d.K21Rehearsal.Evidence)
	}
	for _, a := range d.ExternalAudits {
		refs = append(refs, a.Report, a.Signoff)
	}
	for _, g := range d.Gates {
		refs = append(refs, g.Evidence...)
	}
	byName := map[string]ArtifactRef{}
	for _, r := range refs {
		if err := validateDecisionEvidenceRefV3(r); err != nil {
			return nil, err
		}
		if old, ok := byName[r.Name]; ok && old != r {
			return nil, errors.New("decision evidence name has conflicting digests")
		}
		byName[r.Name] = r
	}
	result := make([]ArtifactRef, 0, len(byName))
	for _, r := range byName {
		result = append(result, r)
	}
	slices.SortFunc(result, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	if err := validateV4ArtifactSet(result, 512+2*MaxAuditors); err != nil {
		return nil, err
	}
	return result, nil
}

func decisionGatesV4() []ProductionGate {
	gates := decisionGatesV3()
	return slices.DeleteFunc(gates, func(g ProductionGate) bool { return g == GateParticipantIndependent || g == GateLiveTwentyParty })
}

func decisionGatesV5() []ProductionGate {
	gates := decisionGatesV4()
	for i, gate := range gates {
		if gate == GateK21Rehearsal {
			gates[i] = GateExactCircuitRehearsal
		}
	}
	return gates
}
