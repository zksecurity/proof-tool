package mpcceremony

import "errors"

var (
	errDecisionDraftSchemaV3 = errors.New("explicit production decision draft v3 is required")
	errDecisionDraftSizeV3   = errors.New("decision draft exceeds record size limit")
)

type FinalReleaseEvidenceDraftV4 struct {
	FinalReleaseCheckpoint SignedArtifactRefs `json:"final_release_checkpoint"`
	CandidateID            string             `json:"candidate_id"`
}

// Drafts omit content-derived IDs. They still name exact reviewed evidence;
// preparation never infers PASS from a file existing.
type ProductionDecisionDraftV3 struct {
	Schema                string                      `json:"schema"`
	CeremonyID            string                      `json:"ceremony_id"`
	AssurancePolicy       *AssurancePolicy            `json:"assurance_policy"`
	Release               FinalReleaseEvidenceDraftV4 `json:"release"`
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

func (d ProductionDecisionDraftV3) Validate() error {
	_, err := d.decision()
	return err
}

func (d ProductionDecisionDraftV3) decision() (ProductionDecisionV3, error) {
	if d.Schema != ProductionDecisionDraftSchemaV3 && d.Schema != ProductionDecisionDraftSchemaV4 && d.Schema != ProductionDecisionDraftSchemaV5 {
		return ProductionDecisionV3{}, errDecisionDraftSchemaV3
	}
	release, err := NewFinalReleaseEvidenceV4(d.CeremonyID, d.Release.FinalReleaseCheckpoint, d.Release.CandidateID)
	if err != nil {
		return ProductionDecisionV3{}, err
	}
	schema := ProductionDecisionSchemaV3
	switch d.Schema {
	case ProductionDecisionDraftSchemaV4:
		schema = ProductionDecisionSchemaV4
	case ProductionDecisionDraftSchemaV5:
		schema = ProductionDecisionSchemaV5
	}
	return NewProductionDecisionV3(ProductionDecisionV3{Schema: schema, CeremonyID: d.CeremonyID, AssurancePolicy: cloneAssurancePolicy(d.AssurancePolicy), Release: release, SourceRelease: d.SourceRelease, Auditors: d.Auditors, ExternalAudits: d.ExternalAudits, K21Rehearsal: d.K21Rehearsal, CircuitRehearsal: d.CircuitRehearsal, MainnetDeploymentPlan: d.MainnetDeploymentPlan, FormalChecklist: d.FormalChecklist, Gates: d.Gates, Decision: d.Decision, DecidedAt: d.DecidedAt})
}

func PrepareProductionDecisionV4(trust TrustPaths, root string, draftBytes []byte) (ProductionDecisionV3, []byte, error) {
	if len(draftBytes) > maxSignedRecordBytes {
		return ProductionDecisionV3{}, nil, errDecisionDraftSizeV3
	}
	var draft ProductionDecisionDraftV3
	if err := UnmarshalCanonical(draftBytes, &draft); err != nil {
		return ProductionDecisionV3{}, nil, err
	}
	decision, err := draft.decision()
	if err != nil {
		return ProductionDecisionV3{}, nil, err
	}
	raw, err := MarshalCanonical(decision)
	if err != nil {
		return ProductionDecisionV3{}, nil, err
	}
	if _, err := VerifyProductionDecisionEvidenceV4(VerifyProductionDecisionEvidenceV4Options{Trust: trust, ArtifactRoot: root, DecisionBytes: raw}); err != nil {
		return ProductionDecisionV3{}, nil, err
	}
	return decision, raw, nil
}
