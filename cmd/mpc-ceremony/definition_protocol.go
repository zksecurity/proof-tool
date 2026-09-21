package main

import m "proof-tool/internal/mpcceremony"

// This is a separate projection so existing definition inspection consumers
// retain their wire format. StorageWorkflow is derived from the authenticated
// definition format, not an unauthenticated backend hint.
type DefinitionProtocolInspection struct {
	Schema              string               `json:"schema"`
	DefinitionSchema    string               `json:"definition_schema"`
	StorageWorkflow     string               `json:"storage_workflow"`
	ReleaseVerification string               `json:"release_verification"`
	Definition          DefinitionInspection `json:"definition"`
	DefinitionRefs      m.SignedArtifactRefs `json:"definition_refs"`
}

func executeInspectDefinitionProtocol(o InspectDefinitionOptions) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(o)
	if err != nil {
		return CommandResult{}, err
	}
	d := trusted.Definition
	workflow := m.StorageFirstWorkflowV1
	if d.UsesCoordinatorReplay() {
		workflow = m.StorageFirstWorkflowV2
	}
	inspection := DefinitionProtocolInspection{
		Schema:           "proof-tool-mpc-definition-protocol-inspection-v1",
		DefinitionSchema: d.Schema, StorageWorkflow: workflow,
		ReleaseVerification: d.ReleaseVerification, Definition: inspectDefinition(d),
		DefinitionRefs: trusted.DefinitionRefs,
	}
	return CommandResult{CeremonyID: d.CeremonyID, Summary: "Authenticated definition protocol and schedules; no backend state or contribution mathematics verified.", DefinitionProtocolInspection: &inspection}, nil
}
