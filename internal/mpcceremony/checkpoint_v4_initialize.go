package mpcceremony

import (
	"errors"
	"path/filepath"
)

// InitialCheckpointV4Options identifies the already initialized, signed
// ceremony files from which the first storage-first checkpoint is derived.
// Callers cannot supply a checkpoint proposal or alter its initial projection.
type InitialCheckpointV4Options struct {
	Trust        TrustPaths
	Circuit      *CompiledCircuit
	ArtifactRoot string
}

// InitialCheckpointV4 is a fully checked, unsigned initial checkpoint. The
// caller signs Canonical with the authenticated coordinator key and publishes
// that exact pair through the delivery service.
type InitialCheckpointV4 struct {
	Checkpoint CheckpointV4
	Canonical  []byte
}

// PrepareInitialCheckpointV4 derives sequence zero from the authenticated
// definition and the fully replayed Phase 1 genesis chain. This keeps protocol
// JSON construction inside proof-tool rather than a transport controller.
func PrepareInitialCheckpointV4(options InitialCheckpointV4Options) (InitialCheckpointV4, error) {
	trusted, err := LoadSignedDefinition(options.Trust)
	if err != nil {
		return InitialCheckpointV4{}, err
	}
	d := trusted.Definition
	if d.Schema != DefinitionSchemaV4 || d.ReleaseVerification != CoordinatorReplayReleaseV1 {
		return InitialCheckpointV4{}, errors.New("initial checkpoint requires the explicit trusted-coordinator definition v4")
	}
	chainPath := filepath.Join(options.ArtifactRoot, "phase1", "chain-0000.json")
	chainSignaturePath := filepath.Join(options.ArtifactRoot, "phase1", "chain-0000.sig")
	chain, chainRefs, err := VerifyAcceptedPhase1Chain(options.Trust, options.Circuit, PhaseTranscriptPaths{
		RootDir: options.ArtifactRoot, ChainPath: chainPath, ChainSignaturePath: chainSignaturePath,
	})
	if err != nil {
		return InitialCheckpointV4{}, err
	}
	headID, err := chain.HeadRecordID()
	if err != nil {
		return InitialCheckpointV4{}, err
	}
	headPayload, err := chain.HeadPayload()
	if err != nil {
		return InitialCheckpointV4{}, err
	}
	checkpoint := CheckpointV4{
		Schema: CheckpointSchemaV4, Workflow: StorageFirstWorkflowV2,
		CeremonyID: d.CeremonyID, Definition: trusted.DefinitionRefs,
		AssurancePolicy: d.AssurancePolicy, ReleaseVerification: d.ReleaseVerification,
		Transition: CheckpointTransitionV4{Kind: CheckpointInitial, Evidence: []ArtifactRef{}},
		Progress: CheckpointProgressV4{Phase1: CheckpointPhaseState{
			Phase: Phase1, HeadRecordID: headID, HeadPayload: headPayload, Chain: chainRefs,
		}},
		AcceptedArtifacts: appendUniqueSortedArtifactsV4(nil, trusted.DefinitionRefs.Record, trusted.DefinitionRefs.Signature, d.Circuit.R1CS, chainRefs.Record, chainRefs.Signature, headPayload),
		Deliveries:        []DeliverySlotV2{},
	}
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{
		Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: checkpoint, Circuit: options.Circuit,
	})
	if err != nil {
		return InitialCheckpointV4{}, err
	}
	return InitialCheckpointV4{Checkpoint: checkpoint, Canonical: canonical}, nil
}
