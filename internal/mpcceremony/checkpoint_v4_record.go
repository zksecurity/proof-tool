package mpcceremony

import (
	"errors"
	"path/filepath"
)

// RecordedCheckpointV4Options describes an already-created signed protocol
// record which the coordinator wants to add to the authenticated state. The
// helper derives every state projection; callers do not author checkpoint JSON.
type RecordedCheckpointV4Options struct {
	Trust        TrustPaths
	Circuit      *CompiledCircuit
	ArtifactRoot string
	Checkpoint   SignedArtifactRefs
	Kind         CheckpointTransitionKind
	Record       SignedArtifactRefs
	Evidence     []ArtifactRef
}

type RecordedCheckpointV4 struct {
	Checkpoint CheckpointV4
	Canonical  []byte
}

func recordableCheckpointKindV4(kind CheckpointTransitionKind) bool {
	switch kind {
	case CheckpointEnrollmentRecorded, CheckpointMirrorRecorded, CheckpointWitnessRecorded,
		CheckpointBeaconEvidenceRecorded, CheckpointAuditRecorded, CheckpointIncidentRecorded,
		CheckpointPhase1Closed, CheckpointPhase1BeaconRecorded, CheckpointPhase1Sealed,
		CheckpointPhase2Initialized, CheckpointPhase2Closed, CheckpointPhase2BeaconRecorded,
		CheckpointFinalCandidateRecorded, CheckpointFinalReleaseRecorded, CheckpointAborted:
		return true
	default:
		return false
	}
}

// PrepareRecordedCheckpointV4 authenticates the complete predecessor, derives
// the only legal descendant for Kind, and rechecks the exact record/evidence.
// Allocation and candidate acceptance have dedicated APIs; restart and
// rejection remain explicit advanced proposal operations.
func PrepareRecordedCheckpointV4(options RecordedCheckpointV4Options) (RecordedCheckpointV4, error) {
	if !recordableCheckpointKindV4(options.Kind) {
		return RecordedCheckpointV4{}, errors.New("transition is not supported by record-v4")
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return RecordedCheckpointV4{}, err
	}
	defer func() { _ = stored.reader.root.Close() }()
	previous := stored.ancestry.head
	d := stored.trusted.Definition

	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return RecordedCheckpointV4{}, err
	}
	next.Sequence++
	next.PreviousCheckpoint = &options.Checkpoint
	next.Transition = CheckpointTransitionV4{Kind: options.Kind, Record: &options.Record, Evidence: appendUniqueSortedArtifactsV4(nil, options.Evidence...)}
	next.AcceptedArtifacts = appendUniqueSortedArtifactsV4(next.AcceptedArtifacts, append(signedArtifacts(&options.Record), options.Evidence...)...)

	switch options.Kind {
	case CheckpointPhase1Closed:
		next.Progress.Phase1Closure = &options.Record
	case CheckpointPhase1BeaconRecorded:
		next.Progress.Phase1Beacon = &options.Record
	case CheckpointPhase1Sealed:
		next.Progress.Phase1Seal = &options.Record
	case CheckpointPhase2Initialized:
		if options.Circuit == nil || previous.Progress.Phase1Seal == nil {
			return RecordedCheckpointV4{}, errors.New("phase2 initialization requires the authenticated phase1 seal and circuit")
		}
		path := func(ref ArtifactRef) string { return filepath.Join(options.ArtifactRoot, filepath.FromSlash(ref.Name)) }
		verified, err := VerifyPhase2GenesisFiles(VerifyPhase2GenesisFilesOptions{
			Trust: options.Trust, Circuit: options.Circuit, TranscriptRoot: options.ArtifactRoot,
			Phase1SealPath: path(previous.Progress.Phase1Seal.Record), Phase1SealSignaturePath: path(previous.Progress.Phase1Seal.Signature),
			Phase2ChainPath: path(options.Record.Record), Phase2ChainSignaturePath: path(options.Record.Signature),
		})
		if err != nil {
			return RecordedCheckpointV4{}, err
		}
		headID, err := verified.Chain.HeadRecordID()
		if err != nil {
			return RecordedCheckpointV4{}, err
		}
		next.Progress.Phase2 = &CheckpointPhaseState{Phase: Phase2, HeadRecordID: headID, HeadPayload: verified.Genesis, Chain: verified.ChainRefs}
	case CheckpointPhase2Closed:
		next.Progress.Phase2Closure = &options.Record
	case CheckpointPhase2BeaconRecorded:
		next.Progress.Phase2Beacon = &options.Record
	case CheckpointFinalCandidateRecorded:
		running, err := RunningSoftwareBindingForMode(d.Software.ProofToolVersion, d.Mode)
		if err != nil {
			return RecordedCheckpointV4{}, err
		}
		next.Transition.ReplayVerification = &CheckpointReplayVerificationV4{Method: CoordinatorReplayReleaseV1, ToolBinary: running.ToolBinary}
		next.Progress.FinalCandidate = &options.Record
	case CheckpointFinalReleaseRecorded:
		next.Progress.FinalRelease = &options.Record
	case CheckpointAborted:
		next.Progress.Terminal = &CheckpointTerminalV4{Kind: GovernanceAbort, Record: options.Record}
	}

	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{
		Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next, Circuit: options.Circuit,
	})
	if err != nil {
		return RecordedCheckpointV4{}, err
	}
	return RecordedCheckpointV4{Checkpoint: next, Canonical: canonical}, nil
}
