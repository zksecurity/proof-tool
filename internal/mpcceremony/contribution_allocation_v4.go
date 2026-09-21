package mpcceremony

import (
	"errors"
	"fmt"
	"path/filepath"
)

// AllocatedContributionFilesV4Options names one coordinator-allocated V4
// attempt. The signed checkpoint, rather than caller-provided chain paths,
// selects the exact immutable input snapshot.
type AllocatedContributionFilesV4Options struct {
	Trust                     TrustPaths
	Circuit                   *CompiledCircuit
	ArtifactRoot              string
	Checkpoint                SignedArtifactRefs
	AttemptID                 string
	ParticipantPrivateKeyPath string
	Environment               ContributionEnvironment
	ContributedAt             string
	CandidateDir              string
}

// CreateAllocatedContributionCandidateV4 authenticates the allocation and
// its exact transcript snapshot in the same process that later generates the
// contribution randomness. No candidate bytes are written before these
// checks and the full chain replay succeed.
func CreateAllocatedContributionCandidateV4(options AllocatedContributionFilesV4Options) (ContributionFilesResult, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return ContributionFilesResult{}, err
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return ContributionFilesResult{}, err
	}
	defer func() { _ = stored.reader.root.Close() }()
	if !stored.trusted.Definition.UsesCoordinatorReplay() {
		return ContributionFilesResult{}, errors.New("allocated contribution requires definition v4")
	}
	allocation, ok := stored.ancestry.allocations[options.AttemptID]
	if !ok || allocation.Scope == nil {
		return ContributionFilesResult{}, errors.New("candidate attempt is not allocated by the authenticated checkpoint ancestry")
	}
	var slot *DeliverySlotV2
	for index := range stored.ancestry.head.Deliveries {
		candidate := &stored.ancestry.head.Deliveries[index]
		if candidate.AttemptID == options.AttemptID {
			slot = candidate
			break
		}
	}
	if slot == nil || slot.Kind != CheckpointSubmissionCandidate || slot.Status != DeliveryAllocated || slot.Scope != *allocation.Scope {
		return ContributionFilesResult{}, errors.New("candidate allocation is no longer active at the authenticated checkpoint")
	}
	if err := stored.ancestry.head.Progress.currentTurn(*allocation.Scope); err != nil {
		return ContributionFilesResult{}, fmt.Errorf("candidate allocation is not the current turn: %w", err)
	}
	state := stored.ancestry.head.Progress.Phase1
	if allocation.Scope.Phase == Phase2 {
		if stored.ancestry.head.Progress.Phase2 == nil || stored.ancestry.head.Progress.Phase1Seal == nil {
			return ContributionFilesResult{}, errors.New("phase2 allocation requires authenticated phase2 state and phase1 seal")
		}
		state = *stored.ancestry.head.Progress.Phase2
	}
	root := stored.reader.path
	contribution := ContributionFilesOptions{
		Trust:                     options.Trust,
		Circuit:                   options.Circuit,
		Phase:                     allocation.Scope.Phase,
		Transcript:                PhaseTranscriptPaths{RootDir: root, ChainPath: filepath.Join(root, state.Chain.Record.Name), ChainSignaturePath: filepath.Join(root, state.Chain.Signature.Name)},
		ParticipantID:             allocation.Scope.ParticipantID,
		ParticipantPrivateKeyPath: options.ParticipantPrivateKeyPath,
		Environment:               options.Environment,
		ContributedAt:             options.ContributedAt,
		CandidateDir:              options.CandidateDir,
		ExpectedScope:             allocation.Scope,
	}
	if allocation.Scope.Phase == Phase2 {
		seal := stored.ancestry.head.Progress.Phase1Seal
		contribution.Phase1SealPath = filepath.Join(root, seal.Record.Name)
		contribution.Phase1SealSignaturePath = filepath.Join(root, seal.Signature.Name)
	}
	return CreateContributionCandidate(contribution)
}
