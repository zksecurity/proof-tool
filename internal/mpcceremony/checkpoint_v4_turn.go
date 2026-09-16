package mpcceremony

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
)

// CandidateAllocationCheckpointV4Options identifies one fresh coordinator
// allocation. The phase, participant, index and parent head are derived from
// authenticated ceremony state rather than supplied by the transport layer.
type CandidateAllocationCheckpointV4Options struct {
	Trust        TrustPaths
	ArtifactRoot string
	Checkpoint   SignedArtifactRefs
	AttemptID    string
	AllocatedAt  string
}

// CandidateAllocationCheckpointV4 is an internally prepared, unsigned
// checkpoint. The caller must sign its Canonical bytes with the authenticated
// coordinator key and publish the record/signature pair atomically.
type CandidateAllocationCheckpointV4 struct {
	Checkpoint CheckpointV4
	Scope      ContributionScope
	Canonical  []byte
}

// PrepareCandidateAllocationCheckpointV4 derives and verifies the exact next
// contribution turn. It never accepts caller-supplied phase, index,
// participant or parent-head values.
func PrepareCandidateAllocationCheckpointV4(options CandidateAllocationCheckpointV4Options) (CandidateAllocationCheckpointV4, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return CandidateAllocationCheckpointV4{}, fmt.Errorf("attempt ID: %w", err)
	}
	if err := validateTimestamp("allocated_at", options.AllocatedAt); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	if stored.trusted.Definition.Schema != DefinitionSchemaV4 {
		_ = stored.reader.root.Close()
		return CandidateAllocationCheckpointV4{}, errors.New("candidate allocation requires definition v4")
	}
	previous := stored.ancestry.head
	d := stored.trusted.Definition
	if err := stored.reader.root.Close(); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}

	phase := Phase1
	state := previous.Progress.Phase1
	policy := d.Phase1Policy
	if previous.Progress.Phase1Closure != nil {
		if previous.Progress.Phase2 == nil || previous.Progress.Phase2Closure != nil {
			return CandidateAllocationCheckpointV4{}, errors.New("ceremony is not accepting contribution allocations")
		}
		phase = Phase2
		state = *previous.Progress.Phase2
		policy = d.Phase2Policy
	}
	index := int(state.AcceptedCount) + 1
	if index > len(policy.Participants) {
		return CandidateAllocationCheckpointV4{}, errors.New("signed participant schedule has no next contribution")
	}
	scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: uint8(index), ParticipantID: policy.Participants[index-1], ParentHeadID: state.HeadRecordID}
	if err := scope.ValidateAssignment(d); err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}

	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	next.PreviousCheckpoint = &options.Checkpoint
	next.Sequence++
	kind := CheckpointPhase1CandidateAllocated
	if phase == Phase2 {
		kind = CheckpointPhase2CandidateAllocated
	}
	next.Transition = CheckpointTransitionV4{Kind: kind, Scope: &scope, AttemptID: options.AttemptID, AllocatedAt: options.AllocatedAt, Evidence: []ArtifactRef{}}
	next.Deliveries, err = AllocateDeliveryV2(previous.Deliveries, scope, CheckpointSubmissionCandidate, options.AttemptID)
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next})
	if err != nil {
		return CandidateAllocationCheckpointV4{}, err
	}
	return CandidateAllocationCheckpointV4{Checkpoint: next, Scope: scope, Canonical: canonical}, nil
}

type AcceptAllocatedCandidateV4Options struct {
	Trust                     TrustPaths
	Circuit                   *CompiledCircuit
	ArtifactRoot              string
	Checkpoint                SignedArtifactRefs
	AttemptID                 string
	CandidateDir              string
	CoordinatorPrivateKeyPath string
	AcceptedAt                string
}

type AcceptedCandidateCheckpointV4 struct {
	Checkpoint CheckpointV4
	Scope      ContributionScope
	Candidate  CandidateInventory
	Accepted   AcceptContributionFilesResult
	Canonical  []byte
}

// VerifyAndAcceptAllocatedCandidateV4 authenticates the allocation, verifies
// the candidate mathematics, publishes immutable accepted artifacts, and
// prepares the exact next checkpoint. No phase, participant, index, or input
// chain path is accepted from the caller.
func VerifyAndAcceptAllocatedCandidateV4(options AcceptAllocatedCandidateV4Options) (AcceptedCandidateCheckpointV4, error) {
	if err := validateHex(options.AttemptID, 16); err != nil {
		return AcceptedCandidateCheckpointV4{}, fmt.Errorf("attempt ID: %w", err)
	}
	stored, err := openStoredCheckpointV4(options.Trust, options.ArtifactRoot, options.Checkpoint)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	if stored.trusted.Definition.Schema != DefinitionSchemaV4 {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate acceptance requires definition v4")
	}
	allocation, ok := stored.ancestry.allocations[options.AttemptID]
	if !ok || allocation.Scope == nil {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate attempt is not allocated by the authenticated checkpoint ancestry")
	}
	previous := stored.ancestry.head
	scope := *allocation.Scope
	active := false
	for _, slot := range previous.Deliveries {
		if slot.AttemptID == options.AttemptID && slot.Kind == CheckpointSubmissionCandidate && slot.Status == DeliveryAllocated && slot.Scope == scope {
			active = true
		}
	}
	if !active {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, errors.New("candidate allocation is no longer active at the authenticated checkpoint")
	}
	if err := previous.Progress.currentTurn(scope); err != nil {
		_ = stored.reader.root.Close()
		return AcceptedCandidateCheckpointV4{}, err
	}
	if err := stored.reader.root.Close(); err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}

	state := previous.Progress.Phase1
	if scope.Phase == Phase2 {
		state = *previous.Progress.Phase2
	}
	paths := PhaseTranscriptPaths{RootDir: options.ArtifactRoot, ChainPath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(state.Chain.Record.Name)), ChainSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(state.Chain.Signature.Name))}
	accept := AcceptContributionFilesOptions{Trust: options.Trust, Circuit: options.Circuit, Phase: scope.Phase, Transcript: paths, CandidateDir: options.CandidateDir, CoordinatorPrivateKeyPath: options.CoordinatorPrivateKeyPath, AcceptedAt: options.AcceptedAt}
	if scope.Phase == Phase2 {
		if previous.Progress.Phase1Seal == nil {
			return AcceptedCandidateCheckpointV4{}, errors.New("phase2 acceptance requires the authenticated phase1 seal")
		}
		accept.Phase1SealPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Progress.Phase1Seal.Record.Name))
		accept.Phase1SealSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Progress.Phase1Seal.Signature.Name))
	}
	accepted, err := VerifyAndAcceptContribution(accept)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	acceptedPaths := PhaseTranscriptPaths{RootDir: options.ArtifactRoot, ChainPath: accepted.ChainPath, ChainSignaturePath: accepted.ChainSignaturePath}
	var chain Chain
	var chainRefs SignedArtifactRefs
	if scope.Phase == Phase1 {
		chain, chainRefs, err = VerifyAcceptedPhase1Chain(options.Trust, options.Circuit, acceptedPaths)
	} else {
		chain, chainRefs, err = VerifyAcceptedPhase2Chain(options.Trust, options.Circuit, options.ArtifactRoot, accept.Phase1SealPath, accept.Phase1SealSignaturePath, acceptedPaths)
	}
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	last := chain.Records[len(chain.Records)-1]
	files := []ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	inventory := CandidateInventory{Schema: CandidateInventorySchemaV1, Scope: scope, Files: slices.Clone(files)}
	for i := range inventory.Files {
		inventory.Files[i].Name = filepath.Base(inventory.Files[i].Name)
	}
	if err := inventory.Validate(); err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	evidence := append(slices.Clone(files), last.Verification)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })

	next, err := cloneCheckpointForTurnV4(previous)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	next.PreviousCheckpoint = &options.Checkpoint
	next.Sequence++
	kind := CheckpointPhase1CandidateAccepted
	if scope.Phase == Phase2 {
		kind = CheckpointPhase2CandidateAccepted
	}
	next.Transition = CheckpointTransitionV4{Kind: kind, Scope: &scope, AttemptID: options.AttemptID, Record: &chainRefs, Evidence: evidence, Contribution: &inventory}
	next.Deliveries, err = AdvanceDeliveryV2(previous.Deliveries, options.AttemptID, DeliveryAccepted, &inventory)
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	payload, err := chain.HeadPayload()
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	nextState := CheckpointPhaseState{Phase: scope.Phase, AcceptedCount: scope.Index, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}
	if scope.Phase == Phase1 {
		next.Progress.Phase1 = nextState
	} else {
		next.Progress.Phase2 = &nextState
	}
	next.AcceptedArtifacts = appendUniqueSortedArtifactsV4(previous.AcceptedArtifacts, append(signedArtifacts(&chainRefs), evidence...)...)
	canonical, err := PrepareCheckpointV4(CheckpointPreparationV4{Trust: options.Trust, ArtifactRoot: options.ArtifactRoot, Proposal: next, Circuit: options.Circuit})
	if err != nil {
		return AcceptedCandidateCheckpointV4{}, err
	}
	return AcceptedCandidateCheckpointV4{Checkpoint: next, Scope: scope, Candidate: inventory, Accepted: accepted, Canonical: canonical}, nil
}

func cloneCheckpointForTurnV4(value CheckpointV4) (CheckpointV4, error) {
	data, err := MarshalCanonical(value)
	if err != nil {
		return CheckpointV4{}, err
	}
	var cloned CheckpointV4
	if err := UnmarshalCanonical(data, &cloned); err != nil {
		return CheckpointV4{}, err
	}
	return cloned, nil
}

func appendUniqueSortedArtifactsV4(base []ArtifactRef, values ...ArtifactRef) []ArtifactRef {
	result := slices.Clone(base)
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
