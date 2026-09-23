package mpcceremony

import (
	"errors"
	"fmt"
	"math"

	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

// Phase2Loader returns a freshly decoded contribution by zero-based ordinal.
// File-oriented callers should implement it with the strict preflight reader.
type Phase2Loader func(index int) (*gnarkmpc.Phase2, error)

// InitializePhase2 deterministically derives the circuit-specific Phase 2
// genesis state from the exact compiled circuit and sealed Phase 1 commons.
func InitializePhase2(circuit *CompiledCircuit, commons *gnarkmpc.SrsCommons) (*gnarkmpc.Phase2, Phase2Shape, error) {
	owned, err := initializeOwnedPhase2(circuit, commons)
	if err != nil {
		return nil, Phase2Shape{}, err
	}
	return owned.genesis, owned.shape, nil
}

// This pair belongs to one invocation. Sealing consumes its evaluations because
// the returned keys retain their slices. Never cache or share this object.
type ownedPhase2Initialization struct {
	genesis     *gnarkmpc.Phase2
	shape       Phase2Shape
	evaluations *gnarkmpc.Phase2Evaluations
	commons     *gnarkmpc.SrsCommons
	consumed    bool
}

func initializeOwnedPhase2(circuit *CompiledCircuit, commons *gnarkmpc.SrsCommons) (*ownedPhase2Initialization, error) {
	if err := validatePhase2Inputs(circuit, commons); err != nil {
		return nil, err
	}

	initial := new(gnarkmpc.Phase2)
	var evaluations gnarkmpc.Phase2Evaluations
	if err := runGnarkMutation("initialize Phase 2", func() {
		evaluations = initial.Initialize(circuit.R1CS, commons)
	}); err != nil {
		return nil, err
	}
	shape, err := DerivePhase2Shape(initial)
	if err != nil {
		return nil, fmt.Errorf("derive initial Phase 2 shape: %w", err)
	}
	if shape.ChallengeLength != 0 {
		return nil, fmt.Errorf("initial Phase 2 challenge is %d bytes, want 0", shape.ChallengeLength)
	}
	if !equalPhase2Shape(shape, circuit.Binding.Phase2Shape) {
		return nil, fmt.Errorf(
			"initialized Phase 2 shape %+v does not match circuit binding %+v",
			shape,
			circuit.Binding.Phase2Shape,
		)
	}
	return &ownedPhase2Initialization{genesis: initial, shape: shape, evaluations: &evaluations, commons: commons}, nil
}

// DerivePhase2Shape returns the serialization/preflight shape of a Phase 2
// object. It rejects inconsistent or non-representable slice lengths before
// they can be used as trusted preflight limits.
func DerivePhase2Shape(phase2 *gnarkmpc.Phase2) (Phase2Shape, error) {
	if phase2 == nil {
		return Phase2Shape{}, errors.New("Phase 2 object is required")
	}

	commitments := len(phase2.Parameters.G2.Sigma)
	if commitments > int(MaxPhase2Commitments) {
		return Phase2Shape{}, fmt.Errorf("Phase 2 commitments %d exceed %d", commitments, MaxPhase2Commitments)
	}
	if len(phase2.Parameters.G1.SigmaCKK) != commitments {
		return Phase2Shape{}, fmt.Errorf(
			"Phase 2 SigmaCKK count %d does not match Sigma count %d",
			len(phase2.Parameters.G1.SigmaCKK),
			commitments,
		)
	}
	if len(phase2.Sigmas) != commitments {
		return Phase2Shape{}, fmt.Errorf(
			"Phase 2 update-proof count %d does not match commitment count %d",
			len(phase2.Sigmas),
			commitments,
		)
	}
	if len(phase2.Parameters.G1.PKK) > math.MaxUint32 {
		return Phase2Shape{}, fmt.Errorf("Phase 2 PKK length %d exceeds uint32", len(phase2.Parameters.G1.PKK))
	}
	if len(phase2.Parameters.G1.Z) > math.MaxUint32 {
		return Phase2Shape{}, fmt.Errorf("Phase 2 Z length %d exceeds uint32", len(phase2.Parameters.G1.Z))
	}
	if len(phase2.Challenge) > math.MaxUint8 {
		return Phase2Shape{}, fmt.Errorf("Phase 2 challenge length %d exceeds uint8", len(phase2.Challenge))
	}

	shape := Phase2Shape{
		Commitments:     uint16(commitments),
		PKK:             uint32(len(phase2.Parameters.G1.PKK)),
		Z:               uint32(len(phase2.Parameters.G1.Z)),
		SigmaCKK:        make([]uint32, commitments),
		ChallengeLength: uint8(len(phase2.Challenge)),
	}
	for i := range phase2.Parameters.G1.SigmaCKK {
		if len(phase2.Parameters.G1.SigmaCKK[i]) > math.MaxUint32 {
			return Phase2Shape{}, fmt.Errorf(
				"Phase 2 SigmaCKK[%d] length %d exceeds uint32",
				i,
				len(phase2.Parameters.G1.SigmaCKK[i]),
			)
		}
		shape.SigmaCKK[i] = uint32(len(phase2.Parameters.G1.SigmaCKK[i]))
	}
	if err := shape.Validate(); err != nil {
		return Phase2Shape{}, fmt.Errorf("Phase 2 shape: %w", err)
	}
	return shape, nil
}

// ReplayPhase2 deterministically initializes Phase 2 and verifies every
// contribution in order. Supplied contribution objects are never mutated.
func ReplayPhase2(circuit *CompiledCircuit, commons *gnarkmpc.SrsCommons, contributions []*gnarkmpc.Phase2) error {
	_, _, err := replayPhase2State(circuit, commons, len(contributions), phase2SliceLoader(contributions))
	return err
}

// ReplayPhase2Loaded is the streaming-loader form of ReplayPhase2.
func ReplayPhase2Loaded(
	circuit *CompiledCircuit,
	commons *gnarkmpc.SrsCommons,
	contributionCount int,
	load Phase2Loader,
) error {
	_, _, err := replayPhase2State(circuit, commons, contributionCount, load)
	return err
}

// ContributePhase2 verifies the complete Phase 2 chain and returns a fresh
// contribution derived from its head. Neither the archived chain nor the
// sealed Phase 1 commons is mutated.
func ContributePhase2(circuit *CompiledCircuit, commons *gnarkmpc.SrsCommons, contributions []*gnarkmpc.Phase2) (*gnarkmpc.Phase2, error) {
	return ContributePhase2Loaded(circuit, commons, len(contributions), phase2SliceLoader(contributions))
}

// ContributePhase2Loaded is the streaming-loader form of ContributePhase2.
func ContributePhase2Loaded(
	circuit *CompiledCircuit,
	commons *gnarkmpc.SrsCommons,
	contributionCount int,
	load Phase2Loader,
) (*gnarkmpc.Phase2, error) {
	head, _, err := replayPhase2State(circuit, commons, contributionCount, load)
	if err != nil {
		return nil, err
	}

	return contributePhase2FromHead(head)
}

func contributePhase2FromVerifiedGenesis(genesis *gnarkmpc.Phase2, shape Phase2Shape, count int, load Phase2Loader) (*gnarkmpc.Phase2, error) {
	head, err := replayPhase2FromVerifiedGenesis(genesis, shape, count, load)
	if err != nil {
		return nil, err
	}
	return contributePhase2FromHead(head)
}

func contributePhase2FromHead(head *gnarkmpc.Phase2) (*gnarkmpc.Phase2, error) {
	if head == nil {
		return nil, errors.New("Phase 2 head is required")
	}
	digest, err := writerDigest(head)
	if err != nil {
		return nil, err
	}
	return contributePhase2FromAuthenticatedHead(head, digest)
}

func contributePhase2FromAuthenticatedHead(head *gnarkmpc.Phase2, predecessor Digest, progress ...StageProgress) (*gnarkmpc.Phase2, error) {
	if head == nil {
		return nil, errors.New("authenticated Phase 2 head is required")
	}
	next := new(gnarkmpc.Phase2)
	if err := streamClone(head, next); err != nil {
		return nil, fmt.Errorf("clone Phase 2 head: %w", err)
	}
	if len(progress) > 0 && progress[0] != nil {
		progress[0]("Creating your contribution", 3, 5)
	}
	if err := runGnarkMutation("Phase 2 contribution", next.Contribute); err != nil {
		return nil, err
	}
	if len(progress) > 0 && progress[0] != nil {
		progress[0]("Checking your contribution", 4, 5)
	}
	if err := requireContributionChallenge(next.Challenge, "new Phase 2 contribution"); err != nil {
		return nil, err
	}
	if err := requireChallengeMatchesDigest(next.Challenge, predecessor); err != nil {
		return nil, fmt.Errorf("generated Phase 2 challenge: %w", err)
	}
	if err := requireSamePhase2Structure(head, next); err != nil {
		return nil, fmt.Errorf("new Phase 2 contribution shape: %w", err)
	}
	check := new(gnarkmpc.Phase2)
	if err := streamClone(next, check); err != nil {
		return nil, fmt.Errorf("decode generated Phase 2 contribution: %w", err)
	}
	if err := verifyPhase2Transition(head, check); err != nil {
		return nil, fmt.Errorf("verify new Phase 2 contribution: %w", err)
	}
	return next, nil
}

// SealPhase2 verifies the complete chain, applies an exact 32-byte public
// beacon to a private clone of its head, and returns native gnark BLS12-381
// proving and verifying keys.
func SealPhase2(
	circuit *CompiledCircuit,
	commons *gnarkmpc.SrsCommons,
	beaconChallenge []byte,
	contributions []*gnarkmpc.Phase2,
) (*groth16bls.ProvingKey, *groth16bls.VerifyingKey, error) {
	return SealPhase2Loaded(
		circuit,
		commons,
		beaconChallenge,
		len(contributions),
		phase2SliceLoader(contributions),
	)
}

// SealPhase2Loaded is the streaming-loader form of SealPhase2.
func SealPhase2Loaded(
	circuit *CompiledCircuit,
	commons *gnarkmpc.SrsCommons,
	beaconChallenge []byte,
	contributionCount int,
	load Phase2Loader,
) (*groth16bls.ProvingKey, *groth16bls.VerifyingKey, error) {
	if err := requireBeaconChallenge(beaconChallenge); err != nil {
		return nil, nil, err
	}
	if contributionCount == 0 {
		return nil, nil, errors.New("seal Phase 2: at least one contribution is required")
	}

	head, evaluations, err := replayPhase2State(circuit, commons, contributionCount, load)
	if err != nil {
		return nil, nil, err
	}

	return sealPhase2Head(head, commons, evaluations, beaconChallenge)
}

func sealOwnedPhase2(owned *ownedPhase2Initialization, beaconChallenge []byte, count int, load Phase2Loader) (*groth16bls.ProvingKey, *groth16bls.VerifyingKey, error) {
	if err := requireBeaconChallenge(beaconChallenge); err != nil {
		return nil, nil, err
	}
	if count <= 0 || load == nil {
		return nil, nil, errors.New("seal Phase 2 requires contributions and a loader")
	}
	if owned == nil || owned.consumed || owned.evaluations == nil {
		return nil, nil, errors.New("Phase 2 initialization is missing or already consumed")
	}
	owned.consumed = true
	evaluations := owned.evaluations
	owned.evaluations = nil
	head, err := replayPhase2FromVerifiedGenesis(owned.genesis, owned.shape, count, load)
	if err != nil {
		return nil, nil, err
	}
	return sealPhase2Head(head, owned.commons, evaluations, beaconChallenge)
}

func sealPhase2Head(head *gnarkmpc.Phase2, commons *gnarkmpc.SrsCommons, evaluations *gnarkmpc.Phase2Evaluations, beaconChallenge []byte) (*groth16bls.ProvingKey, *groth16bls.VerifyingKey, error) {
	// Seal does not copy the evaluations: the returned proving and verifying
	// keys retain evals.G1.CKK and evals.G1.VKK directly. The evaluations must
	// therefore stay per-call and must never be cached or shared between
	// seals, or two key sets would alias one set of commitment arrays.
	var provingKey, verifyingKey any
	if err := runGnarkMutation("seal Phase 2", func() {
		provingKey, verifyingKey = head.Seal(commons, evaluations, append([]byte(nil), beaconChallenge...))
	}); err != nil {
		return nil, nil, err
	}
	nativePK, ok := provingKey.(*groth16bls.ProvingKey)
	if !ok {
		return nil, nil, fmt.Errorf("seal Phase 2 proving key type is %T, want *bls12-381.ProvingKey", provingKey)
	}
	nativeVK, ok := verifyingKey.(*groth16bls.VerifyingKey)
	if !ok {
		return nil, nil, fmt.Errorf("seal Phase 2 verifying key type is %T, want *bls12-381.VerifyingKey", verifyingKey)
	}
	return nativePK, nativeVK, nil
}

func replayPhase2State(
	circuit *CompiledCircuit,
	commons *gnarkmpc.SrsCommons,
	contributionCount int,
	load Phase2Loader,
) (*gnarkmpc.Phase2, *gnarkmpc.Phase2Evaluations, error) {
	if err := validatePhase2Inputs(circuit, commons); err != nil {
		return nil, nil, err
	}
	if contributionCount < 0 {
		return nil, nil, fmt.Errorf("replay Phase 2: contribution count %d is negative", contributionCount)
	}
	if contributionCount > 0 && load == nil {
		return nil, nil, errors.New("replay Phase 2: contribution loader is required")
	}

	previous := new(gnarkmpc.Phase2)
	var evaluations gnarkmpc.Phase2Evaluations
	if err := runGnarkMutation("initialize Phase 2", func() {
		evaluations = previous.Initialize(circuit.R1CS, commons)
	}); err != nil {
		return nil, nil, err
	}
	initialShape, err := DerivePhase2Shape(previous)
	if err != nil {
		return nil, nil, fmt.Errorf("derive initial Phase 2 shape: %w", err)
	}
	if !equalPhase2Shape(initialShape, circuit.Binding.Phase2Shape) {
		return nil, nil, errors.New("initialized Phase 2 shape does not match circuit binding")
	}

	head, err := replayPhase2FromVerifiedGenesis(previous, circuit.Binding.Phase2Shape, contributionCount, load)
	if err != nil {
		return nil, nil, err
	}
	// Each replay owns fresh evaluations. Seal retains their commitment slices,
	// so evaluations must never be shared between independently produced keys.
	return head, &evaluations, nil
}

// replayPhase2FromVerifiedGenesis consumes a freshly derived genesis from the
// current verification call. Callers must establish deterministic initialization;
// this helper does not authenticate a stored genesis or authorize cached state.
// Every archived contribution is cloned and mathematically verified.
func replayPhase2FromVerifiedGenesis(previous *gnarkmpc.Phase2, expectedShape Phase2Shape, contributionCount int, load Phase2Loader) (*gnarkmpc.Phase2, error) {
	if contributionCount < 0 {
		return nil, fmt.Errorf("replay Phase 2: contribution count %d is negative", contributionCount)
	}
	if contributionCount > 0 && load == nil {
		return nil, errors.New("replay Phase 2: contribution loader is required")
	}
	initialShape, err := DerivePhase2Shape(previous)
	if err != nil {
		return nil, fmt.Errorf("derive initial Phase 2 shape: %w", err)
	}
	if initialShape.ChallengeLength != 0 || !equalPhase2Shape(initialShape, expectedShape) {
		return nil, errors.New("verified Phase 2 genesis shape or challenge differs from circuit binding")
	}
	for i := 0; i < contributionCount; i++ {
		archived, err := load(i)
		if err != nil {
			return nil, fmt.Errorf("load Phase 2 contribution %d: %w", i+1, err)
		}
		if archived == nil {
			return nil, fmt.Errorf("replay Phase 2 contribution %d: nil contribution", i+1)
		}
		if err := requireContributionChallenge(archived.Challenge, fmt.Sprintf("Phase 2 contribution %d", i+1)); err != nil {
			return nil, err
		}

		next := new(gnarkmpc.Phase2)
		if err := streamClone(archived, next); err != nil {
			return nil, fmt.Errorf("clone Phase 2 contribution %d: %w", i+1, err)
		}
		if err := requirePhase2Structure(initialShape, next); err != nil {
			return nil, fmt.Errorf("Phase 2 contribution %d shape: %w", i+1, err)
		}
		if err := verifyPhase2Transition(previous, next); err != nil {
			return nil, fmt.Errorf("verify Phase 2 contribution %d: %w", i+1, err)
		}
		previous = next
	}
	return previous, nil
}

func verifyPhase2Transition(previous, next *gnarkmpc.Phase2) error {
	if previous == nil || next == nil {
		return errors.New("Phase 2 transition requires previous and next states")
	}
	if err := requireContributionChallenge(next.Challenge, "Phase 2 transition"); err != nil {
		return err
	}
	if err := requireSamePhase2Structure(previous, next); err != nil {
		return err
	}
	return runGnarkVerification(
		"verify Phase 2 transition",
		func() error { return previous.Verify(next) },
	)
}

func phase2SliceLoader(contributions []*gnarkmpc.Phase2) Phase2Loader {
	return func(index int) (*gnarkmpc.Phase2, error) {
		if index < 0 || index >= len(contributions) {
			return nil, fmt.Errorf("contribution index %d outside [0,%d)", index, len(contributions))
		}
		return contributions[index], nil
	}
}

func validatePhase2Inputs(circuit *CompiledCircuit, commons *gnarkmpc.SrsCommons) error {
	if err := validateCompiledCircuit(circuit); err != nil {
		return err
	}
	if commons == nil {
		return errors.New("sealed Phase 1 commons are required")
	}
	if err := validateDomainN(circuit.Binding.DomainSize); err != nil {
		return fmt.Errorf("compiled circuit domain: %w", err)
	}
	if err := validateCommonsDomain(commons, circuit.Binding.DomainSize); err != nil {
		return fmt.Errorf("sealed Phase 1 commons: %w", err)
	}
	return nil
}

func requireSamePhase2Structure(previous, next *gnarkmpc.Phase2) error {
	expected, err := DerivePhase2Shape(previous)
	if err != nil {
		return err
	}
	return requirePhase2Structure(expected, next)
}

func requirePhase2Structure(expected Phase2Shape, actual *gnarkmpc.Phase2) error {
	got, err := DerivePhase2Shape(actual)
	if err != nil {
		return err
	}
	// Contributions have a 32-byte challenge while genesis has none. The
	// remaining fields must be exactly invariant across the phase.
	gotChallengeLength := got.ChallengeLength
	got.ChallengeLength = expected.ChallengeLength
	if got.Commitments != expected.Commitments ||
		got.PKK != expected.PKK ||
		got.Z != expected.Z ||
		len(got.SigmaCKK) != len(expected.SigmaCKK) {
		return fmt.Errorf("got %+v, want structure %+v (challenge length %d)", got, expected, gotChallengeLength)
	}
	for i := range got.SigmaCKK {
		if got.SigmaCKK[i] != expected.SigmaCKK[i] {
			return fmt.Errorf(
				"SigmaCKK[%d] length %d, want %d",
				i,
				got.SigmaCKK[i],
				expected.SigmaCKK[i],
			)
		}
	}
	return nil
}
