package mpcceremony

import (
	"errors"
	"fmt"
	"path/filepath"

	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

func authenticatedPhase1Head(root string, chain Chain, domainN uint64, canonical *gnarkmpc.Phase1) (*gnarkmpc.Phase1, Digest, error) {
	ref, err := chain.HeadPayload()
	if err != nil {
		return nil, Digest{}, err
	}
	if len(chain.Records) == 0 {
		return canonical, ref.Digest, nil
	}
	path, err := resolveArtifactPath(root, ref.Name)
	if err != nil {
		return nil, Digest{}, err
	}
	head, digest, err := ReadPhase1File(path, Phase1Shape{DomainN: domainN, ChallengeLength: contributionChallengeSize})
	if err != nil {
		return nil, Digest{}, err
	}
	if modelDigest(digest) != ref.Digest {
		return nil, Digest{}, errors.New("assigned Phase 1 head differs from signed payload")
	}
	return head, ref.Digest, nil
}

func authenticatedPhase2Head(root string, chain Chain, baseShape Phase2Shape) (*gnarkmpc.Phase2, Digest, error) {
	ref, err := chain.HeadPayload()
	if err != nil {
		return nil, Digest{}, err
	}
	shape := baseShape
	if len(chain.Records) > 0 {
		shape = contributionPhase2Shape(baseShape)
	}
	path, err := resolveArtifactPath(root, ref.Name)
	if err != nil {
		return nil, Digest{}, err
	}
	head, digest, err := ReadPhase2File(path, shape)
	if err != nil {
		return nil, Digest{}, err
	}
	if modelDigest(digest) != ref.Digest {
		return nil, Digest{}, errors.New("assigned Phase 2 head differs from signed payload")
	}
	return head, ref.Digest, nil
}

func authenticateParticipantPhase1Seal(trusted *TrustedCeremony, circuit *CompiledCircuit, root string, assignment authenticatedContributionAssignment, sealPath, sealSignaturePath string) error {
	paths := PhaseTranscriptPaths{RootDir: root, ChainPath: filepath.Join(root, assignment.phase1Chain.Record.Name), ChainSignaturePath: filepath.Join(root, assignment.phase1Chain.Signature.Name)}
	chain, refs, err := loadVerifiedPhase1FilesExact(trusted, circuit, paths)
	if err != nil {
		return fmt.Errorf("authenticate Phase 1 acceptance history: %w", err)
	}
	if refs != assignment.phase1Chain {
		return errors.New("Phase 1 history differs from authenticated checkpoint")
	}
	if err := requireArtifactPath(root, sealPath, assignment.phase1Seal.Record); err != nil {
		return err
	}
	if err := requireArtifactPath(root, sealSignaturePath, assignment.phase1Seal.Signature); err != nil {
		return err
	}
	if _, err := verifyArtifactBytes(root, assignment.phase1Seal.Record, maxSignedRecordBytes); err != nil {
		return err
	}
	if _, err := verifyArtifactBytes(root, assignment.phase1Seal.Signature, maxSignedRecordBytes); err != nil {
		return err
	}
	_, seal, closeRecord, err := loadAuthenticatedPhase1CommonsForCoordinator(trusted, circuit, root, sealPath, sealSignaturePath)
	if err != nil {
		return err
	}
	if err := ValidateClose(trusted.Definition, chain, closeRecord); err != nil {
		return fmt.Errorf("Phase 1 closure differs from accepted history: %w", err)
	}
	if seal.CeremonyID != trusted.Definition.CeremonyID {
		return errors.New("Phase 1 seal differs from assigned ceremony")
	}
	refs, err = signedArtifactRefsAtPaths(root, sealPath, sealSignaturePath)
	if err != nil {
		return err
	}
	if refs != assignment.phase1Seal {
		return errors.New("Phase 1 seal changed after authenticated checkpoint capture")
	}
	return nil
}

func signedArtifactRefsAtPaths(root, recordPath, signaturePath string) (SignedArtifactRefs, error) {
	var refs SignedArtifactRefs
	for index, path := range []string{recordPath, signaturePath} {
		name, err := logicalPathWithin(root, path)
		if err != nil {
			return SignedArtifactRefs{}, err
		}
		data, err := readRegularBounded(path, maxSignedRecordBytes)
		if err != nil {
			return SignedArtifactRefs{}, err
		}
		ref := ArtifactRef{Name: name, Digest: NewDigest(data)}
		if index == 0 {
			refs.Record = ref
		} else {
			refs.Signature = ref
		}
	}
	return refs, nil
}

func loadAcceptedPhase2FilesExact(trusted *TrustedCeremony, circuit *CompiledCircuit, sealRefs SignedArtifactRefs, paths PhaseTranscriptPaths) (Chain, SignedArtifactRefs, error) {
	if err := validateWorkflowCircuit(trusted, circuit); err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	sealBytes, err := verifyArtifactBytes(paths.RootDir, sealRefs.Record, maxSignedRecordBytes)
	if err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	sigBytes, err := verifyArtifactBytes(paths.RootDir, sealRefs.Signature, maxSignedRecordBytes)
	if err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	var seal SealRecord
	if err := VerifySignedRecord(sealBytes, sigBytes, &seal, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	if seal.Phase != Phase1 || seal.CeremonyID != trusted.Definition.CeremonyID {
		return Chain{}, SignedArtifactRefs{}, errors.New("assigned Phase 1 seal is for a different ceremony")
	}
	chain, refs, err := LoadSignedChainExact(trusted, paths)
	if err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	if chain.Phase != Phase2 {
		return Chain{}, SignedArtifactRefs{}, errors.New("assigned chain is not Phase 2")
	}
	phaseID, err := ComputePhaseID(trusted.Definition.CeremonyID, Phase2, chain.Genesis, seal.SealID)
	if err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	if chain.PhaseID != phaseID {
		return Chain{}, SignedArtifactRefs{}, errors.New("Phase 2 chain does not bind the assigned Phase 1 seal")
	}
	if err := verifyChainFiles(trusted, paths.RootDir, chain, circuit.Binding.Phase2Shape); err != nil {
		return Chain{}, SignedArtifactRefs{}, err
	}
	return chain, refs, nil
}
