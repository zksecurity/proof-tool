package mpcceremony

import "errors"

// ComputationOutputInspectionV4 is the three-file result before cleanup signing.
// It is not a CandidateInventory and deliberately has no candidate result ID.
// It proves signatures and bytes, not mathematics, process exit or cleanup.
type ComputationOutputInspectionV4 struct {
	Scope       ContributionScope  `json:"scope"`
	Predecessor SignedArtifactRefs `json:"predecessor"`
	Files       []ArtifactRef      `json:"files"`
}

func InspectComputationOutputV4(trust TrustPaths, predecessor PhaseTranscriptPaths, expected ContributionScope, candidateDir string) (ComputationOutputInspectionV4, error) {
	var zero ComputationOutputInspectionV4
	trusted, err := LoadSignedDefinition(trust)
	if err != nil {
		return zero, err
	}
	d := trusted.Definition
	if d.Schema != DefinitionSchemaV4 {
		return zero, errors.New("computation output inspection requires definition v4")
	}
	if err := expected.ValidateAssignment(d); err != nil {
		return zero, err
	}
	chain, refs, err := LoadSignedChainExact(trusted, predecessor)
	if err != nil {
		return zero, err
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		return zero, err
	}
	if chain.Phase != expected.Phase || len(chain.Records)+1 != int(expected.Index) || head != expected.ParentHeadID {
		return zero, errors.New("signed predecessor differs from the exact expected turn")
	}
	r, err := openCheckpointReaderV4(candidateDir)
	if err != nil {
		return zero, err
	}
	defer r.root.Close()
	result, _, err := inspectComputationOutputV4(r, d, chain, expected)
	if err != nil {
		return zero, err
	}
	result.Predecessor = refs
	return result, nil
}

func inspectComputationOutputV4(r *checkpointReaderV4, d CeremonyDefinition, chain Chain, scope ContributionScope) (ComputationOutputInspectionV4, ContributionAttestation, error) {
	var zero ComputationOutputInspectionV4
	var attestation ContributionAttestation
	record, err := readLocalInventoryRecordV4(r, "attestation.json", maxSignedRecordBytes)
	if err != nil {
		return zero, attestation, err
	}
	signature, err := readLocalInventoryRecordV4(r, "attestation.sig", 4096)
	if err != nil {
		return zero, attestation, err
	}
	participant, ok := d.ParticipantByID(scope.ParticipantID)
	if !ok {
		return zero, attestation, errors.New("candidate participant is not scheduled")
	}
	key, err := identityPublicKey(participant.Identity)
	if err != nil {
		return zero, attestation, err
	}
	if err := VerifySignedRecord(record, signature, &attestation, participant.Identity.KeyID, key); err != nil {
		return zero, attestation, err
	}
	previous, err := chain.HeadPayload()
	if err != nil {
		return zero, attestation, err
	}
	if attestation.CeremonyID != scope.CeremonyID || attestation.Phase != scope.Phase || attestation.PhaseID != chain.PhaseID || attestation.Index != scope.Index || attestation.ParticipantID != scope.ParticipantID || attestation.ParticipantKeyID != participant.Identity.KeyID || attestation.PreviousAcceptanceID != scope.ParentHeadID || attestation.PreviousPayload != previous || attestation.OutputPayload.Name != contributionLogicalNames(scope.Phase, int(scope.Index)).Payload {
		return zero, attestation, errors.New("candidate attestation differs from the exact expected predecessor and participant")
	}
	if err := validateAttestationSoftwareBinding(d, attestation); err != nil {
		return zero, attestation, err
	}
	if err := validateContributionChronology(d, chain, attestation); err != nil {
		return zero, attestation, err
	}
	output := attestation.OutputPayload
	output.Name = "contribution.bin"
	if _, err := r.read(output, MaxArtifactSize, false); err != nil {
		return zero, attestation, err
	}
	return ComputationOutputInspectionV4{Scope: scope, Files: []ArtifactRef{{Name: "attestation.json", Digest: NewDigest(record)}, {Name: "attestation.sig", Digest: NewDigest(signature)}, output}}, attestation, nil
}
