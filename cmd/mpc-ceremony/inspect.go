// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"proof-tool/internal/mpcceremony"
)

const (
	definitionInspectionSchema  = "proof-tool-mpc-definition-inspection-v1"
	chainInspectionSchema       = "proof-tool-mpc-chain-inspection-v1"
	participantInspectionSchema = "proof-tool-mpc-participant-inspection-v1"
	enrollmentInspectionSchema  = "proof-tool-mpc-enrollment-inspection-v1"
)

func executeInspectDefinition(options InspectDefinitionOptions) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(options)
	if err != nil {
		return CommandResult{}, err
	}
	inspection := inspectDefinition(trusted.Definition)
	return CommandResult{
		CeremonyID:           trusted.Definition.CeremonyID,
		Summary:              "authenticated ceremony definition",
		DefinitionInspection: &inspection,
	}, nil
}

func executeInspectChain(options InspectChainOptions) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	chain, err := mpcceremony.LoadSignedChain(trusted, mpcceremony.PhaseTranscriptPaths{
		RootDir:            options.TranscriptRoot,
		ChainPath:          options.ChainPath,
		ChainSignaturePath: options.ChainSignaturePath,
	})
	if err != nil {
		return CommandResult{}, err
	}
	inspection := inspectChain(chain)
	return CommandResult{
		CeremonyID:      chain.CeremonyID,
		Phase:           string(chain.Phase),
		Sequence:        len(chain.Records),
		Summary:         fmt.Sprintf("authenticated %s chain with %d accepted contributions", chain.Phase, len(chain.Records)),
		ChainInspection: &inspection,
	}, nil
}

func executeInspectParticipant(options InspectParticipantOptions) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	match, err := mpcceremony.InspectParticipantSigningKey(
		trusted.Definition,
		options.ParticipantSigningKey,
	)
	if err != nil {
		return CommandResult{}, fmt.Errorf("participant signing key: %w", err)
	}
	inspection := ParticipantInspection{
		Schema:               participantInspectionSchema,
		CeremonyID:           trusted.Definition.CeremonyID,
		ParticipantID:        match.ParticipantID,
		KeyID:                match.KeyID,
		PublicKeyFingerprint: match.PublicKeyFingerprint,
		Phase1Position:       cloneUint8Pointer(match.Phase1Position),
		Phase2Position:       cloneUint8Pointer(match.Phase2Position),
	}
	return CommandResult{
		CeremonyID:            trusted.Definition.CeremonyID,
		Summary:               "matched existing signing key to authenticated participant roster",
		ParticipantInspection: &inspection,
	}, nil
}

func executeInspectEnrollment(options InspectEnrollmentOptions) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	recordBytes, err := readRegularOperationalFile(options.EnrollmentPath, maxOperationalRecordBytes)
	if err != nil {
		return CommandResult{}, err
	}
	signatureBytes, err := readRegularOperationalFile(options.EnrollmentSignaturePath, 4096)
	if err != nil {
		return CommandResult{}, err
	}
	definitionBytes, err := canonicalDefinition(trusted)
	if err != nil {
		return CommandResult{}, err
	}
	enrollment, err := mpcceremony.VerifyEnrollmentProofOfPossession(
		trusted.Definition,
		definitionBytes,
		recordBytes,
		signatureBytes,
	)
	if err != nil {
		return CommandResult{}, fmt.Errorf("enrollment proof of possession: %w", err)
	}
	inspection := EnrollmentInspection{
		Schema:                 enrollmentInspectionSchema,
		CeremonyID:             enrollment.CeremonyID,
		Identity:               enrollment.Identity,
		Role:                   enrollment.Role,
		RoleIndex:              enrollment.RoleIndex,
		EnrolledAt:             enrollment.EnrolledAt,
		IndependenceDisclosure: enrollment.IndependenceDisclosure,
	}
	return CommandResult{
		CeremonyID:           enrollment.CeremonyID,
		Summary:              "authenticated operational enrollment and proof of possession",
		EnrollmentInspection: &inspection,
	}, nil
}

func cloneUint8Pointer(value *uint8) *uint8 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func loadInspectionCeremony(options InspectDefinitionOptions) (*mpcceremony.TrustedCeremony, error) {
	return mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{
		DefinitionPath:           options.CeremonyPath,
		DefinitionSignaturePath:  options.CeremonySignaturePath,
		CoordinatorPublicKeyPath: options.CoordinatorPublicKeyFile,
	})
}

func inspectDefinition(definition mpcceremony.CeremonyDefinition) DefinitionInspection {
	return DefinitionInspection{
		Schema:             definitionInspectionSchema,
		CeremonyID:         definition.CeremonyID,
		Mode:               definition.Mode,
		Phase1Participants: append([]string(nil), definition.Phase1Policy.Participants...),
		Phase2Participants: append([]string(nil), definition.Phase2Policy.Participants...),
		R1CS:               definition.Circuit.R1CS,
	}
}

func inspectChain(chain mpcceremony.Chain) ChainInspection {
	artifacts := make([]mpcceremony.ArtifactRef, 0, 1+6*len(chain.Records))
	artifacts = append(artifacts, chain.Genesis)
	records := make([]ChainRecordInspection, 0, len(chain.Records))
	for _, record := range chain.Records {
		recordArtifacts := []mpcceremony.ArtifactRef{
			record.OutputPayload,
			record.Attestation,
			record.AttestationSignature,
			record.Erasure,
			record.ErasureSignature,
			record.Verification,
		}
		artifacts = append(artifacts, recordArtifacts...)
		records = append(records, ChainRecordInspection{
			Index:         record.Index,
			RecordID:      record.RecordID,
			ParticipantID: record.ParticipantID,
			Artifacts:     recordArtifacts,
		})
	}
	return ChainInspection{
		Schema:        chainInspectionSchema,
		CeremonyID:    chain.CeremonyID,
		Phase:         chain.Phase,
		AcceptedCount: len(chain.Records),
		Artifacts:     artifacts,
		Records:       records,
	}
}
