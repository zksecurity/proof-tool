// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"proof-tool/internal/mpcceremony"
)

const (
	definitionInspectionSchema                = "proof-tool-mpc-definition-inspection-v1"
	chainInspectionSchema                     = "proof-tool-mpc-chain-inspection-v1"
	participantInspectionSchema               = "proof-tool-mpc-participant-inspection-v1"
	enrollmentInspectionSchema                = "proof-tool-mpc-enrollment-inspection-v1"
	checkpointInspectionSchema                = "proof-tool-mpc-checkpoint-inspection-v1"
	checkpointTransitionInspectionSchema      = "proof-tool-mpc-checkpoint-transition-inspection-v1"
	submissionInspectionSchema                = "proof-tool-mpc-submission-inspection-v1"
	submissionAcknowledgementInspectionSchema = "proof-tool-mpc-submission-acknowledgement-inspection-v1"
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

func executeInspectCheckpoint(options InspectCheckpointOptions) (CommandResult, error) {
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	checkpoint, checkpointBytes, _, err := loadInspectionCheckpoint(
		trusted.Definition,
		definitionBytes,
		definitionSignatureBytes,
		options.CheckpointPath,
		options.CheckpointSignaturePath,
	)
	if err != nil {
		return CommandResult{}, err
	}
	inspection := inspectCheckpoint(checkpoint, checkpointBytes)
	return CommandResult{
		CeremonyID:           checkpoint.CeremonyID,
		Summary:              fmt.Sprintf("authenticated checkpoint %d; referenced protocol artifacts were not replayed", checkpoint.Sequence),
		CheckpointInspection: &inspection,
	}, nil
}

func executeInspectCheckpointTransition(options InspectCheckpointTransitionOptions) (CommandResult, error) {
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	previous, previousBytes, previousSignatureBytes, err := loadInspectionCheckpoint(
		trusted.Definition,
		definitionBytes,
		definitionSignatureBytes,
		options.PreviousCheckpointPath,
		options.PreviousCheckpointSignaturePath,
	)
	if err != nil {
		return CommandResult{}, fmt.Errorf("previous checkpoint: %w", err)
	}
	next, nextBytes, _, err := loadInspectionCheckpoint(
		trusted.Definition,
		definitionBytes,
		definitionSignatureBytes,
		options.CheckpointPath,
		options.CheckpointSignaturePath,
	)
	if err != nil {
		return CommandResult{}, fmt.Errorf("next checkpoint: %w", err)
	}
	if err := mpcceremony.ValidateCheckpointTransition(previous, next); err != nil {
		return CommandResult{}, fmt.Errorf("checkpoint transition: %w", err)
	}
	previousSignatureDigest := mpcceremony.NewDigest(previousSignatureBytes)
	if next.PreviousCheckpoint == nil || next.PreviousCheckpoint.Signature.Digest != previousSignatureDigest {
		return CommandResult{}, fmt.Errorf("checkpoint transition: next checkpoint does not bind the exact previous checkpoint signature")
	}
	checkpointInspection := inspectCheckpoint(next, nextBytes)
	inspection := CheckpointTransitionInspection{
		Schema:                   checkpointTransitionInspectionSchema,
		CeremonyID:               next.CeremonyID,
		PreviousSequence:         previous.Sequence,
		Sequence:                 next.Sequence,
		PreviousCheckpointDigest: mpcceremony.NewDigest(previousBytes),
		PreviousSignatureDigest:  previousSignatureDigest,
		CheckpointDigest:         mpcceremony.NewDigest(nextBytes),
		Transition:               next.Transition,
		Checkpoint:               checkpointInspection,
	}
	return CommandResult{
		CeremonyID:                     next.CeremonyID,
		Summary:                        fmt.Sprintf("authenticated legal checkpoint transition %d to %d; referenced protocol artifacts were not replayed", previous.Sequence, next.Sequence),
		CheckpointTransitionInspection: &inspection,
	}, nil
}

func executeInspectSubmission(options InspectSubmissionOptions) (CommandResult, error) {
	trusted, checkpoint, slot, envelope, envelopeBytes, envelopeSignatureBytes, manifestBytes, err := loadInspectionSubmission(options)
	if err != nil {
		return CommandResult{}, err
	}
	_ = checkpoint
	inspection := inspectSubmission(envelope, envelopeBytes, envelopeSignatureBytes, manifestBytes)
	return CommandResult{
		CeremonyID:           trusted.Definition.CeremonyID,
		Summary:              fmt.Sprintf("authenticated %s submission for phase1 index %d and its exact allocated slot", slot.Kind, slot.Index),
		SubmissionInspection: &inspection,
	}, nil
}

func executeInspectSubmissionAcknowledgement(options InspectSubmissionAcknowledgementOptions) (CommandResult, error) {
	trusted, checkpoint, slot, envelope, envelopeBytes, envelopeSignatureBytes, manifestBytes, err := loadInspectionSubmission(options.InspectSubmissionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	acknowledgementBytes, err := readRegularOperationalFile(options.AcknowledgementPath, maxOperationalRecordBytes)
	if err != nil {
		return CommandResult{}, err
	}
	acknowledgementSignatureBytes, err := readRegularOperationalFile(options.AcknowledgementSignaturePath, 4096)
	if err != nil {
		return CommandResult{}, err
	}
	acknowledgement, err := mpcceremony.VerifySignedSubmissionAcknowledgement(
		trusted.Definition, checkpoint, slot,
		envelope.ManifestKey+".envelope.json", envelope.ManifestKey+".envelope.sig",
		envelopeBytes, envelopeSignatureBytes, envelope.ManifestKey, manifestBytes,
		acknowledgementBytes, acknowledgementSignatureBytes,
	)
	if err != nil {
		// The acknowledgement commits the actual logical envelope names. Retry
		// with those authenticated names rather than guessing from local paths.
		var parsed mpcceremony.SubmissionAcknowledgementV1
		if parseErr := mpcceremony.UnmarshalCanonical(acknowledgementBytes, &parsed); parseErr != nil {
			return CommandResult{}, err
		}
		acknowledgement, err = mpcceremony.VerifySignedSubmissionAcknowledgement(
			trusted.Definition, checkpoint, slot,
			parsed.Envelope.Record.Name, parsed.Envelope.Signature.Name,
			envelopeBytes, envelopeSignatureBytes, envelope.ManifestKey, manifestBytes,
			acknowledgementBytes, acknowledgementSignatureBytes,
		)
		if err != nil {
			return CommandResult{}, err
		}
	}
	submission := inspectSubmission(envelope, envelopeBytes, envelopeSignatureBytes, manifestBytes)
	inspection := SubmissionAcknowledgementInspection{
		Schema: submissionAcknowledgementInspectionSchema, Submission: submission,
		CoordinatorID: acknowledgement.CoordinatorID, CoordinatorKeyID: acknowledgement.CoordinatorKeyID,
		Result: acknowledgement.Result, ReasonCode: acknowledgement.ReasonCode,
		AcknowledgementDigest:          mpcceremony.NewDigest(acknowledgementBytes),
		AcknowledgementSignatureDigest: mpcceremony.NewDigest(acknowledgementSignatureBytes),
	}
	return CommandResult{
		CeremonyID:                          trusted.Definition.CeremonyID,
		Summary:                             fmt.Sprintf("authenticated coordinator %s acknowledgement for exact submission attempt", acknowledgement.Result),
		SubmissionAcknowledgementInspection: &inspection,
	}, nil
}

func loadInspectionSubmission(options InspectSubmissionOptions) (*mpcceremony.TrustedCeremony, mpcceremony.Checkpoint, mpcceremony.CheckpointSubmissionSlot, mpcceremony.SubmissionEnvelopeV1, []byte, []byte, []byte, error) {
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, mpcceremony.CheckpointSubmissionSlot{}, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	checkpoint, _, _, err := loadInspectionCheckpoint(trusted.Definition, definitionBytes, definitionSignatureBytes, options.CheckpointPath, options.CheckpointSignaturePath)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, mpcceremony.CheckpointSubmissionSlot{}, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	slot := mpcceremony.CheckpointSubmissionSlot{
		Kind: mpcceremony.CheckpointSubmissionKind(options.Kind), Phase: mpcceremony.Phase(options.Phase), Index: uint8(options.Index),
		IdentityID: options.SubmitterID, AttemptID: options.AttemptID,
	}
	found := false
	for _, candidate := range checkpoint.Submissions {
		if candidate.Kind == slot.Kind && candidate.Phase == slot.Phase && candidate.Index == slot.Index &&
			candidate.IdentityID == slot.IdentityID && candidate.AttemptID == slot.AttemptID {
			slot, found = candidate, true
			break
		}
	}
	if !found {
		return nil, mpcceremony.Checkpoint{}, mpcceremony.CheckpointSubmissionSlot{}, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, errors.New("submission scope is not an exact checkpoint slot")
	}
	envelopeBytes, err := readRegularOperationalFile(options.EnvelopePath, maxOperationalRecordBytes)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, slot, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	envelopeSignatureBytes, err := readRegularOperationalFile(options.EnvelopeSignaturePath, 4096)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, slot, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	envelope, err := mpcceremony.VerifySignedSubmissionEnvelope(trusted.Definition, checkpoint, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, slot, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	manifestBytes, err := readRegularOperationalFile(options.ManifestPath, maxOperationalRecordBytes)
	if err != nil {
		return nil, mpcceremony.Checkpoint{}, slot, mpcceremony.SubmissionEnvelopeV1{}, nil, nil, nil, err
	}
	return trusted, checkpoint, slot, envelope, envelopeBytes, envelopeSignatureBytes, manifestBytes, nil
}

func inspectSubmission(envelope mpcceremony.SubmissionEnvelopeV1, envelopeBytes, envelopeSignatureBytes, manifestBytes []byte) SubmissionInspection {
	return SubmissionInspection{
		Schema: submissionInspectionSchema, CeremonyID: envelope.CeremonyID, Workflow: envelope.Workflow,
		RelayReleaseID: envelope.RelayReleaseID, SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID,
		SubmitterRole: envelope.SubmitterRole, Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
		ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256, ParentHeadID: envelope.ParentHeadID,
		AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
		Payloads:       append([]mpcceremony.ArtifactRef(nil), envelope.Payloads...),
		EnvelopeDigest: mpcceremony.NewDigest(envelopeBytes), EnvelopeSignatureDigest: mpcceremony.NewDigest(envelopeSignatureBytes),
		ManifestDigest: mpcceremony.NewDigest(manifestBytes),
	}
}

func loadExactInspectionCeremony(options InspectDefinitionOptions) (*mpcceremony.TrustedCeremony, []byte, []byte, error) {
	trusted, err := loadInspectionCeremony(options)
	if err != nil {
		return nil, nil, nil, err
	}
	definitionBytes, err := readRegularOperationalFile(options.CeremonyPath, maxOperationalRecordBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	definitionSignatureBytes, err := readRegularOperationalFile(options.CeremonySignaturePath, 4096)
	if err != nil {
		return nil, nil, nil, err
	}
	return trusted, definitionBytes, definitionSignatureBytes, nil
}

func loadInspectionCheckpoint(
	definition mpcceremony.CeremonyDefinition,
	definitionBytes, definitionSignatureBytes []byte,
	checkpointPath, checkpointSignaturePath string,
) (mpcceremony.Checkpoint, []byte, []byte, error) {
	checkpointBytes, err := readRegularOperationalFile(checkpointPath, maxOperationalRecordBytes)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, nil, err
	}
	checkpointSignatureBytes, err := readRegularOperationalFile(checkpointSignaturePath, 4096)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, nil, err
	}
	checkpoint, err := mpcceremony.VerifySignedCheckpoint(
		definition,
		definitionBytes,
		definitionSignatureBytes,
		checkpointBytes,
		checkpointSignatureBytes,
	)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, nil, err
	}
	return checkpoint, checkpointBytes, checkpointSignatureBytes, nil
}

func inspectCheckpoint(checkpoint mpcceremony.Checkpoint, checkpointBytes []byte) CheckpointInspection {
	return CheckpointInspection{
		Schema:             checkpointInspectionSchema,
		CeremonyID:         checkpoint.CeremonyID,
		Workflow:           checkpoint.Workflow,
		RelayReleaseID:     checkpoint.RelayReleaseID,
		Sequence:           checkpoint.Sequence,
		Digest:             mpcceremony.NewDigest(checkpointBytes),
		Definition:         checkpoint.Definition,
		PreviousCheckpoint: checkpoint.PreviousCheckpoint,
		Transition:         checkpoint.Transition,
		Phase1:             checkpoint.Phase1,
		Phase1Closure:      checkpoint.Phase1Closure,
		Phase1Beacon:       checkpoint.Phase1Beacon,
		Submissions:        append([]mpcceremony.CheckpointSubmissionSlot(nil), checkpoint.Submissions...),
		AcceptedArtifacts:  append([]mpcceremony.ArtifactRef(nil), checkpoint.AcceptedArtifacts...),
	}
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
		Journey:            inspectDefinitionJourney(definition),
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
