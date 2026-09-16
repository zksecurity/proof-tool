// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

const checkpointEvidenceInspectionSchema = "proof-tool-mpc-checkpoint-evidence-inspection-v1"

type builtCheckpointEvidence struct {
	trusted    *mpcceremony.TrustedCeremony
	checkpoint mpcceremony.Checkpoint
	canonical  []byte
	request    mpcceremony.CheckpointSigningRequest
}

type checkpointAcceptanceSigner func(
	trusted *mpcceremony.TrustedCeremony,
	checkpoint mpcceremony.Checkpoint,
	slot mpcceremony.CheckpointSubmissionSlot,
	envelope mpcceremony.SubmissionEnvelopeV1,
	envelopeRefs mpcceremony.SignedArtifactRefs,
	manifest mpcceremony.ArtifactRef,
) ([]byte, []byte, mpcceremony.SignedArtifactRefs, error)

func parseCheckpoint(invocation Invocation, args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, &usageError{message: "missing checkpoint command", topic: []string{"checkpoint"}}
	}
	if args[0] == "help" {
		return Invocation{}, &helpRequest{topic: append([]string{"checkpoint"}, args[1:]...)}
	}
	switch args[0] {
	case "verify-release-v4":
		options, err := parseEvidenceV4(CommandCheckpointVerifyReleaseV4, args[1:])
		invocation.Command, invocation.Options = CommandCheckpointVerifyReleaseV4, options
		return invocation, wrapCommandError(err, "checkpoint", args[0])
	case "prepare-v4", "sign-v4", "initialize-v4", "record-v4", "allocate-v4", "accept-candidate-v4", "verify-stored-v4", "inspect-signed-v4", "inspect-enrollments-v4":
		options, err := parseCheckpointV4(args[0], args[1:])
		invocation.Command, invocation.Options = Command("checkpoint "+args[0]), options
		return invocation, wrapCommandError(err, "checkpoint", args[0])
	case "prepare":
		options, err := parseCheckpointPrepare(args[1:])
		invocation.Command, invocation.Options = CommandCheckpointPrepare, options
		return invocation, wrapCommandError(err, "checkpoint", "prepare")
	case "sign":
		options, err := parseCheckpointSign(args[1:])
		invocation.Command, invocation.Options = CommandCheckpointSign, options
		return invocation, wrapCommandError(err, "checkpoint", "sign")
	case "verify":
		options, err := parseCheckpointVerify(args[1:])
		invocation.Command, invocation.Options = CommandCheckpointVerify, options
		return invocation, wrapCommandError(err, "checkpoint", "verify")
	case "verify-stored":
		options, err := parseCheckpointVerifyStored(args[1:])
		invocation.Command, invocation.Options = CommandCheckpointVerifyStored, options
		return invocation, wrapCommandError(err, "checkpoint", "verify-stored")
	default:
		return Invocation{}, &usageError{message: fmt.Sprintf("unknown checkpoint command %q", args[0]), topic: []string{"checkpoint"}}
	}
}

func addCheckpointEvidenceFlags(fs *flag.FlagSet, options *CheckpointEvidenceOptions) {
	fs.StringVar(&options.CeremonyPath, "ceremony", "", "signed ceremony definition")
	fs.StringVar(&options.CeremonySignaturePath, "ceremony-signature", "", "detached ceremony signature")
	fs.StringVar(&options.CoordinatorPublicKeyFile, "coordinator-public-key-file", "", "independently authenticated coordinator public key")
	fs.StringVar(&options.ArtifactRoot, "artifact-root", "", "root containing every referenced immutable public artifact")
	fs.StringVar(&options.RelayReleaseID, "relay-release-id", "", "approved Relay release identity")
	fs.StringVar(&options.TransitionKind, "transition", "", "supported authenticated ceremony checkpoint transition")
	fs.StringVar(&options.PreviousCheckpointPath, "previous-checkpoint", "", "exact previous checkpoint for a noninitial transition")
	fs.StringVar(&options.PreviousCheckpointSignaturePath, "previous-checkpoint-signature", "", "detached previous checkpoint signature")
	fs.StringVar(&options.ChainPath, "chain", "", "exact current phase1 chain")
	fs.StringVar(&options.ChainSignaturePath, "chain-signature", "", "detached current chain signature")
	fs.StringVar(&options.HeadPayloadPath, "head-payload", "", "exact current phase1 head payload")
	fs.StringVar(&options.Phase2GenesisPath, "phase2-genesis", "", "exact deterministic phase2 genesis payload")
	fs.StringVar(&options.Phase2ChainPath, "phase2-chain", "", "exact current phase2 chain")
	fs.StringVar(&options.Phase2ChainSignaturePath, "phase2-chain-signature", "", "detached current phase2 chain signature")
	fs.StringVar(&options.Phase2HeadPayloadPath, "phase2-head-payload", "", "exact current phase2 head payload")
	fs.StringVar(&options.TransitionRecordPath, "transition-record", "", "signed record that causes the transition")
	fs.StringVar(&options.TransitionRecordSignaturePath, "transition-record-signature", "", "detached transition record signature")
	fs.StringVar(&options.AcknowledgementPath, "acknowledgement", "", "signed accepted submission acknowledgement")
	fs.StringVar(&options.AcknowledgementSignaturePath, "acknowledgement-signature", "", "detached acknowledgement signature")
	fs.StringVar(&options.ManifestPath, "manifest", "", "exact submission transport manifest")
	fs.StringVar(&options.AttemptID, "attempt-id", "", "preallocated receipt attempt ID")
	fs.StringVar(&options.ManifestKey, "manifest-key", "", "preallocated receipt manifest key")
	fs.StringVar(&options.NextAttemptID, "next-attempt-id", "", "preallocated candidate attempt ID")
	fs.StringVar(&options.NextManifestKey, "next-manifest-key", "", "preallocated candidate manifest key")
	fs.StringVar(&options.CandidateDir, "candidate-dir", "", "exact closed finalized candidate directory")
	fs.StringVar(&options.ReleaseDir, "release-dir", "", "exact closed signed final release directory")
}

func validateCheckpointEvidenceOptions(options CheckpointEvidenceOptions) error {
	if err := requireValues(
		pathValue("--ceremony", options.CeremonyPath), pathValue("--ceremony-signature", options.CeremonySignaturePath),
		pathValue("--coordinator-public-key-file", options.CoordinatorPublicKeyFile), pathValue("--artifact-root", options.ArtifactRoot),
		value("--relay-release-id", options.RelayReleaseID), value("--transition", options.TransitionKind),
		pathValue("--chain", options.ChainPath), pathValue("--chain-signature", options.ChainSignaturePath),
		pathValue("--head-payload", options.HeadPayloadPath),
	); err != nil {
		return err
	}
	kind := mpcceremony.CheckpointTransitionKind(options.TransitionKind)
	if kind != mpcceremony.CheckpointFinalCandidateRecorded && options.CandidateDir != "" {
		return errors.New("--candidate-dir is permitted only for final-candidate-recorded")
	}
	if kind != mpcceremony.CheckpointFinalReleaseRecorded && options.ReleaseDir != "" {
		return errors.New("--release-dir is permitted only for final-release-recorded")
	}
	switch kind {
	case mpcceremony.CheckpointInitial:
		if checkpointTransitionOnlyInputsPresent(options) {
			return errors.New("initial checkpoint must not supply predecessor or transition-only inputs")
		}
		return nil
	case mpcceremony.CheckpointPhase1OutboundPublished:
		if checkpointPhase2TurnInputsPresent(options) {
			return errors.New("phase1 checkpoint must not supply phase2 chain inputs")
		}
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("outbound checkpoint must not supply acknowledgement, submission manifest, or next-attempt inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			value("--attempt-id", options.AttemptID), value("--manifest-key", options.ManifestKey),
		)
	case mpcceremony.CheckpointPhase1ReceiptAccepted:
		if checkpointPhase2TurnInputsPresent(options) {
			return errors.New("phase1 checkpoint must not supply phase2 chain inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath), value("--next-attempt-id", options.NextAttemptID), value("--next-manifest-key", options.NextManifestKey),
		)
	case mpcceremony.CheckpointPhase1CandidateAccepted:
		if checkpointPhase2TurnInputsPresent(options) {
			return errors.New("phase1 checkpoint must not supply phase2 chain inputs")
		}
		if options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("candidate-accepted checkpoint derives its allocated attempt and must not supply attempt flags")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath),
		)
	case mpcceremony.CheckpointPhase1Closed:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" ||
			options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("phase1 closure checkpoint must not supply submission or attempt inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
		)
	case mpcceremony.CheckpointPhase1BeaconRecorded, mpcceremony.CheckpointPhase1Sealed:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" ||
			options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("phase1 closure/beacon/seal checkpoint must not supply submission or attempt inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
		)
	case mpcceremony.CheckpointPhase2Initialized:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" ||
			options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("phase2 initialization checkpoint must not supply submission or attempt inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--phase2-genesis", options.Phase2GenesisPath),
		)
	case mpcceremony.CheckpointPhase2OutboundPublished:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" || options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" {
			return errors.New("phase2 outbound checkpoint must not supply acknowledgement, submission manifest, next-attempt, or genesis inputs")
		}
		return requireCheckpointPhase2TurnValues(options,
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			value("--attempt-id", options.AttemptID), value("--manifest-key", options.ManifestKey))
	case mpcceremony.CheckpointPhase2ReceiptAccepted:
		if options.Phase2GenesisPath != "" {
			return errors.New("phase2 receipt checkpoint must not supply a genesis input")
		}
		return requireCheckpointPhase2TurnValues(options,
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath), value("--next-attempt-id", options.NextAttemptID), value("--next-manifest-key", options.NextManifestKey))
	case mpcceremony.CheckpointPhase2CandidateAccepted:
		if options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" {
			return errors.New("phase2 candidate checkpoint derives its allocated attempt and must not supply attempt or genesis flags")
		}
		return requireCheckpointPhase2TurnValues(options,
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath))
	case mpcceremony.CheckpointPhase2Closed, mpcceremony.CheckpointPhase2BeaconRecorded:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" ||
			options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" {
			return errors.New("phase2 closure/beacon checkpoint must not supply submission, attempt, or genesis inputs")
		}
		return requireCheckpointPhase2TurnValues(options,
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath))
	case mpcceremony.CheckpointFinalCandidateRecorded:
		if options.TransitionRecordPath != "" || options.TransitionRecordSignaturePath != "" || options.AcknowledgementPath != "" ||
			options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" || options.AttemptID != "" || options.ManifestKey != "" ||
			options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" {
			return errors.New("final candidate checkpoint derives its record and inventory from candidate-dir and must not supply submission inputs")
		}
		return requireCheckpointPhase2TurnValues(options, pathValue("--candidate-dir", options.CandidateDir))
	case mpcceremony.CheckpointFinalReleaseRecorded:
		if options.TransitionRecordPath != "" || options.TransitionRecordSignaturePath != "" || options.AcknowledgementPath != "" ||
			options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" || options.AttemptID != "" || options.ManifestKey != "" ||
			options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" {
			return errors.New("final release checkpoint derives its record and inventory from release-dir and must not supply submission inputs")
		}
		return requireCheckpointPhase2TurnValues(options, pathValue("--release-dir", options.ReleaseDir))
	default:
		return fmt.Errorf("unsupported guarded checkpoint transition %q", kind)
	}
}

func checkpointPhase2TurnInputsPresent(options CheckpointEvidenceOptions) bool {
	return options.Phase2ChainPath != "" || options.Phase2ChainSignaturePath != "" || options.Phase2HeadPayloadPath != ""
}

func requireCheckpointPhase2TurnValues(options CheckpointEvidenceOptions, values ...requiredValue) error {
	base := []requiredValue{
		pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
		pathValue("--phase2-chain", options.Phase2ChainPath), pathValue("--phase2-chain-signature", options.Phase2ChainSignaturePath),
		pathValue("--phase2-head-payload", options.Phase2HeadPayloadPath),
	}
	return requireValues(append(base, values...)...)
}

func checkpointTransitionOnlyInputsPresent(options CheckpointEvidenceOptions) bool {
	return options.PreviousCheckpointPath != "" || options.PreviousCheckpointSignaturePath != "" ||
		options.TransitionRecordPath != "" || options.TransitionRecordSignaturePath != "" ||
		options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" ||
		options.ManifestPath != "" || options.AttemptID != "" || options.ManifestKey != "" ||
		options.NextAttemptID != "" || options.NextManifestKey != "" || options.Phase2GenesisPath != "" ||
		options.CandidateDir != "" || options.ReleaseDir != "" ||
		checkpointPhase2TurnInputsPresent(options)
}

func parseCheckpointPrepare(args []string) (CheckpointPrepareOptions, error) {
	var options CheckpointPrepareOptions
	fs := commandFlagSet("checkpoint prepare")
	addCheckpointEvidenceFlags(fs, &options.CheckpointEvidenceOptions)
	fs.StringVar(&options.OutDir, "out-dir", "", "fresh checkpoint signing packet directory")
	if err := parseFlags(fs, args); err != nil {
		return options, err
	}
	if err := validateCheckpointEvidenceOptions(options.CheckpointEvidenceOptions); err != nil {
		return options, err
	}
	return options, requireValues(pathValue("--out-dir", options.OutDir))
}

func parseCheckpointSign(args []string) (CheckpointSignOptions, error) {
	var options CheckpointSignOptions
	fs := commandFlagSet("checkpoint sign")
	addCheckpointEvidenceFlags(fs, &options.CheckpointEvidenceOptions)
	fs.StringVar(&options.CheckpointPath, "checkpoint", "", "exact reviewed checkpoint")
	fs.StringVar(&options.SigningRequestPath, "signing-request", "", "exact checkpoint signing request")
	fs.StringVar(&options.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
	fs.StringVar(&options.OutPath, "out", "", "fresh detached checkpoint signature")
	if err := parseFlags(fs, args); err != nil {
		return options, err
	}
	if err := validateCheckpointEvidenceOptions(options.CheckpointEvidenceOptions); err != nil {
		return options, err
	}
	return options, requireValues(pathValue("--checkpoint", options.CheckpointPath), pathValue("--signing-request", options.SigningRequestPath), pathValue("--coordinator-signing-key", options.CoordinatorSigningKey), pathValue("--out", options.OutPath))
}

func parseCheckpointVerify(args []string) (CheckpointVerifyOptions, error) {
	var options CheckpointVerifyOptions
	fs := commandFlagSet("checkpoint verify")
	addCheckpointEvidenceFlags(fs, &options.CheckpointEvidenceOptions)
	fs.StringVar(&options.CheckpointPath, "checkpoint", "", "exact checkpoint")
	fs.StringVar(&options.CheckpointSignaturePath, "checkpoint-signature", "", "detached checkpoint signature")
	if err := parseFlags(fs, args); err != nil {
		return options, err
	}
	if err := validateCheckpointEvidenceOptions(options.CheckpointEvidenceOptions); err != nil {
		return options, err
	}
	return options, requireValues(pathValue("--checkpoint", options.CheckpointPath), pathValue("--checkpoint-signature", options.CheckpointSignaturePath))
}

func parseCheckpointVerifyStored(args []string) (CheckpointVerifyStoredOptions, error) {
	var options CheckpointVerifyStoredOptions
	fs := commandFlagSet("checkpoint verify-stored")
	addCeremonyTrustFlags(fs, &options.CeremonyPath, &options.CeremonySignaturePath, &options.CoordinatorPublicKeyFile)
	fs.StringVar(&options.ArtifactRoot, "artifact-root", "", "root containing the fetched immutable checkpoint graph")
	fs.StringVar(&options.CheckpointPath, "checkpoint", "", "exact target checkpoint")
	fs.StringVar(&options.CheckpointSignaturePath, "checkpoint-signature", "", "detached target checkpoint signature")
	if err := parseFlags(fs, args); err != nil {
		return options, err
	}
	return options, requireValues(
		pathValue("--ceremony", options.CeremonyPath), pathValue("--ceremony-signature", options.CeremonySignaturePath),
		pathValue("--coordinator-public-key-file", options.CoordinatorPublicKeyFile), pathValue("--artifact-root", options.ArtifactRoot),
		pathValue("--checkpoint", options.CheckpointPath), pathValue("--checkpoint-signature", options.CheckpointSignaturePath),
	)
}

func executeCheckpointPrepare(options CheckpointPrepareOptions) (CommandResult, error) {
	built, err := buildCheckpointEvidence(options.CheckpointEvidenceOptions)
	if err != nil {
		return CommandResult{}, err
	}
	requestBytes, err := mpcceremony.MarshalCanonical(built.request)
	if err != nil {
		return CommandResult{}, err
	}
	checkpointPath, requestPath, err := writeOperationalSigningExport(options.OutDir, built.canonical, requestBytes)
	if err != nil {
		return CommandResult{}, err
	}
	return CommandResult{
		CeremonyID: built.checkpoint.CeremonyID,
		Summary:    fmt.Sprintf("prepared checkpoint %d from authenticated lifecycle evidence; review before signing", built.checkpoint.Sequence),
		Outputs: map[string]string{
			"checkpoint": checkpointPath, "signing_request": requestPath,
		},
	}, nil
}

func executeCheckpointSign(options CheckpointSignOptions) (CommandResult, error) {
	built, checkpointBytes, err := loadExactBuiltCheckpoint(options.CheckpointEvidenceOptions, options.CheckpointPath)
	if err != nil {
		return CommandResult{}, err
	}
	requestBytes, err := readRegularOperationalFile(options.SigningRequestPath, maxOperationalRecordBytes)
	if err != nil {
		return CommandResult{}, err
	}
	var request mpcceremony.CheckpointSigningRequest
	if err := mpcceremony.UnmarshalCanonical(requestBytes, &request); err != nil {
		return CommandResult{}, fmt.Errorf("checkpoint signing request: %w", err)
	}
	if request != built.request {
		return CommandResult{}, errors.New("checkpoint signing request does not bind the exact re-derived checkpoint")
	}
	key, publicKey, err := keybundle.LoadExistingPrivateKey(options.CoordinatorSigningKey)
	if err != nil {
		return CommandResult{}, err
	}
	if hex.EncodeToString(publicKey) != built.trusted.Definition.Coordinator.Ed25519PublicKeyHex {
		return CommandResult{}, errors.New("checkpoint signing key does not match the authenticated coordinator")
	}
	_, signatureBytes, err := mpcceremony.SignRecord(
		built.checkpoint,
		built.trusted.Definition.Coordinator.KeyID,
		key,
	)
	if err != nil {
		return CommandResult{}, err
	}
	if !bytes.Equal(checkpointBytes, built.canonical) {
		return CommandResult{}, errors.New("checkpoint changed after evidence validation")
	}
	if err := writeFreshOperationalFile(options.OutPath, signatureBytes, 0o600); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{
		CeremonyID: built.checkpoint.CeremonyID,
		Summary:    fmt.Sprintf("signed fully re-derived checkpoint %d", built.checkpoint.Sequence),
		Outputs:    map[string]string{"checkpoint": options.CheckpointPath, "signature": options.OutPath},
	}, nil
}

func executeCheckpointVerify(options CheckpointVerifyOptions) (CommandResult, error) {
	built, checkpointBytes, err := loadExactBuiltCheckpoint(options.CheckpointEvidenceOptions, options.CheckpointPath)
	if err != nil {
		return CommandResult{}, err
	}
	_, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	signatureBytes, err := readRegularOperationalFile(options.CheckpointSignaturePath, 4096)
	if err != nil {
		return CommandResult{}, err
	}
	if _, err := mpcceremony.VerifySignedCheckpoint(
		built.trusted.Definition, definitionBytes, definitionSignatureBytes, checkpointBytes, signatureBytes,
	); err != nil {
		return CommandResult{}, err
	}
	inspection := CheckpointEvidenceInspection{
		Schema: checkpointEvidenceInspectionSchema, CeremonyID: built.checkpoint.CeremonyID,
		Sequence: built.checkpoint.Sequence, CheckpointDigest: mpcceremony.NewDigest(checkpointBytes),
		TransitionKind: built.checkpoint.Transition.Kind, FullyVerified: true,
		VerifiedEvidenceBoundary: checkpointEvidenceBoundary(built.checkpoint.Transition.Kind, false),
	}
	return CommandResult{
		CeremonyID:                   built.checkpoint.CeremonyID,
		Summary:                      fmt.Sprintf("fully authenticated ceremony checkpoint %d", built.checkpoint.Sequence),
		CheckpointEvidenceInspection: &inspection,
	}, nil
}

func executeCheckpointVerifyStored(options CheckpointVerifyStoredOptions) (CommandResult, error) {
	checkpoint, checkpointBytes, err := verifyStoredCheckpointAncestry(options, options.CheckpointPath, options.CheckpointSignaturePath, make(map[string]struct{}), 0)
	if err != nil {
		return CommandResult{}, err
	}
	inspection := CheckpointEvidenceInspection{
		Schema: checkpointEvidenceInspectionSchema, CeremonyID: checkpoint.CeremonyID,
		Sequence: checkpoint.Sequence, CheckpointDigest: mpcceremony.NewDigest(checkpointBytes),
		TransitionKind: checkpoint.Transition.Kind, FullyVerified: true,
		VerifiedEvidenceBoundary: checkpointEvidenceBoundary(checkpoint.Transition.Kind, true),
	}
	return CommandResult{
		CeremonyID:                   checkpoint.CeremonyID,
		Summary:                      fmt.Sprintf("fully authenticated stored checkpoint ancestry through sequence %d", checkpoint.Sequence),
		CheckpointEvidenceInspection: &inspection,
	}, nil
}

func checkpointEvidenceBoundary(kind mpcceremony.CheckpointTransitionKind, stored bool) string {
	prefix := "authenticated checkpoint"
	if stored {
		prefix = "complete fetched checkpoint ancestry"
	}
	if kind == mpcceremony.CheckpointFinalReleaseRecorded {
		return prefix + " through the signed final release: every ceremony transition and the exact closed release tree are authenticated; publication and GO/NO-GO approval are separate"
	}
	if kind == mpcceremony.CheckpointFinalCandidateRecorded {
		return prefix + " through the finalized candidate: every transition is re-derived from exact signed records; both phases, cleanup, closure, beacon, sealed commons, deterministic Phase 2 genesis, and the closed candidate file inventory are fully replayed"
	}
	return prefix + " through " + string(kind) + ": every transition is re-derived from exact signed records, including full accepted-contribution replay and every lifecycle record reached so far"
}

func verifyStoredCheckpointAncestry(options CheckpointVerifyStoredOptions, checkpointPath, signaturePath string, seen map[string]struct{}, depth int) (mpcceremony.Checkpoint, []byte, error) {
	if depth > mpcceremony.MaxCheckpointAncestry {
		return mpcceremony.Checkpoint{}, nil, fmt.Errorf("checkpoint ancestry exceeds the supported %d-edge bound", mpcceremony.MaxCheckpointAncestry)
	}
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, err
	}
	checkpoint, checkpointBytes, _, err := loadInspectionCheckpoint(
		trusted.Definition, definitionBytes, definitionSignatureBytes, checkpointPath, signaturePath,
	)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, err
	}
	digest := mpcceremony.NewDigest(checkpointBytes).SHA256
	if _, exists := seen[digest]; exists {
		return mpcceremony.Checkpoint{}, nil, errors.New("checkpoint ancestry contains a cycle")
	}
	seen[digest] = struct{}{}
	defer delete(seen, digest)

	evidence, err := inferStoredCheckpointEvidence(options, checkpoint)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, err
	}
	if checkpoint.PreviousCheckpoint != nil {
		previousPath := filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.PreviousCheckpoint.Record.Name))
		previousSignaturePath := filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.PreviousCheckpoint.Signature.Name))
		if _, _, err := verifyStoredCheckpointAncestry(options, previousPath, previousSignaturePath, seen, depth+1); err != nil {
			return mpcceremony.Checkpoint{}, nil, fmt.Errorf("checkpoint %d predecessor: %w", checkpoint.Sequence, err)
		}
	}
	if checkpoint.Phase2 != nil {
		evidence.Phase2ChainPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase2.Chain.Record.Name))
		evidence.Phase2ChainSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase2.Chain.Signature.Name))
		evidence.Phase2HeadPayloadPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase2.HeadPayload.Name))
	}
	// The recursive walk above already fully re-derived the predecessor.
	built, err := buildCheckpointEvidenceWithParent(evidence, false)
	if err != nil {
		return mpcceremony.Checkpoint{}, nil, fmt.Errorf("checkpoint %d evidence: %w", checkpoint.Sequence, err)
	}
	if !bytes.Equal(built.canonical, checkpointBytes) {
		return mpcceremony.Checkpoint{}, nil, fmt.Errorf("checkpoint %d differs from its fully re-derived evidence", checkpoint.Sequence)
	}
	return checkpoint, checkpointBytes, nil
}

func inferStoredCheckpointEvidence(options CheckpointVerifyStoredOptions, checkpoint mpcceremony.Checkpoint) (CheckpointEvidenceOptions, error) {
	evidence := CheckpointEvidenceOptions{
		InspectDefinitionOptions: options.InspectDefinitionOptions,
		ArtifactRoot:             options.ArtifactRoot, RelayReleaseID: checkpoint.RelayReleaseID,
		TransitionKind:     string(checkpoint.Transition.Kind),
		ChainPath:          filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase1.Chain.Record.Name)),
		ChainSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase1.Chain.Signature.Name)),
		HeadPayloadPath:    filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase1.HeadPayload.Name)),
	}
	if checkpoint.PreviousCheckpoint != nil {
		evidence.PreviousCheckpointPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.PreviousCheckpoint.Record.Name))
		evidence.PreviousCheckpointSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.PreviousCheckpoint.Signature.Name))
	}
	if checkpoint.Transition.Record != nil {
		evidence.TransitionRecordPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Transition.Record.Record.Name))
		evidence.TransitionRecordSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Transition.Record.Signature.Name))
	}
	if checkpoint.Transition.Acknowledgement != nil {
		evidence.AcknowledgementPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Transition.Acknowledgement.Record.Name))
		evidence.AcknowledgementSignaturePath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Transition.Acknowledgement.Signature.Name))
		ackBytes, err := checkpointBytesForRef(options.ArtifactRoot, checkpoint.Transition.Acknowledgement.Record, maxOperationalRecordBytes)
		if err != nil {
			return CheckpointEvidenceOptions{}, err
		}
		var acknowledgement mpcceremony.SubmissionAcknowledgementV1
		if err := mpcceremony.UnmarshalCanonical(ackBytes, &acknowledgement); err != nil {
			return CheckpointEvidenceOptions{}, err
		}
		evidence.ManifestPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(acknowledgement.Manifest.Name))
	}
	switch checkpoint.Transition.Kind {
	case mpcceremony.CheckpointInitial:
	case mpcceremony.CheckpointPhase1OutboundPublished, mpcceremony.CheckpointPhase2OutboundPublished:
		for _, slot := range checkpoint.Submissions {
			if slot.Kind == mpcceremony.CheckpointSubmissionReceipt && slot.AttemptID == checkpoint.Transition.AttemptID {
				evidence.AttemptID, evidence.ManifestKey = slot.AttemptID, slot.ManifestKey
				break
			}
		}
	case mpcceremony.CheckpointPhase1ReceiptAccepted, mpcceremony.CheckpointPhase2ReceiptAccepted:
		for _, slot := range checkpoint.Submissions {
			if slot.Kind == mpcceremony.CheckpointSubmissionCandidate && slot.AttemptID == checkpoint.Transition.NextAttemptID {
				evidence.NextAttemptID, evidence.NextManifestKey = slot.AttemptID, slot.ManifestKey
				break
			}
		}
	case mpcceremony.CheckpointPhase1CandidateAccepted, mpcceremony.CheckpointPhase2CandidateAccepted:
	case mpcceremony.CheckpointPhase1Closed:
	case mpcceremony.CheckpointPhase1BeaconRecorded:
	case mpcceremony.CheckpointPhase1Sealed:
	case mpcceremony.CheckpointPhase2Initialized:
		if checkpoint.Phase2 == nil {
			return CheckpointEvidenceOptions{}, errors.New("stored phase2 initialization checkpoint has no phase2 state")
		}
		evidence.Phase2GenesisPath = filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.Phase2.HeadPayload.Name))
	case mpcceremony.CheckpointPhase2Closed, mpcceremony.CheckpointPhase2BeaconRecorded:
	case mpcceremony.CheckpointFinalCandidateRecorded:
		if checkpoint.FinalCandidate == nil {
			return CheckpointEvidenceOptions{}, errors.New("stored final candidate checkpoint has no final candidate")
		}
		evidence.CandidateDir = filepath.Dir(filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.FinalCandidate.Record.Name)))
	case mpcceremony.CheckpointFinalReleaseRecorded:
		if checkpoint.FinalRelease == nil {
			return CheckpointEvidenceOptions{}, errors.New("stored final release checkpoint has no final release")
		}
		evidence.ReleaseDir = filepath.Dir(filepath.Join(options.ArtifactRoot, filepath.FromSlash(checkpoint.FinalRelease.Record.Name)))
	default:
		return CheckpointEvidenceOptions{}, fmt.Errorf("stored checkpoint transition %q is outside the supported authenticated lifecycle boundary", checkpoint.Transition.Kind)
	}
	return evidence, nil
}

func loadExactBuiltCheckpoint(options CheckpointEvidenceOptions, checkpointPath string) (builtCheckpointEvidence, []byte, error) {
	built, err := buildCheckpointEvidence(options)
	if err != nil {
		return builtCheckpointEvidence{}, nil, err
	}
	checkpointBytes, err := readRegularOperationalFile(checkpointPath, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, nil, err
	}
	if !bytes.Equal(checkpointBytes, built.canonical) {
		return builtCheckpointEvidence{}, nil, errors.New("checkpoint bytes do not equal the checkpoint re-derived from authenticated evidence")
	}
	return built, checkpointBytes, nil
}

func buildCheckpointEvidence(options CheckpointEvidenceOptions) (builtCheckpointEvidence, error) {
	return buildCheckpointEvidenceWithParent(options, true)
}

func buildCheckpointEvidenceWithParent(options CheckpointEvidenceOptions, verifyParent bool) (builtCheckpointEvidence, error) {
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(options.InspectDefinitionOptions)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if trusted.Definition.Schema == mpcceremony.DefinitionSchemaV4 {
		return builtCheckpointEvidence{}, errors.New("definition v4 requires the explicit V4 checkpoint commands")
	}
	definitionRefs, err := checkpointPairRefs(options.ArtifactRoot, options.CeremonyPath, options.CeremonySignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("definition references: %w", err)
	}
	if definitionRefs.Record.Digest != mpcceremony.NewDigest(definitionBytes) || definitionRefs.Signature.Digest != mpcceremony.NewDigest(definitionSignatureBytes) {
		return builtCheckpointEvidence{}, errors.New("definition reference bytes changed during validation")
	}
	chainPaths := mpcceremony.PhaseTranscriptPaths{
		RootDir: options.ArtifactRoot, ChainPath: options.ChainPath, ChainSignaturePath: options.ChainSignaturePath,
	}
	chain, chainRefs, err := mpcceremony.LoadSignedChainExact(trusted, chainPaths)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if chain.Phase != mpcceremony.Phase1 {
		return builtCheckpointEvidence{}, errors.New("checkpoint foundation currently supports phase1 only")
	}
	expectedChainName := fmt.Sprintf("phase1/chain-%04d.json", len(chain.Records))
	if err := requireCheckpointArtifactName(chainRefs.Record, expectedChainName, "phase1 chain"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(chainRefs.Signature, strings.TrimSuffix(expectedChainName, ".json")+".sig", "phase1 chain signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	headPayload, err := chain.HeadPayload()
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	suppliedHead, err := checkpointArtifactRef(options.ArtifactRoot, options.HeadPayloadPath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("head payload: %w", err)
	}
	if suppliedHead != headPayload {
		return builtCheckpointEvidence{}, errors.New("head payload does not match the authenticated chain head")
	}
	headID, err := chain.HeadRecordID()
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	phaseState := mpcceremony.CheckpointPhaseState{
		Phase: mpcceremony.Phase1, AcceptedCount: uint8(len(chain.Records)), HeadRecordID: headID,
		HeadPayload: headPayload, Chain: chainRefs,
	}

	kind := mpcceremony.CheckpointTransitionKind(options.TransitionKind)
	var circuit *mpcceremony.CompiledCircuit
	if kind == mpcceremony.CheckpointPhase1CandidateAccepted || kind == mpcceremony.CheckpointPhase1Sealed || kind == mpcceremony.CheckpointPhase2Initialized || kind == mpcceremony.CheckpointPhase2CandidateAccepted || kind == mpcceremony.CheckpointPhase2Closed || kind == mpcceremony.CheckpointFinalCandidateRecorded {
		r1csPath := filepath.Join(options.ArtifactRoot, filepath.FromSlash(trusted.Definition.Circuit.R1CS.Name))
		rootAbs, rootErr := filepath.Abs(options.ArtifactRoot)
		if rootErr != nil {
			return builtCheckpointEvidence{}, rootErr
		}
		r1csAbs, pathErr := filepath.Abs(r1csPath)
		if pathErr != nil {
			return builtCheckpointEvidence{}, pathErr
		}
		if pathErr = validateCheckpointPathComponents(rootAbs, r1csAbs); pathErr != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("signed circuit artifact: %w", pathErr)
		}
		circuit, err = mpcceremony.ReadR1CSFile(r1csPath, trusted.Definition.Circuit)
		if err != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("signed circuit artifact: %w", err)
		}
	}
	if kind == mpcceremony.CheckpointPhase1CandidateAccepted {
		chain, chainRefs, err = mpcceremony.VerifyAcceptedPhase1Chain(
			trustPaths(options.CeremonyPath, options.CeremonySignaturePath, options.CoordinatorPublicKeyFile), circuit, chainPaths,
		)
		if err != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("full candidate chain verification: %w", err)
		}
		headPayload, err = chain.HeadPayload()
		if err != nil {
			return builtCheckpointEvidence{}, err
		}
		headID, err = chain.HeadRecordID()
		if err != nil {
			return builtCheckpointEvidence{}, err
		}
		phaseState = mpcceremony.CheckpointPhaseState{
			Phase: mpcceremony.Phase1, AcceptedCount: uint8(len(chain.Records)), HeadRecordID: headID,
			HeadPayload: headPayload, Chain: chainRefs,
		}
	}
	if kind == mpcceremony.CheckpointInitial {
		if len(chain.Records) != 0 {
			return builtCheckpointEvidence{}, errors.New("initial checkpoint requires the authenticated phase1 genesis chain")
		}
		checkpoint := mpcceremony.Checkpoint{
			Schema: checkpointSchemaForDefinition(trusted.Definition), Workflow: mpcceremony.StorageFirstWorkflowV1,
			CeremonyID: trusted.Definition.CeremonyID, Definition: definitionRefs,
			AssurancePolicy: trusted.Definition.AssurancePolicy,
			RelayReleaseID:  options.RelayReleaseID, Sequence: 0,
			Transition: mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointInitial}, Phase1: phaseState,
			AcceptedArtifacts: checkpointSortedArtifacts(definitionRefs.Record, definitionRefs.Signature, headPayload, chainRefs.Record, chainRefs.Signature),
			Submissions:       []mpcceremony.CheckpointSubmissionSlot{},
		}
		return finishBuiltCheckpoint(trusted, checkpoint)
	}
	if verifyParent {
		if _, _, err := verifyStoredCheckpointAncestry(
			CheckpointVerifyStoredOptions{
				InspectCheckpointOptions: InspectCheckpointOptions{
					InspectDefinitionOptions: options.InspectDefinitionOptions,
					CheckpointPath:           options.PreviousCheckpointPath,
					CheckpointSignaturePath:  options.PreviousCheckpointSignaturePath,
				},
				ArtifactRoot: options.ArtifactRoot,
			},
			options.PreviousCheckpointPath,
			options.PreviousCheckpointSignaturePath,
			make(map[string]struct{}), 0,
		); err != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("previous checkpoint ancestry: %w", err)
		}
	}

	previous, previousBytes, previousSignatureBytes, err := loadInspectionCheckpoint(
		trusted.Definition, definitionBytes, definitionSignatureBytes,
		options.PreviousCheckpointPath, options.PreviousCheckpointSignaturePath,
	)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("previous checkpoint: %w", err)
	}
	previousRefs, err := checkpointPairRefs(options.ArtifactRoot, options.PreviousCheckpointPath, options.PreviousCheckpointSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("previous checkpoint references: %w", err)
	}
	if previousRefs.Record.Digest != mpcceremony.NewDigest(previousBytes) || previousRefs.Signature.Digest != mpcceremony.NewDigest(previousSignatureBytes) {
		return builtCheckpointEvidence{}, errors.New("previous checkpoint reference bytes changed during validation")
	}
	if kind != mpcceremony.CheckpointPhase1CandidateAccepted && previous.Phase1 != phaseState {
		return builtCheckpointEvidence{}, errors.New("phase1 chain and head do not equal the previous checkpoint state")
	}
	if options.RelayReleaseID != previous.RelayReleaseID {
		return builtCheckpointEvidence{}, errors.New("relay release id differs from previous checkpoint")
	}
	activePhase := mpcceremony.Phase1
	activeState := phaseState
	activeChain := chain
	if kind == mpcceremony.CheckpointPhase2OutboundPublished || kind == mpcceremony.CheckpointPhase2ReceiptAccepted || kind == mpcceremony.CheckpointPhase2CandidateAccepted || kind == mpcceremony.CheckpointPhase2Closed || kind == mpcceremony.CheckpointPhase2BeaconRecorded || kind == mpcceremony.CheckpointFinalCandidateRecorded || kind == mpcceremony.CheckpointFinalReleaseRecorded {
		if previous.Phase2 == nil || previous.Phase1Seal == nil {
			return builtCheckpointEvidence{}, errors.New("phase2 turn requires an initialized phase2 checkpoint")
		}
		activePhase = mpcceremony.Phase2
		phase2Paths := mpcceremony.PhaseTranscriptPaths{RootDir: options.ArtifactRoot, ChainPath: options.Phase2ChainPath, ChainSignaturePath: options.Phase2ChainSignaturePath}
		var phase2Refs mpcceremony.SignedArtifactRefs
		if kind == mpcceremony.CheckpointPhase2CandidateAccepted || kind == mpcceremony.CheckpointPhase2Closed {
			activeChain, phase2Refs, err = mpcceremony.VerifyAcceptedPhase2Chain(
				trustPaths(options.CeremonyPath, options.CeremonySignaturePath, options.CoordinatorPublicKeyFile), circuit, options.ArtifactRoot,
				filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Record.Name)),
				filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Signature.Name)), phase2Paths)
		} else {
			activeChain, phase2Refs, err = mpcceremony.LoadSignedChainExact(trusted, phase2Paths)
		}
		if err != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("phase2 chain verification: %w", err)
		}
		expectedName := fmt.Sprintf("phase2/chain-%04d.json", len(activeChain.Records))
		if err := requireCheckpointArtifactName(phase2Refs.Record, expectedName, "phase2 chain"); err != nil {
			return builtCheckpointEvidence{}, err
		}
		if err := requireCheckpointArtifactName(phase2Refs.Signature, strings.TrimSuffix(expectedName, ".json")+".sig", "phase2 chain signature"); err != nil {
			return builtCheckpointEvidence{}, err
		}
		phase2Head, headErr := activeChain.HeadPayload()
		if headErr != nil {
			return builtCheckpointEvidence{}, headErr
		}
		supplied, refErr := checkpointArtifactRef(options.ArtifactRoot, options.Phase2HeadPayloadPath)
		if refErr != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("phase2 head payload: %w", refErr)
		}
		if supplied != phase2Head {
			return builtCheckpointEvidence{}, errors.New("phase2 head payload does not match the authenticated chain head")
		}
		phase2HeadID, headErr := activeChain.HeadRecordID()
		if headErr != nil {
			return builtCheckpointEvidence{}, headErr
		}
		activeState = mpcceremony.CheckpointPhaseState{Phase: mpcceremony.Phase2, AcceptedCount: uint8(len(activeChain.Records)), HeadRecordID: phase2HeadID, HeadPayload: phase2Head, Chain: phase2Refs}
		if kind != mpcceremony.CheckpointPhase2CandidateAccepted && *previous.Phase2 != activeState {
			return builtCheckpointEvidence{}, errors.New("phase2 chain and head do not equal the previous checkpoint state")
		}
	}

	switch kind {
	case mpcceremony.CheckpointPhase1OutboundPublished:
		return buildOutboundCheckpoint(options, trusted, previous, previousRefs, activeState, activePhase)
	case mpcceremony.CheckpointPhase1ReceiptAccepted:
		return buildReceiptCheckpoint(options, trusted, previous, previousRefs, activeState, activePhase)
	case mpcceremony.CheckpointPhase1CandidateAccepted:
		return buildCandidateCheckpoint(options, trusted, previous, previousRefs, activeState, activeChain, activePhase)
	case mpcceremony.CheckpointPhase1Closed:
		return buildPhase1ClosedCheckpoint(options, trusted, previous, previousRefs, phaseState, chain)
	case mpcceremony.CheckpointPhase1BeaconRecorded:
		return buildPhase1BeaconCheckpoint(options, trusted, previous, previousRefs, phaseState)
	case mpcceremony.CheckpointPhase1Sealed:
		return buildPhase1SealCheckpoint(options, trusted, previous, previousRefs, phaseState, circuit)
	case mpcceremony.CheckpointPhase2Initialized:
		return buildPhase2InitializedCheckpoint(options, trusted, previous, previousRefs, phaseState, circuit)
	case mpcceremony.CheckpointPhase2OutboundPublished:
		return buildOutboundCheckpoint(options, trusted, previous, previousRefs, activeState, activePhase)
	case mpcceremony.CheckpointPhase2ReceiptAccepted:
		return buildReceiptCheckpoint(options, trusted, previous, previousRefs, activeState, activePhase)
	case mpcceremony.CheckpointPhase2CandidateAccepted:
		return buildCandidateCheckpoint(options, trusted, previous, previousRefs, activeState, activeChain, activePhase)
	case mpcceremony.CheckpointPhase2Closed:
		return buildPhaseClosedCheckpoint(options, trusted, previous, previousRefs, activeState, activeChain, mpcceremony.Phase2)
	case mpcceremony.CheckpointPhase2BeaconRecorded:
		return buildPhaseBeaconCheckpoint(options, trusted, previous, previousRefs, activeState, mpcceremony.Phase2)
	case mpcceremony.CheckpointFinalCandidateRecorded:
		return buildFinalCandidateCheckpoint(options, trusted, previous, previousRefs, phaseState, activeState, circuit)
	case mpcceremony.CheckpointFinalReleaseRecorded:
		return buildFinalReleaseCheckpoint(options, trusted, previous, previousRefs, phaseState, activeState)
	default:
		return builtCheckpointEvidence{}, fmt.Errorf("unsupported guarded checkpoint transition %q", kind)
	}
}

func buildPhase2InitializedCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phase1State mpcceremony.CheckpointPhaseState, circuit *mpcceremony.CompiledCircuit) (builtCheckpointEvidence, error) {
	if previous.Phase1Seal == nil || previous.Phase1Closure == nil || previous.Phase1Beacon == nil {
		return builtCheckpointEvidence{}, errors.New("phase2 initialization requires a sealed phase1 checkpoint")
	}
	if previous.Phase2 != nil {
		return builtCheckpointEvidence{}, errors.New("phase2 is already initialized in the previous checkpoint")
	}
	verified, err := mpcceremony.VerifyPhase2GenesisFiles(mpcceremony.VerifyPhase2GenesisFilesOptions{
		Trust:   trustPaths(options.CeremonyPath, options.CeremonySignaturePath, options.CoordinatorPublicKeyFile),
		Circuit: circuit, TranscriptRoot: options.ArtifactRoot,
		Phase1SealPath:          filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Record.Name)),
		Phase1SealSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Signature.Name)),
		Phase2ChainPath:         options.TransitionRecordPath, Phase2ChainSignaturePath: options.TransitionRecordSignaturePath,
	})
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("full phase2 genesis verification: %w", err)
	}
	if err := requireCheckpointArtifactName(verified.ChainRefs.Record, "phase2/chain-0000.json", "phase2 genesis chain"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(verified.ChainRefs.Signature, "phase2/chain-0000.sig", "phase2 genesis chain signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(verified.Genesis, "phase2/genesis.bin", "phase2 genesis"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	suppliedGenesis, err := checkpointArtifactRef(options.ArtifactRoot, options.Phase2GenesisPath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 genesis: %w", err)
	}
	if suppliedGenesis != verified.Genesis {
		return builtCheckpointEvidence{}, errors.New("phase2 genesis does not match the authenticated deterministic chain genesis")
	}
	headID, err := verified.Chain.HeadRecordID()
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	phase2State := mpcceremony.CheckpointPhaseState{Phase: mpcceremony.Phase2, AcceptedCount: 0, HeadRecordID: headID, HeadPayload: verified.Genesis, Chain: verified.ChainRefs}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointPhase2Initialized, Phase: mpcceremony.Phase2, Record: &verified.ChainRefs, Evidence: []mpcceremony.ArtifactRef{verified.Genesis}}
	checkpoint.Phase1 = phase1State
	checkpoint.Phase2 = &phase2State
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), verified.ChainRefs.Record, verified.ChainRefs.Signature, verified.Genesis)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildPhaseClosedCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, chain mpcceremony.Chain, phase mpcceremony.Phase) (builtCheckpointEvidence, error) {
	if phase != mpcceremony.Phase2 || previous.Phase2 == nil || previous.Phase1Closure == nil {
		return builtCheckpointEvidence{}, errors.New("phase2 closure requires initialized phase2 state")
	}
	if previous.Phase2Closure != nil {
		return builtCheckpointEvidence{}, errors.New("phase2 is already closed in the previous checkpoint")
	}
	closeBytes, closeSignature, closeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure: %w", err)
	}
	if err := requireCheckpointArtifactName(closeRefs.Record, "phase2/closure/record.json", "phase2 closure"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(closeRefs.Signature, "phase2/closure/record.sig", "phase2 closure signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	publicKey, err := keybundle.DecodePublicKeyHex(trusted.Definition.Coordinator.Ed25519PublicKeyHex)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("coordinator public key: %w", err)
	}
	var closeRecord mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(closeBytes, closeSignature, &closeRecord, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure signature: %w", err)
	}
	if closeRecord.Phase != phase {
		return builtCheckpointEvidence{}, errors.New("phase2-closed checkpoint received a non-phase2 closure")
	}
	if err := mpcceremony.ValidateClose(trusted.Definition, chain, closeRecord); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure: %w", err)
	}
	phase1CloseBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure: %w", err)
	}
	phase1CloseSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	var phase1Close mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(phase1CloseBytes, phase1CloseSignature, &phase1Close, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	if err := validateDistinctPhaseCloseRounds(phase1Close, closeRecord); err != nil {
		return builtCheckpointEvidence{}, err
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointPhase2Closed, Phase: phase, Record: &closeRefs}
	state := phaseState
	checkpoint.Phase2 = &state
	checkpoint.Phase2Closure = &closeRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), closeRefs.Record, closeRefs.Signature)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildPhaseBeaconCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, phase mpcceremony.Phase) (builtCheckpointEvidence, error) {
	if phase != mpcceremony.Phase2 || previous.Phase2Closure == nil || previous.Phase1Beacon == nil {
		return builtCheckpointEvidence{}, errors.New("phase2 beacon requires a closure in the previous checkpoint")
	}
	if previous.Phase2Beacon != nil {
		return builtCheckpointEvidence{}, errors.New("phase2 beacon is already recorded in the previous checkpoint")
	}
	publicKey, err := keybundle.DecodePublicKeyHex(trusted.Definition.Coordinator.Ed25519PublicKeyHex)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("coordinator public key: %w", err)
	}
	closureBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase2Closure.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure: %w", err)
	}
	closureSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase2Closure.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure signature: %w", err)
	}
	var closure mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(closureBytes, closureSignature, &closure, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 closure signature: %w", err)
	}
	beaconBytes, beaconSignature, beaconRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 beacon: %w", err)
	}
	if err := requireCheckpointArtifactName(beaconRefs.Record, "phase2/beacon/record.json", "phase2 beacon"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(beaconRefs.Signature, "phase2/beacon/record.sig", "phase2 beacon signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	var beacon mpcceremony.BeaconRecord
	if err := mpcceremony.VerifySignedRecord(beaconBytes, beaconSignature, &beacon, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 beacon signature: %w", err)
	}
	if beacon.Phase != phase {
		return builtCheckpointEvidence{}, errors.New("phase2-beacon-recorded checkpoint received a non-phase2 beacon")
	}
	if err := mpcceremony.ValidateBeacon(trusted.Definition, closure, beacon); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 beacon: %w", err)
	}
	if err := mpcceremony.VerifyBeaconRecordFiles(trusted, options.ArtifactRoot, closure, beacon); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 beacon evidence: %w", err)
	}
	phase1BeaconBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Beacon.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon: %w", err)
	}
	phase1BeaconSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Beacon.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon signature: %w", err)
	}
	var phase1Beacon mpcceremony.BeaconRecord
	if err := mpcceremony.VerifySignedRecord(phase1BeaconBytes, phase1BeaconSignature, &phase1Beacon, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon signature: %w", err)
	}
	if err := validateDistinctPhaseBeaconRecords(phase1Beacon, beacon); err != nil {
		return builtCheckpointEvidence{}, err
	}
	rawResponse, err := checkpointArtifactRef(options.ArtifactRoot, filepath.Join(options.ArtifactRoot, filepath.FromSlash(beacon.RawResponse.Name)))
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase2 raw beacon response: %w", err)
	}
	if rawResponse != beacon.RawResponse {
		return builtCheckpointEvidence{}, errors.New("phase2 raw beacon response changed during validation")
	}
	if err := requireCheckpointArtifactName(rawResponse, "phase2/beacon/raw-response.bin", "phase2 raw beacon response"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointPhase2BeaconRecorded, Phase: phase, Record: &beaconRefs, Evidence: []mpcceremony.ArtifactRef{rawResponse}}
	state := phaseState
	checkpoint.Phase2 = &state
	checkpoint.Phase2Beacon = &beaconRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), beaconRefs.Record, beaconRefs.Signature, rawResponse)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func validateDistinctPhaseCloseRounds(phase1, phase2 mpcceremony.CloseRecord) error {
	if phase1.BeaconProvider == phase2.BeaconProvider && phase1.BeaconNetwork == phase2.BeaconNetwork && phase1.BeaconRound == phase2.BeaconRound {
		return errors.New("phase1 and phase2 must use distinct beacon rounds")
	}
	return nil
}

func validateDistinctPhaseBeaconRecords(phase1, phase2 mpcceremony.BeaconRecord) error {
	if phase1.ChallengeSHA256 == phase2.ChallengeSHA256 ||
		(phase1.Provider == phase2.Provider && phase1.Network == phase2.Network && phase1.Round == phase2.Round) {
		return errors.New("phase1 and phase2 must use distinct beacon challenges and rounds")
	}
	return nil
}

func buildFinalCandidateCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phase1State, phase2State mpcceremony.CheckpointPhaseState, circuit *mpcceremony.CompiledCircuit) (builtCheckpointEvidence, error) {
	if previous.Phase1Closure == nil || previous.Phase1Beacon == nil || previous.Phase1Seal == nil || previous.Phase2 == nil || previous.Phase2Closure == nil || previous.Phase2Beacon == nil {
		return builtCheckpointEvidence{}, errors.New("final candidate requires both completed phases and the phase1 seal")
	}
	if previous.FinalCandidate != nil {
		return builtCheckpointEvidence{}, errors.New("final candidate is already recorded in the previous checkpoint")
	}
	rootAbs, err := filepath.Abs(options.ArtifactRoot)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	candidateAbs, err := filepath.Abs(options.CandidateDir)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := validateCheckpointPathComponents(rootAbs, candidateAbs); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final candidate directory: %w", err)
	}
	relativeCandidate, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil || filepath.ToSlash(relativeCandidate) != "final/candidate" {
		return builtCheckpointEvidence{}, errors.New("final candidate directory must be the canonical final/candidate path under artifact-root")
	}
	replay := mpcceremony.ReplayPaths{
		TranscriptRoot:            options.ArtifactRoot,
		CoordinatorPublicKeyHex:   trusted.Definition.Coordinator.Ed25519PublicKeyHex,
		DefinitionPath:            options.CeremonyPath,
		DefinitionSignaturePath:   options.CeremonySignaturePath,
		Phase1ChainPath:           options.ChainPath,
		Phase1ChainSignaturePath:  options.ChainSignaturePath,
		Phase1ClosePath:           filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Closure.Record.Name)),
		Phase1CloseSignaturePath:  filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Closure.Signature.Name)),
		Phase1BeaconPath:          filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Beacon.Record.Name)),
		Phase1BeaconSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Beacon.Signature.Name)),
		Phase1SealPath:            filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Record.Name)),
		Phase1SealSignaturePath:   filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Seal.Signature.Name)),
		Phase2ChainPath:           options.Phase2ChainPath,
		Phase2ChainSignaturePath:  options.Phase2ChainSignaturePath,
		Phase2ClosePath:           filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase2Closure.Record.Name)),
		Phase2CloseSignaturePath:  filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase2Closure.Signature.Name)),
		Phase2BeaconPath:          filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase2Beacon.Record.Name)),
		Phase2BeaconSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase2Beacon.Signature.Name)),
	}
	_, candidateRefs, err := mpcceremony.VerifyFinalCandidateCheckpoint(replay, circuit, options.CandidateDir)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final candidate verification: %w", err)
	}
	prefixed := make([]mpcceremony.ArtifactRef, 0, len(candidateRefs))
	for _, ref := range candidateRefs {
		ref.Name = "final/candidate/" + ref.Name
		prefixed = append(prefixed, ref)
	}
	prefixed = checkpointSortedArtifacts(prefixed...)
	var recordRefs mpcceremony.SignedArtifactRefs
	evidence := make([]mpcceremony.ArtifactRef, 0, len(prefixed)-2)
	for _, ref := range prefixed {
		switch ref.Name {
		case "final/candidate/" + mpcceremony.CandidateMetadataFile:
			recordRefs.Record = ref
		case "final/candidate/" + mpcceremony.CandidateSignatureFile:
			recordRefs.Signature = ref
		default:
			evidence = append(evidence, ref)
		}
	}
	if err := recordRefs.Validate(); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final candidate record: %w", err)
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointFinalCandidateRecorded, Record: &recordRefs, Evidence: evidence}
	checkpoint.Phase1 = phase1State
	state := phase2State
	checkpoint.Phase2 = &state
	checkpoint.FinalCandidate = &recordRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), prefixed...)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildFinalReleaseCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phase1State, phase2State mpcceremony.CheckpointPhaseState) (builtCheckpointEvidence, error) {
	if previous.FinalCandidate == nil || previous.Phase2Beacon == nil {
		return builtCheckpointEvidence{}, errors.New("final release requires the authenticated final candidate checkpoint")
	}
	if previous.FinalRelease != nil {
		return builtCheckpointEvidence{}, errors.New("final release is already recorded in the previous checkpoint")
	}
	rootAbs, err := filepath.Abs(options.ArtifactRoot)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	releaseAbs, err := filepath.Abs(options.ReleaseDir)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := validateCheckpointPathComponents(rootAbs, releaseAbs); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final release directory: %w", err)
	}
	relativeRelease, err := filepath.Rel(rootAbs, releaseAbs)
	if err != nil || filepath.ToSlash(relativeRelease) != "final/release" {
		return builtCheckpointEvidence{}, errors.New("final release directory must be the canonical final/release path under artifact-root")
	}
	verified, releaseRefs, err := mpcceremony.VerifyFinalReleaseCheckpoint(mpcceremony.VerifyReleaseOptions{
		DefinitionPath: options.CeremonyPath, DefinitionSignaturePath: options.CeremonySignaturePath,
		CoordinatorPublicKeyHex: trusted.Definition.Coordinator.Ed25519PublicKeyHex,
		KeysDir:                 options.ReleaseDir, TrustedPublicKeyHex: trusted.Definition.ReleaseSigner.Ed25519PublicKeyHex,
		ExpectedSignatureKeyID: trusted.Definition.ReleaseSigner.KeyID, RequireProvingKey: true,
	})
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final release verification: %w", err)
	}
	prefixed := make([]mpcceremony.ArtifactRef, 0, len(releaseRefs))
	for _, ref := range releaseRefs {
		ref.Name = "final/release/" + ref.Name
		prefixed = append(prefixed, ref)
	}
	prefixed = checkpointSortedArtifacts(prefixed...)
	releaseCandidate := make(map[string]mpcceremony.ArtifactRef)
	for _, ref := range prefixed {
		suffix, ok := strings.CutPrefix(ref.Name, "final/release/")
		if ok {
			releaseCandidate[suffix] = ref
		}
	}
	for _, frozen := range previous.AcceptedArtifacts {
		suffix, ok := strings.CutPrefix(frozen.Name, "final/candidate/")
		if !ok {
			continue
		}
		copied, exists := releaseCandidate[suffix]
		if !exists || copied.Digest != frozen.Digest {
			return builtCheckpointEvidence{}, fmt.Errorf("final release candidate file %q differs from the checkpointed final candidate", suffix)
		}
	}
	var releaseRecord mpcceremony.SignedArtifactRefs
	evidence := make([]mpcceremony.ArtifactRef, 0, len(prefixed)-2)
	for _, ref := range prefixed {
		switch ref.Name {
		case "final/release/" + keybundle.ManifestFile:
			releaseRecord.Record = ref
		case "final/release/" + keybundle.ManifestSignatureFile:
			releaseRecord.Signature = ref
		default:
			evidence = append(evidence, ref)
		}
	}
	if err := releaseRecord.Validate(); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("final release manifest: %w", err)
	}
	if releaseRecord.Record.Digest.SHA256 != verified.ManifestSHA256 {
		return builtCheckpointEvidence{}, errors.New("verified release manifest changed during checkpoint preparation")
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{Kind: mpcceremony.CheckpointFinalReleaseRecorded, Record: &releaseRecord, Evidence: evidence}
	checkpoint.Phase1 = phase1State
	state := phase2State
	checkpoint.Phase2 = &state
	checkpoint.FinalRelease = &releaseRecord
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), prefixed...)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildPhase1BeaconCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState) (builtCheckpointEvidence, error) {
	if previous.Phase1Closure == nil {
		return builtCheckpointEvidence{}, errors.New("phase1 beacon requires a closure in the previous checkpoint")
	}
	if previous.Phase1Beacon != nil {
		return builtCheckpointEvidence{}, errors.New("phase1 beacon is already recorded in the previous checkpoint")
	}
	publicKey, err := keybundle.DecodePublicKeyHex(trusted.Definition.Coordinator.Ed25519PublicKeyHex)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("coordinator public key: %w", err)
	}
	closureBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure: %w", err)
	}
	closureSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	var closure mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(closureBytes, closureSignature, &closure, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}

	beaconBytes, beaconSignature, beaconRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon: %w", err)
	}
	if err := requireCheckpointArtifactName(beaconRefs.Record, "phase1/beacon/record.json", "phase1 beacon"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(beaconRefs.Signature, "phase1/beacon/record.sig", "phase1 beacon signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	var beacon mpcceremony.BeaconRecord
	if err := mpcceremony.VerifySignedRecord(beaconBytes, beaconSignature, &beacon, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon signature: %w", err)
	}
	if beacon.Phase != mpcceremony.Phase1 {
		return builtCheckpointEvidence{}, errors.New("phase1-beacon-recorded checkpoint received a non-phase1 beacon")
	}
	if err := mpcceremony.ValidateBeacon(trusted.Definition, closure, beacon); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon: %w", err)
	}
	if err := mpcceremony.VerifyBeaconRecordFiles(trusted, options.ArtifactRoot, closure, beacon); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon evidence: %w", err)
	}
	rawResponse, err := checkpointArtifactRef(options.ArtifactRoot, filepath.Join(options.ArtifactRoot, filepath.FromSlash(beacon.RawResponse.Name)))
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 raw beacon response: %w", err)
	}
	if rawResponse != beacon.RawResponse {
		return builtCheckpointEvidence{}, errors.New("phase1 raw beacon response changed during validation")
	}
	if err := requireCheckpointArtifactName(rawResponse, "phase1/beacon/raw-response.bin", "phase1 raw beacon response"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1BeaconRecorded, Phase: mpcceremony.Phase1,
		Record: &beaconRefs, Evidence: []mpcceremony.ArtifactRef{rawResponse},
	}
	checkpoint.Phase1 = phaseState
	checkpoint.Phase1Beacon = &beaconRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), beaconRefs.Record, beaconRefs.Signature, rawResponse)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildPhase1SealCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, circuit *mpcceremony.CompiledCircuit) (builtCheckpointEvidence, error) {
	if previous.Phase1Closure == nil || previous.Phase1Beacon == nil {
		return builtCheckpointEvidence{}, errors.New("phase1 seal requires closure and beacon in the previous checkpoint")
	}
	if previous.Phase1Seal != nil {
		return builtCheckpointEvidence{}, errors.New("phase1 is already sealed in the previous checkpoint")
	}
	closureBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure: %w", err)
	}
	closureSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Closure.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	beaconBytes, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Beacon.Record, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon: %w", err)
	}
	beaconSignature, err := checkpointBytesForRef(options.ArtifactRoot, previous.Phase1Beacon.Signature, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon signature: %w", err)
	}
	sealBytes, sealSignature, sealRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 seal: %w", err)
	}
	if err := requireCheckpointArtifactName(sealRefs.Record, "phase1/sealed/seal.json", "phase1 seal"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(sealRefs.Signature, "phase1/sealed/seal.sig", "phase1 seal signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	publicKey, err := keybundle.DecodePublicKeyHex(trusted.Definition.Coordinator.Ed25519PublicKeyHex)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("coordinator public key: %w", err)
	}
	var seal mpcceremony.SealRecord
	if err := mpcceremony.VerifySignedRecord(sealBytes, sealSignature, &seal, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 seal signature: %w", err)
	}
	var closure mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(closureBytes, closureSignature, &closure, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	var beacon mpcceremony.BeaconRecord
	if err := mpcceremony.VerifySignedRecord(beaconBytes, beaconSignature, &beacon, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 beacon signature: %w", err)
	}
	if seal.Phase != mpcceremony.Phase1 {
		return builtCheckpointEvidence{}, errors.New("phase1-sealed checkpoint received a non-phase1 seal")
	}
	verified, err := mpcceremony.VerifyPhase1SealFiles(mpcceremony.VerifyPhase1SealFilesOptions{
		Trust:   trustPaths(options.CeremonyPath, options.CeremonySignaturePath, options.CoordinatorPublicKeyFile),
		Circuit: circuit, TranscriptRoot: options.ArtifactRoot,
		Phase1ChainPath:           filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1.Chain.Record.Name)),
		Phase1ChainSignaturePath:  filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1.Chain.Signature.Name)),
		Phase1ClosePath:           filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Closure.Record.Name)),
		Phase1CloseSignaturePath:  filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Closure.Signature.Name)),
		Phase1BeaconPath:          filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Beacon.Record.Name)),
		Phase1BeaconSignaturePath: filepath.Join(options.ArtifactRoot, filepath.FromSlash(previous.Phase1Beacon.Signature.Name)),
		Phase1SealPath:            options.TransitionRecordPath, Phase1SealSignaturePath: options.TransitionRecordSignaturePath,
	})
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("full phase1 seal verification: %w", err)
	}
	if verified.Seal.SealID != seal.SealID {
		return builtCheckpointEvidence{}, errors.New("verified phase1 seal differs from transition record")
	}
	if verified.Close.CloseID != closure.CloseID || seal.BeaconID != beacon.BeaconID {
		return builtCheckpointEvidence{}, errors.New("phase1 seal does not bind the checkpoint's exact closure and beacon")
	}
	commons := verified.Commons
	if err := requireCheckpointArtifactName(commons, "phase1/sealed/commons.bin", "phase1 commons"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	actualCommons, err := checkpointArtifactRef(options.ArtifactRoot, filepath.Join(options.ArtifactRoot, filepath.FromSlash(commons.Name)))
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 commons: %w", err)
	}
	if actualCommons != commons {
		return builtCheckpointEvidence{}, errors.New("phase1 commons changed during validation")
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1Sealed, Phase: mpcceremony.Phase1,
		Record: &sealRefs, Evidence: []mpcceremony.ArtifactRef{commons},
	}
	checkpoint.Phase1 = phaseState
	checkpoint.Phase1Seal = &sealRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), sealRefs.Record, sealRefs.Signature, commons)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildPhase1ClosedCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, chain mpcceremony.Chain) (builtCheckpointEvidence, error) {
	if previous.Phase1Closure != nil {
		return builtCheckpointEvidence{}, errors.New("phase1 is already closed in the previous checkpoint")
	}
	closeBytes, closeSignature, closeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure: %w", err)
	}
	if err := requireCheckpointArtifactName(closeRefs.Record, "phase1/closure/record.json", "phase1 closure"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireCheckpointArtifactName(closeRefs.Signature, "phase1/closure/record.sig", "phase1 closure signature"); err != nil {
		return builtCheckpointEvidence{}, err
	}
	publicKey, err := keybundle.DecodePublicKeyHex(trusted.Definition.Coordinator.Ed25519PublicKeyHex)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("coordinator public key: %w", err)
	}
	var closeRecord mpcceremony.CloseRecord
	if err := mpcceremony.VerifySignedRecord(closeBytes, closeSignature, &closeRecord, trusted.Definition.Coordinator.KeyID, publicKey); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure signature: %w", err)
	}
	if closeRecord.Phase != mpcceremony.Phase1 {
		return builtCheckpointEvidence{}, errors.New("phase1-closed checkpoint received a non-phase1 closure")
	}
	if err := mpcceremony.ValidateClose(trusted.Definition, chain, closeRecord); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("phase1 closure: %w", err)
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1Closed, Phase: mpcceremony.Phase1, Record: &closeRefs,
	}
	checkpoint.Phase1 = phaseState
	checkpoint.Phase1Closure = &closeRefs
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), closeRefs.Record, closeRefs.Signature)...)
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func checkpointSchemaForDefinition(definition mpcceremony.CeremonyDefinition) string {
	if definition.Schema == mpcceremony.DefinitionSchemaV3 {
		return mpcceremony.CheckpointSchema
	}
	return mpcceremony.CheckpointSchemaV1
}

func buildOutboundCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, phase mpcceremony.Phase) (builtCheckpointEvidence, error) {
	recordBytes, record, recordRefs, err := loadSignedOperationalPair(options, mpcceremony.RecordHandoff, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	_ = recordBytes
	handoff := record.(*mpcceremony.TransferHandoff)
	policy := trusted.Definition.Phase1Policy
	transitionKind := mpcceremony.CheckpointPhase1OutboundPublished
	if phase == mpcceremony.Phase2 {
		policy = trusted.Definition.Phase2Policy
		transitionKind = mpcceremony.CheckpointPhase2OutboundPublished
	}
	index, participantID, err := nextCheckpointParticipant(phaseState, policy, phase)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	participant, _ := trusted.Definition.ParticipantByID(participantID)
	if handoff.Phase != phase || handoff.Index != index || handoff.PredecessorHeadID != phaseState.HeadRecordID ||
		handoff.SenderID != trusted.Definition.Coordinator.ID || handoff.SenderKeyID != trusted.Definition.Coordinator.KeyID ||
		handoff.RecipientID != participantID || handoff.RecipientKeyID != participant.Identity.KeyID ||
		!slices.Equal(handoff.Files, []mpcceremony.ArtifactRef{phaseState.HeadPayload}) {
		return builtCheckpointEvidence{}, errors.New("outbound handoff does not bind the exact current head, next participant, and input payload")
	}
	transition := mpcceremony.CheckpointTransition{
		Kind: transitionKind, Phase: phase, Index: index,
		ParticipantID: participantID, AttemptID: options.AttemptID, Record: &recordRefs,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	if phase == mpcceremony.Phase2 {
		state := phaseState
		checkpoint.Phase2 = &state
	} else {
		checkpoint.Phase1 = phaseState
	}
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), recordRefs.Record, recordRefs.Signature)...)
	checkpoint.Submissions = append(append([]mpcceremony.CheckpointSubmissionSlot(nil), previous.Submissions...), mpcceremony.CheckpointSubmissionSlot{
		Kind: mpcceremony.CheckpointSubmissionReceipt, Phase: phase, Index: index,
		IdentityID: participantID, AttemptID: options.AttemptID, ManifestKey: options.ManifestKey,
		BasisCheckpointSHA256: previousRefs.Record.Digest.SHA256, ParentHeadID: phaseState.HeadRecordID,
		Status: mpcceremony.CheckpointSubmissionAllocated,
	})
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func nextCheckpointParticipant(state mpcceremony.CheckpointPhaseState, policy mpcceremony.PhasePolicy, phase mpcceremony.Phase) (uint8, string, error) {
	if int(state.AcceptedCount) >= len(policy.Participants) {
		return 0, "", fmt.Errorf("no next %s participant in the authenticated schedule", phase)
	}
	return state.AcceptedCount + 1, policy.Participants[int(state.AcceptedCount)], nil
}

func buildReceiptCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, phase mpcceremony.Phase) (builtCheckpointEvidence, error) {
	envelopeBytes, envelopeSignatureBytes, envelopeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("receipt submission envelope: %w", err)
	}
	var untrustedEnvelope mpcceremony.SubmissionEnvelopeV1
	if err := mpcceremony.UnmarshalCanonical(envelopeBytes, &untrustedEnvelope); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("receipt submission envelope: %w", err)
	}
	slot, err := findAllocatedSubmission(previous, untrustedEnvelope)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireSubmissionEnvelopeNames(slot, envelopeRefs); err != nil {
		return builtCheckpointEvidence{}, err
	}
	envelope, err := mpcceremony.VerifySignedSubmissionEnvelope(trusted.Definition, previous, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if envelope.Kind != mpcceremony.CheckpointSubmissionReceipt {
		return builtCheckpointEvidence{}, errors.New("receipt-accepted checkpoint requires a receipt submission envelope")
	}
	if err := requireReceiptPayloadNames(slot, envelope.Payloads); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := verifyReceiptEnvelopePayloads(options.ArtifactRoot, trusted, previous, envelope); err != nil {
		return builtCheckpointEvidence{}, err
	}
	manifestBytes, manifest, err := checkpointArtifactBytes(options.ArtifactRoot, options.ManifestPath, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("submission manifest: %w", err)
	}
	var ackBytes, ackSignatureBytes []byte
	var ackRefs mpcceremony.SignedArtifactRefs
	if options.AcceptanceSigner != nil {
		ackBytes, ackSignatureBytes, ackRefs, err = options.AcceptanceSigner(trusted, previous, slot, envelope, envelopeRefs, manifest)
	} else {
		ackBytes, ackSignatureBytes, ackRefs, err = checkpointAcknowledgementBytes(options)
	}
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("submission acknowledgement: %w", err)
	}
	ack, err := mpcceremony.VerifySignedSubmissionAcknowledgement(
		trusted.Definition, previous, slot,
		envelopeRefs.Record.Name, envelopeRefs.Signature.Name, envelopeBytes, envelopeSignatureBytes,
		manifest.Name, manifestBytes, ackBytes, ackSignatureBytes,
	)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if ack.Result != mpcceremony.SubmissionAccepted {
		return builtCheckpointEvidence{}, errors.New("receipt-accepted checkpoint requires an accepted acknowledgement")
	}
	transitionKind := mpcceremony.CheckpointPhase1ReceiptAccepted
	if phase == mpcceremony.Phase2 {
		transitionKind = mpcceremony.CheckpointPhase2ReceiptAccepted
	}
	evidence := checkpointSortedArtifacts(append([]mpcceremony.ArtifactRef{manifest}, envelope.Payloads...)...)
	transition := mpcceremony.CheckpointTransition{
		Kind: transitionKind, Phase: phase,
		Index: slot.Index, ParticipantID: slot.IdentityID, AttemptID: slot.AttemptID,
		NextAttemptID: options.NextAttemptID, Record: &envelopeRefs, Acknowledgement: &ackRefs, Evidence: evidence,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	if phase == mpcceremony.Phase2 {
		state := phaseState
		checkpoint.Phase2 = &state
	} else {
		checkpoint.Phase1 = phaseState
	}
	accepted := append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), envelopeRefs.Record, envelopeRefs.Signature, ackRefs.Record, ackRefs.Signature)
	accepted = append(accepted, evidence...)
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(accepted...)
	checkpoint.Submissions = append([]mpcceremony.CheckpointSubmissionSlot(nil), previous.Submissions...)
	for index := range checkpoint.Submissions {
		if checkpoint.Submissions[index] == slot {
			checkpoint.Submissions[index].Status = mpcceremony.CheckpointSubmissionAccepted
			checkpoint.Submissions[index].Acknowledgement = &ackRefs
		}
	}
	checkpoint.Submissions = append(checkpoint.Submissions, mpcceremony.CheckpointSubmissionSlot{
		Kind: mpcceremony.CheckpointSubmissionCandidate, Phase: phase, Index: slot.Index,
		IdentityID: slot.IdentityID, AttemptID: options.NextAttemptID, ManifestKey: options.NextManifestKey,
		BasisCheckpointSHA256: previousRefs.Record.Digest.SHA256, ParentHeadID: phaseState.HeadRecordID,
		Status: mpcceremony.CheckpointSubmissionAllocated,
	})
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildCandidateCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, chain mpcceremony.Chain, phase mpcceremony.Phase) (builtCheckpointEvidence, error) {
	previousState := previous.Phase1
	transitionKind := mpcceremony.CheckpointPhase1CandidateAccepted
	if phase == mpcceremony.Phase2 {
		if previous.Phase2 == nil {
			return builtCheckpointEvidence{}, errors.New("phase2 candidate requires initialized phase2 state")
		}
		previousState = *previous.Phase2
		transitionKind = mpcceremony.CheckpointPhase2CandidateAccepted
	}
	if phaseState.AcceptedCount != previousState.AcceptedCount+1 || len(chain.Records) == 0 {
		return builtCheckpointEvidence{}, errors.New("candidate checkpoint chain must advance the previous head by exactly one record")
	}
	envelopeBytes, envelopeSignatureBytes, envelopeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate submission envelope: %w", err)
	}
	var untrustedEnvelope mpcceremony.SubmissionEnvelopeV1
	if err := mpcceremony.UnmarshalCanonical(envelopeBytes, &untrustedEnvelope); err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate submission envelope: %w", err)
	}
	slot, err := findAllocatedSubmission(previous, untrustedEnvelope)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if err := requireSubmissionEnvelopeNames(slot, envelopeRefs); err != nil {
		return builtCheckpointEvidence{}, err
	}
	if slot.Kind != mpcceremony.CheckpointSubmissionCandidate {
		return builtCheckpointEvidence{}, errors.New("candidate-accepted checkpoint requires a candidate submission slot")
	}
	envelope, err := mpcceremony.VerifySignedSubmissionEnvelope(trusted.Definition, previous, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	acceptedRecord := chain.Records[len(chain.Records)-1]
	if acceptedRecord.Index != slot.Index || acceptedRecord.ParticipantID != slot.IdentityID ||
		acceptedRecord.PreviousRecordID != previousState.HeadRecordID {
		return builtCheckpointEvidence{}, errors.New("authenticated accepted chain record does not match the allocated candidate slot and previous head")
	}
	if err := verifyCandidateEnvelopePayloads(options.ArtifactRoot, envelope, acceptedRecord); err != nil {
		return builtCheckpointEvidence{}, err
	}
	manifestBytes, manifest, err := checkpointArtifactBytes(options.ArtifactRoot, options.ManifestPath, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate manifest: %w", err)
	}
	var ackBytes, ackSignatureBytes []byte
	var ackRefs mpcceremony.SignedArtifactRefs
	if options.AcceptanceSigner != nil {
		ackBytes, ackSignatureBytes, ackRefs, err = options.AcceptanceSigner(trusted, previous, slot, envelope, envelopeRefs, manifest)
	} else {
		ackBytes, ackSignatureBytes, ackRefs, err = checkpointAcknowledgementBytes(options)
	}
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate acknowledgement: %w", err)
	}
	ack, err := mpcceremony.VerifySignedSubmissionAcknowledgement(
		trusted.Definition, previous, slot,
		envelopeRefs.Record.Name, envelopeRefs.Signature.Name, envelopeBytes, envelopeSignatureBytes,
		manifest.Name, manifestBytes, ackBytes, ackSignatureBytes,
	)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if ack.Result != mpcceremony.SubmissionAccepted {
		return builtCheckpointEvidence{}, errors.New("candidate-accepted checkpoint requires an accepted acknowledgement")
	}
	evidence := checkpointSortedArtifacts(append([]mpcceremony.ArtifactRef{manifest}, envelope.Payloads...)...)
	transition := mpcceremony.CheckpointTransition{
		Kind: transitionKind, Phase: phase,
		Index: slot.Index, ParticipantID: slot.IdentityID, AttemptID: slot.AttemptID,
		Record: &envelopeRefs, Acknowledgement: &ackRefs, Evidence: evidence,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	if phase == mpcceremony.Phase2 {
		state := phaseState
		checkpoint.Phase2 = &state
	} else {
		checkpoint.Phase1 = phaseState
	}
	accepted := append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...),
		envelopeRefs.Record, envelopeRefs.Signature, ackRefs.Record, ackRefs.Signature,
		phaseState.Chain.Record, phaseState.Chain.Signature)
	accepted = append(accepted, evidence...)
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(accepted...)
	checkpoint.Submissions = append([]mpcceremony.CheckpointSubmissionSlot(nil), previous.Submissions...)
	for index := range checkpoint.Submissions {
		if checkpoint.Submissions[index] == slot {
			checkpoint.Submissions[index].Status = mpcceremony.CheckpointSubmissionAccepted
			checkpoint.Submissions[index].Acknowledgement = &ackRefs
		}
	}
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func verifyCandidateEnvelopePayloads(root string, envelope mpcceremony.SubmissionEnvelopeV1, accepted mpcceremony.ChainRecord) error {
	if len(envelope.Payloads) != 5 {
		return errors.New("candidate submission must contain exactly contribution, attestation, attestation signature, cleanup record, and cleanup signature")
	}
	// Contributions are intentionally much larger than ordinary operational
	// records in production. Authenticate that exact file with streaming hashes;
	// VerifyAcceptedPhase1Chain has already enforced its shape-derived exact
	// length and canonical native encoding without an unbounded allocation.
	if err := checkCustodyFile(root, accepted.OutputPayload); err != nil {
		return fmt.Errorf("candidate contribution payload %q: %w", accepted.OutputPayload.Name, err)
	}
	for _, item := range []struct {
		ref   mpcceremony.ArtifactRef
		limit int64
	}{
		{accepted.Attestation, maxOperationalRecordBytes},
		{accepted.AttestationSignature, 4096},
		{accepted.Erasure, maxOperationalRecordBytes},
		{accepted.ErasureSignature, 4096},
	} {
		if _, err := checkpointBytesForRef(root, item.ref, item.limit); err != nil {
			return fmt.Errorf("candidate submission payload %q: %w", item.ref.Name, err)
		}
	}
	want := []mpcceremony.ArtifactRef{
		accepted.OutputPayload, accepted.Attestation, accepted.AttestationSignature,
		accepted.Erasure, accepted.ErasureSignature,
	}
	got := append([]mpcceremony.ArtifactRef(nil), envelope.Payloads...)
	sortRefs := func(values []mpcceremony.ArtifactRef) {
		slices.SortFunc(values, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	}
	sortRefs(want)
	sortRefs(got)
	if !slices.Equal(want, got) {
		return errors.New("candidate submission payloads do not exactly match the fully verified accepted chain record")
	}
	return nil
}

func finishTransitionCheckpoint(trusted *mpcceremony.TrustedCeremony, previous, checkpoint mpcceremony.Checkpoint) (builtCheckpointEvidence, error) {
	if err := mpcceremony.ValidateCheckpointTransition(previous, checkpoint); err != nil {
		return builtCheckpointEvidence{}, err
	}
	return finishBuiltCheckpoint(trusted, checkpoint)
}

func finishBuiltCheckpoint(trusted *mpcceremony.TrustedCeremony, checkpoint mpcceremony.Checkpoint) (builtCheckpointEvidence, error) {
	if err := checkpoint.Validate(); err != nil {
		return builtCheckpointEvidence{}, err
	}
	canonical, err := mpcceremony.MarshalCanonical(checkpoint)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	request, err := mpcceremony.NewCheckpointSigningRequest(trusted.Definition, canonical)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	return builtCheckpointEvidence{trusted: trusted, checkpoint: checkpoint, canonical: canonical, request: request}, nil
}

func loadSignedOperationalPair(options CheckpointEvidenceOptions, kind mpcceremony.OperationalRecordType, recordPath, signaturePath string) ([]byte, any, mpcceremony.SignedArtifactRefs, error) {
	canonical, record, trusted, err := loadBoundOperationalRecord(kind, recordPath, options.CeremonyPath, options.CeremonySignaturePath, options.CoordinatorPublicKeyFile)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	definitionBytes, err := canonicalDefinition(trusted)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	owner, err := mpcceremony.VerifyOperationalRecordBinding(trusted.Definition, definitionBytes, record)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	publicKey, err := hex.DecodeString(owner.Ed25519PublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, errors.New("operational signer has invalid public key")
	}
	signatureBytes, err := readRegularOperationalFile(signaturePath, 4096)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	var signature mpcceremony.DetachedSignature
	if err := mpcceremony.UnmarshalCanonical(signatureBytes, &signature); err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	if err := mpcceremony.VerifyExact(canonical, signature, owner.KeyID, ed25519.PublicKey(publicKey)); err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	refs, err := checkpointPairRefs(options.ArtifactRoot, recordPath, signaturePath)
	if err == nil && (refs.Record.Digest != mpcceremony.NewDigest(canonical) || refs.Signature.Digest != mpcceremony.NewDigest(signatureBytes)) {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, errors.New("signed operational record changed during validation")
	}
	return canonical, record, refs, err
}

func verifyReceiptEnvelopePayloads(root string, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, envelope mpcceremony.SubmissionEnvelopeV1) error {
	if len(envelope.Payloads) != 2 {
		return errors.New("receipt submission must contain exactly the receipt record and its signature")
	}
	var receiptBytes []byte
	var receipt *mpcceremony.TransferReceipt
	var receiptRef mpcceremony.ArtifactRef
	for _, ref := range envelope.Payloads {
		bytes, err := checkpointBytesForRef(root, ref, maxOperationalRecordBytes)
		if err != nil {
			return fmt.Errorf("submission payload %q: %w", ref.Name, err)
		}
		parsed, err := mpcceremony.ParseOperationalRecord(mpcceremony.RecordReceipt, bytes)
		if err == nil {
			if receipt != nil {
				return errors.New("receipt submission contains multiple receipt records")
			}
			receiptBytes, receiptRef = bytes, ref
			receipt = parsed.(*mpcceremony.TransferReceipt)
		}
	}
	if receipt == nil {
		return errors.New("receipt submission does not contain a canonical transfer receipt")
	}
	participant, ok := trusted.Definition.ParticipantByID(envelope.SubmitterID)
	if !ok {
		return errors.New("receipt submitter is not an assigned participant")
	}
	publicKeyBytes, _ := hex.DecodeString(participant.Identity.Ed25519PublicKeyHex)
	foundSignature := false
	for _, ref := range envelope.Payloads {
		if ref == receiptRef {
			continue
		}
		signatureBytes, err := checkpointBytesForRef(root, ref, 4096)
		if err != nil {
			return err
		}
		var signature mpcceremony.DetachedSignature
		if err := mpcceremony.UnmarshalCanonical(signatureBytes, &signature); err == nil &&
			mpcceremony.VerifyExact(receiptBytes, signature, participant.Identity.KeyID, ed25519.PublicKey(publicKeyBytes)) == nil {
			foundSignature = true
		}
	}
	if !foundSignature {
		return errors.New("receipt submission does not contain the participant's exact receipt signature")
	}
	outboundRefs := previous.Transition.Record
	if outboundRefs == nil {
		return errors.New("previous checkpoint does not contain the outbound handoff")
	}
	outboundBytes, err := checkpointBytesForRef(root, outboundRefs.Record, maxOperationalRecordBytes)
	if err != nil {
		return err
	}
	outboundSignatureBytes, err := checkpointBytesForRef(root, outboundRefs.Signature, 4096)
	if err != nil {
		return err
	}
	var outbound mpcceremony.TransferHandoff
	if err := mpcceremony.UnmarshalCanonical(outboundBytes, &outbound); err != nil {
		return err
	}
	var outboundSignature mpcceremony.DetachedSignature
	if err := mpcceremony.UnmarshalCanonical(outboundSignatureBytes, &outboundSignature); err != nil {
		return err
	}
	if err := mpcceremony.VerifyExact(outboundBytes, outboundSignature, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
		return err
	}
	if err := mpcceremony.VerifyTransferReceipt(outboundBytes, outbound, *receipt); err != nil {
		return err
	}
	return nil
}

func findAllocatedSubmission(checkpoint mpcceremony.Checkpoint, envelope mpcceremony.SubmissionEnvelopeV1) (mpcceremony.CheckpointSubmissionSlot, error) {
	for _, slot := range checkpoint.Submissions {
		if slot.Kind == envelope.Kind && slot.Phase == envelope.Phase && slot.Index == envelope.Index &&
			slot.IdentityID == envelope.SubmitterID && slot.AttemptID == envelope.AttemptID && slot.Status == mpcceremony.CheckpointSubmissionAllocated {
			return slot, nil
		}
	}
	return mpcceremony.CheckpointSubmissionSlot{}, errors.New("submission envelope does not match an allocated checkpoint slot")
}

func requireSubmissionEnvelopeNames(slot mpcceremony.CheckpointSubmissionSlot, refs mpcceremony.SignedArtifactRefs) error {
	base := strings.TrimSuffix(slot.ManifestKey, "/manifest.json")
	if refs.Record.Name != base+"/envelope.json" || refs.Signature.Name != base+"/envelope.sig" {
		return errors.New("submission envelope does not use the preallocated storage path")
	}
	return nil
}

func requireReceiptPayloadNames(slot mpcceremony.CheckpointSubmissionSlot, refs []mpcceremony.ArtifactRef) error {
	base := fmt.Sprintf("%s/custody/%04d", slot.Phase, slot.Index)
	want := []string{base + "/outbound-receipt.json", base + "/outbound-receipt.sig"}
	got := make([]string, len(refs))
	for i := range refs {
		got[i] = refs[i].Name
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return errors.New("receipt submission does not use the deterministic ceremony evidence paths")
	}
	return nil
}

func checkpointSignedBytes(root, recordPath, signaturePath string) ([]byte, []byte, mpcceremony.SignedArtifactRefs, error) {
	recordBytes, recordRef, err := checkpointArtifactBytes(root, recordPath, maxOperationalRecordBytes)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	signatureBytes, signatureRef, err := checkpointArtifactBytes(root, signaturePath, 4096)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	refs := mpcceremony.SignedArtifactRefs{Record: recordRef, Signature: signatureRef}
	return recordBytes, signatureBytes, refs, nil
}

func checkpointAcknowledgementBytes(options CheckpointEvidenceOptions) ([]byte, []byte, mpcceremony.SignedArtifactRefs, error) {
	if options.AcknowledgementRecordName == "" && options.AcknowledgementSignatureName == "" {
		return checkpointSignedBytes(options.ArtifactRoot, options.AcknowledgementPath, options.AcknowledgementSignaturePath)
	}
	if options.AcknowledgementRecordName == "" || options.AcknowledgementSignatureName == "" {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, errors.New("both intended acknowledgement names are required")
	}
	record, err := readRegularOperationalFile(options.AcknowledgementPath, maxOperationalRecordBytes)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	signature, err := readRegularOperationalFile(options.AcknowledgementSignaturePath, 4096)
	if err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	refs := mpcceremony.SignedArtifactRefs{
		Record:    mpcceremony.ArtifactRef{Name: options.AcknowledgementRecordName, Digest: mpcceremony.NewDigest(record)},
		Signature: mpcceremony.ArtifactRef{Name: options.AcknowledgementSignatureName, Digest: mpcceremony.NewDigest(signature)},
	}
	if err := refs.Validate(); err != nil {
		return nil, nil, mpcceremony.SignedArtifactRefs{}, err
	}
	return record, signature, refs, nil
}

func requireCheckpointArtifactName(ref mpcceremony.ArtifactRef, expected, label string) error {
	if ref.Name != expected {
		return fmt.Errorf("%s must use canonical storage path %q, got %q", label, expected, ref.Name)
	}
	return nil
}

// checkpointArtifactBytes binds validation bytes and checkpoint references to
// the same opened file. Callers must not separately reopen a mutable path for
// semantic verification after committing the returned reference.
func checkpointArtifactBytes(root, path string, limit int64) ([]byte, mpcceremony.ArtifactRef, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, mpcceremony.ArtifactRef{}, err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, mpcceremony.ArtifactRef{}, err
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return nil, mpcceremony.ArtifactRef{}, errors.New("artifact path escapes artifact root")
	}
	data, err := openCheckpointArtifactBytes(rootAbs, filepath.Clean(rel), limit)
	if err != nil {
		return nil, mpcceremony.ArtifactRef{}, err
	}
	ref := mpcceremony.ArtifactRef{Name: filepath.ToSlash(rel), Digest: mpcceremony.NewDigest(data)}
	if err := ref.Validate(); err != nil {
		return nil, mpcceremony.ArtifactRef{}, err
	}
	return data, ref, nil
}

func checkpointPairRefs(root, recordPath, signaturePath string) (mpcceremony.SignedArtifactRefs, error) {
	record, err := checkpointArtifactRef(root, recordPath)
	if err != nil {
		return mpcceremony.SignedArtifactRefs{}, err
	}
	signature, err := checkpointArtifactRef(root, signaturePath)
	if err != nil {
		return mpcceremony.SignedArtifactRefs{}, err
	}
	refs := mpcceremony.SignedArtifactRefs{Record: record, Signature: signature}
	return refs, refs.Validate()
}

func checkpointArtifactRef(root, path string) (mpcceremony.ArtifactRef, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return mpcceremony.ArtifactRef{}, errors.New("artifact path escapes artifact root")
	}
	name := filepath.ToSlash(rel)
	if err := validateCheckpointPathComponents(rootAbs, pathAbs); err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	digest, err := custodyDigest(pathAbs)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	ref := mpcceremony.ArtifactRef{Name: name, Digest: digest}
	if err := checkCustodyFile(rootAbs, ref); err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	return ref, nil
}

func validateCheckpointPathComponents(root, path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("checkpoint artifacts cannot traverse symbolic links")
		}
		if current == root {
			return nil
		}
		if filepath.Dir(current) == current {
			return errors.New("checkpoint artifact path does not reach artifact root")
		}
	}
}

func checkpointBytesForRef(root string, ref mpcceremony.ArtifactRef, limit int64) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	data, actual, err := checkpointArtifactBytes(root, filepath.Join(root, filepath.FromSlash(ref.Name)), limit)
	if err != nil {
		return nil, err
	}
	if actual != ref {
		return nil, fmt.Errorf("retained file %q differs from checkpoint digest", ref.Name)
	}
	return data, nil
}

func checkpointSortedArtifacts(values ...mpcceremony.ArtifactRef) []mpcceremony.ArtifactRef {
	result := append([]mpcceremony.ArtifactRef(nil), values...)
	slices.SortFunc(result, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return result
}
