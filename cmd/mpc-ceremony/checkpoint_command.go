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

func parseCheckpoint(invocation Invocation, args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, &usageError{message: "missing checkpoint command", topic: []string{"checkpoint"}}
	}
	if args[0] == "help" {
		return Invocation{}, &helpRequest{topic: append([]string{"checkpoint"}, args[1:]...)}
	}
	switch args[0] {
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
	fs.StringVar(&options.TransitionKind, "transition", "", "initial, phase1-outbound-published, or phase1-receipt-accepted")
	fs.StringVar(&options.PreviousCheckpointPath, "previous-checkpoint", "", "exact previous checkpoint for a noninitial transition")
	fs.StringVar(&options.PreviousCheckpointSignaturePath, "previous-checkpoint-signature", "", "detached previous checkpoint signature")
	fs.StringVar(&options.ChainPath, "chain", "", "exact current phase1 chain")
	fs.StringVar(&options.ChainSignaturePath, "chain-signature", "", "detached current chain signature")
	fs.StringVar(&options.HeadPayloadPath, "head-payload", "", "exact current phase1 head payload")
	fs.StringVar(&options.TransitionRecordPath, "transition-record", "", "signed record that causes the transition")
	fs.StringVar(&options.TransitionRecordSignaturePath, "transition-record-signature", "", "detached transition record signature")
	fs.StringVar(&options.AcknowledgementPath, "acknowledgement", "", "signed accepted submission acknowledgement")
	fs.StringVar(&options.AcknowledgementSignaturePath, "acknowledgement-signature", "", "detached acknowledgement signature")
	fs.StringVar(&options.ManifestPath, "manifest", "", "exact submission transport manifest")
	fs.StringVar(&options.AttemptID, "attempt-id", "", "preallocated receipt attempt ID")
	fs.StringVar(&options.ManifestKey, "manifest-key", "", "preallocated receipt manifest key")
	fs.StringVar(&options.NextAttemptID, "next-attempt-id", "", "preallocated candidate attempt ID")
	fs.StringVar(&options.NextManifestKey, "next-manifest-key", "", "preallocated candidate manifest key")
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
	switch kind {
	case mpcceremony.CheckpointInitial:
		if checkpointTransitionOnlyInputsPresent(options) {
			return errors.New("initial checkpoint must not supply predecessor or transition-only inputs")
		}
		return nil
	case mpcceremony.CheckpointPhase1OutboundPublished:
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" || options.ManifestPath != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("outbound checkpoint must not supply acknowledgement, submission manifest, or next-attempt inputs")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			value("--attempt-id", options.AttemptID), value("--manifest-key", options.ManifestKey),
		)
	case mpcceremony.CheckpointPhase1ReceiptAccepted:
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath), value("--next-attempt-id", options.NextAttemptID), value("--next-manifest-key", options.NextManifestKey),
		)
	case mpcceremony.CheckpointPhase1CandidateAccepted:
		if options.AttemptID != "" || options.ManifestKey != "" || options.NextAttemptID != "" || options.NextManifestKey != "" {
			return errors.New("candidate-accepted checkpoint derives its allocated attempt and must not supply attempt flags")
		}
		return requireValues(
			pathValue("--previous-checkpoint", options.PreviousCheckpointPath), pathValue("--previous-checkpoint-signature", options.PreviousCheckpointSignaturePath),
			pathValue("--transition-record", options.TransitionRecordPath), pathValue("--transition-record-signature", options.TransitionRecordSignaturePath),
			pathValue("--acknowledgement", options.AcknowledgementPath), pathValue("--acknowledgement-signature", options.AcknowledgementSignaturePath),
			pathValue("--manifest", options.ManifestPath),
		)
	default:
		return fmt.Errorf("unsupported guarded checkpoint transition %q", kind)
	}
}

func checkpointTransitionOnlyInputsPresent(options CheckpointEvidenceOptions) bool {
	return options.PreviousCheckpointPath != "" || options.PreviousCheckpointSignaturePath != "" ||
		options.TransitionRecordPath != "" || options.TransitionRecordSignaturePath != "" ||
		options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" ||
		options.ManifestPath != "" || options.AttemptID != "" || options.ManifestKey != "" ||
		options.NextAttemptID != "" || options.NextManifestKey != ""
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
		Summary:    fmt.Sprintf("prepared checkpoint %d from authenticated cp0-cp3 evidence; review before signing", built.checkpoint.Sequence),
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
		ed25519.PrivateKey(key),
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
		VerifiedEvidenceBoundary: "phase1 checkpoint cp0-cp3: exact definition, predecessor, chain/head, transition record, submission payloads and acknowledgement; cp3 includes full contribution and cleanup replay",
	}
	return CommandResult{
		CeremonyID:                   built.checkpoint.CeremonyID,
		Summary:                      fmt.Sprintf("fully authenticated checkpoint %d within the cp0-cp3 evidence boundary", built.checkpoint.Sequence),
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
		VerifiedEvidenceBoundary: "complete fetched cp0-cp3 ancestry; each edge re-derived from exact signed records, with full contribution and cleanup replay for cp3",
	}
	return CommandResult{
		CeremonyID:                   checkpoint.CeremonyID,
		Summary:                      fmt.Sprintf("fully authenticated stored checkpoint ancestry through sequence %d", checkpoint.Sequence),
		CheckpointEvidenceInspection: &inspection,
	}, nil
}

func verifyStoredCheckpointAncestry(options CheckpointVerifyStoredOptions, checkpointPath, signaturePath string, seen map[string]struct{}, depth int) (mpcceremony.Checkpoint, []byte, error) {
	if depth > 1024 {
		return mpcceremony.Checkpoint{}, nil, errors.New("checkpoint ancestry exceeds the supported 1024-edge bound")
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
	case mpcceremony.CheckpointPhase1OutboundPublished:
		for _, slot := range checkpoint.Submissions {
			if slot.Kind == mpcceremony.CheckpointSubmissionReceipt && slot.AttemptID == checkpoint.Transition.AttemptID {
				evidence.AttemptID, evidence.ManifestKey = slot.AttemptID, slot.ManifestKey
				break
			}
		}
	case mpcceremony.CheckpointPhase1ReceiptAccepted:
		for _, slot := range checkpoint.Submissions {
			if slot.Kind == mpcceremony.CheckpointSubmissionCandidate && slot.AttemptID == checkpoint.Transition.NextAttemptID {
				evidence.NextAttemptID, evidence.NextManifestKey = slot.AttemptID, slot.ManifestKey
				break
			}
		}
	case mpcceremony.CheckpointPhase1CandidateAccepted:
	default:
		return CheckpointEvidenceOptions{}, fmt.Errorf("stored checkpoint transition %q is outside cp0-cp3", checkpoint.Transition.Kind)
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
	if kind == mpcceremony.CheckpointPhase1CandidateAccepted {
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
		circuit, readErr := mpcceremony.ReadR1CSFile(r1csPath, trusted.Definition.Circuit)
		if readErr != nil {
			return builtCheckpointEvidence{}, fmt.Errorf("signed circuit artifact: %w", readErr)
		}
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
			Schema: mpcceremony.CheckpointSchemaV1, Workflow: mpcceremony.StorageFirstWorkflowV1,
			CeremonyID: trusted.Definition.CeremonyID, Definition: definitionRefs,
			RelayReleaseID: options.RelayReleaseID, Sequence: 0,
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

	switch kind {
	case mpcceremony.CheckpointPhase1OutboundPublished:
		return buildOutboundCheckpoint(options, trusted, previous, previousRefs, phaseState)
	case mpcceremony.CheckpointPhase1ReceiptAccepted:
		return buildReceiptCheckpoint(options, trusted, previous, previousRefs, phaseState)
	case mpcceremony.CheckpointPhase1CandidateAccepted:
		return buildCandidateCheckpoint(options, trusted, previous, previousRefs, phaseState, chain)
	default:
		return builtCheckpointEvidence{}, fmt.Errorf("unsupported guarded checkpoint transition %q", kind)
	}
}

func buildOutboundCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState) (builtCheckpointEvidence, error) {
	recordBytes, record, recordRefs, err := loadSignedOperationalPair(options, mpcceremony.RecordHandoff, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	_ = recordBytes
	handoff := record.(*mpcceremony.TransferHandoff)
	index := previous.Phase1.AcceptedCount + 1
	policy := trusted.Definition.Phase1Policy
	if int(index) > len(policy.Participants) {
		return builtCheckpointEvidence{}, errors.New("no next phase1 participant in the authenticated schedule")
	}
	participantID := policy.Participants[index-1]
	participant, _ := trusted.Definition.ParticipantByID(participantID)
	if handoff.Phase != mpcceremony.Phase1 || handoff.Index != index || handoff.PredecessorHeadID != previous.Phase1.HeadRecordID ||
		handoff.SenderID != trusted.Definition.Coordinator.ID || handoff.SenderKeyID != trusted.Definition.Coordinator.KeyID ||
		handoff.RecipientID != participantID || handoff.RecipientKeyID != participant.Identity.KeyID ||
		!slices.Equal(handoff.Files, []mpcceremony.ArtifactRef{previous.Phase1.HeadPayload}) {
		return builtCheckpointEvidence{}, errors.New("outbound handoff does not bind the exact current head, next participant, and input payload")
	}
	transition := mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1OutboundPublished, Phase: mpcceremony.Phase1, Index: index,
		ParticipantID: participantID, AttemptID: options.AttemptID, Record: &recordRefs,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	checkpoint.AcceptedArtifacts = checkpointSortedArtifacts(append(append([]mpcceremony.ArtifactRef(nil), previous.AcceptedArtifacts...), recordRefs.Record, recordRefs.Signature)...)
	checkpoint.Submissions = append(append([]mpcceremony.CheckpointSubmissionSlot(nil), previous.Submissions...), mpcceremony.CheckpointSubmissionSlot{
		Kind: mpcceremony.CheckpointSubmissionReceipt, Phase: mpcceremony.Phase1, Index: index,
		IdentityID: participantID, AttemptID: options.AttemptID, ManifestKey: options.ManifestKey,
		BasisCheckpointSHA256: previousRefs.Record.Digest.SHA256, ParentHeadID: previous.Phase1.HeadRecordID,
		Status: mpcceremony.CheckpointSubmissionAllocated,
	})
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildReceiptCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState) (builtCheckpointEvidence, error) {
	envelopeBytes, envelopeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
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
	envelopeSignatureBytes, err := readRegularOperationalFile(options.TransitionRecordSignaturePath, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	envelope, err := mpcceremony.VerifySignedSubmissionEnvelope(trusted.Definition, previous, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	if envelope.Kind != mpcceremony.CheckpointSubmissionReceipt {
		return builtCheckpointEvidence{}, errors.New("receipt-accepted checkpoint requires a receipt submission envelope")
	}
	if err := verifyReceiptEnvelopePayloads(options.ArtifactRoot, trusted, previous, envelope); err != nil {
		return builtCheckpointEvidence{}, err
	}
	manifest, err := checkpointArtifactRef(options.ArtifactRoot, options.ManifestPath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("submission manifest: %w", err)
	}
	manifestBytes, err := readRegularOperationalFile(options.ManifestPath, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	ackBytes, ackRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.AcknowledgementPath, options.AcknowledgementSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("submission acknowledgement: %w", err)
	}
	ackSignatureBytes, err := readRegularOperationalFile(options.AcknowledgementSignaturePath, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, err
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
	evidence := checkpointSortedArtifacts(append([]mpcceremony.ArtifactRef{manifest}, envelope.Payloads...)...)
	transition := mpcceremony.CheckpointTransition{
		Kind: mpcceremony.CheckpointPhase1ReceiptAccepted, Phase: mpcceremony.Phase1,
		Index: slot.Index, ParticipantID: slot.IdentityID, AttemptID: slot.AttemptID,
		NextAttemptID: options.NextAttemptID, Record: &envelopeRefs, Acknowledgement: &ackRefs, Evidence: evidence,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	checkpoint.Phase1 = phaseState
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
		Kind: mpcceremony.CheckpointSubmissionCandidate, Phase: mpcceremony.Phase1, Index: slot.Index,
		IdentityID: slot.IdentityID, AttemptID: options.NextAttemptID, ManifestKey: options.NextManifestKey,
		BasisCheckpointSHA256: previousRefs.Record.Digest.SHA256, ParentHeadID: previous.Phase1.HeadRecordID,
		Status: mpcceremony.CheckpointSubmissionAllocated,
	})
	return finishTransitionCheckpoint(trusted, previous, checkpoint)
}

func buildCandidateCheckpoint(options CheckpointEvidenceOptions, trusted *mpcceremony.TrustedCeremony, previous mpcceremony.Checkpoint, previousRefs mpcceremony.SignedArtifactRefs, phaseState mpcceremony.CheckpointPhaseState, chain mpcceremony.Chain) (builtCheckpointEvidence, error) {
	if phaseState.AcceptedCount != previous.Phase1.AcceptedCount+1 || len(chain.Records) == 0 {
		return builtCheckpointEvidence{}, errors.New("candidate checkpoint chain must advance the previous head by exactly one record")
	}
	envelopeBytes, envelopeRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.TransitionRecordPath, options.TransitionRecordSignaturePath)
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
	if slot.Kind != mpcceremony.CheckpointSubmissionCandidate {
		return builtCheckpointEvidence{}, errors.New("candidate-accepted checkpoint requires a candidate submission slot")
	}
	envelopeSignatureBytes, err := readRegularOperationalFile(options.TransitionRecordSignaturePath, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	envelope, err := mpcceremony.VerifySignedSubmissionEnvelope(trusted.Definition, previous, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	acceptedRecord := chain.Records[len(chain.Records)-1]
	if acceptedRecord.Index != slot.Index || acceptedRecord.ParticipantID != slot.IdentityID ||
		acceptedRecord.PreviousRecordID != previous.Phase1.HeadRecordID {
		return builtCheckpointEvidence{}, errors.New("authenticated accepted chain record does not match the allocated candidate slot and previous head")
	}
	if err := verifyCandidateEnvelopePayloads(options.ArtifactRoot, envelope, acceptedRecord); err != nil {
		return builtCheckpointEvidence{}, err
	}
	manifest, err := checkpointArtifactRef(options.ArtifactRoot, options.ManifestPath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate manifest: %w", err)
	}
	manifestBytes, err := readRegularOperationalFile(options.ManifestPath, maxOperationalRecordBytes)
	if err != nil {
		return builtCheckpointEvidence{}, err
	}
	ackBytes, ackRefs, err := checkpointSignedBytes(options.ArtifactRoot, options.AcknowledgementPath, options.AcknowledgementSignaturePath)
	if err != nil {
		return builtCheckpointEvidence{}, fmt.Errorf("candidate acknowledgement: %w", err)
	}
	ackSignatureBytes, err := readRegularOperationalFile(options.AcknowledgementSignaturePath, 4096)
	if err != nil {
		return builtCheckpointEvidence{}, err
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
		Kind: mpcceremony.CheckpointPhase1CandidateAccepted, Phase: mpcceremony.Phase1,
		Index: slot.Index, ParticipantID: slot.IdentityID, AttemptID: slot.AttemptID,
		Record: &envelopeRefs, Acknowledgement: &ackRefs, Evidence: evidence,
	}
	checkpoint := previous
	checkpoint.Sequence++
	checkpoint.PreviousCheckpoint = &previousRefs
	checkpoint.Transition = transition
	checkpoint.Phase1 = phaseState
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

func checkpointSignedBytes(root, recordPath, signaturePath string) ([]byte, mpcceremony.SignedArtifactRefs, error) {
	recordBytes, err := readRegularOperationalFile(recordPath, maxOperationalRecordBytes)
	if err != nil {
		return nil, mpcceremony.SignedArtifactRefs{}, err
	}
	refs, err := checkpointPairRefs(root, recordPath, signaturePath)
	return recordBytes, refs, err
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
	if err := checkCustodyFile(root, ref); err != nil {
		return nil, err
	}
	return readRegularOperationalFile(filepath.Join(root, filepath.FromSlash(ref.Name)), limit)
}

func checkpointSortedArtifacts(values ...mpcceremony.ArtifactRef) []mpcceremony.ArtifactRef {
	result := append([]mpcceremony.ArtifactRef(nil), values...)
	slices.SortFunc(result, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return result
}
