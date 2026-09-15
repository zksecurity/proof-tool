// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"
	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

func parseSubmission(invocation Invocation, args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, &usageError{message: "missing submission command", topic: []string{"submission"}}
	}
	if args[0] == "help" {
		return Invocation{}, &helpRequest{topic: append([]string{"submission"}, args[1:]...)}
	}
	if args[0] == "accept" {
		var options SubmissionAcceptOptions
		fs := commandFlagSet("submission accept")
		addCheckpointEvidenceFlags(fs, &options.CheckpointEvidenceOptions)
		fs.StringVar(&options.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
		fs.StringVar(&options.OutDir, "out-dir", "", "fresh atomic acceptance output directory")
		if err := parseFlags(fs, args[1:]); err != nil {
			return invocation, err
		}
		if options.AcknowledgementPath != "" || options.AcknowledgementSignaturePath != "" {
			return invocation, errors.New("submission accept creates the acknowledgement; do not supply acknowledgement flags")
		}
		validated := options.CheckpointEvidenceOptions
		validated.AcknowledgementPath, validated.AcknowledgementSignaturePath = "/pending/acknowledgement.json", "/pending/acknowledgement.sig"
		if err := validateCheckpointEvidenceOptions(validated); err != nil {
			return invocation, err
		}
		kind := mpcceremony.CheckpointTransitionKind(options.TransitionKind)
		if kind != mpcceremony.CheckpointPhase1ReceiptAccepted && kind != mpcceremony.CheckpointPhase1CandidateAccepted && kind != mpcceremony.CheckpointPhase2ReceiptAccepted && kind != mpcceremony.CheckpointPhase2CandidateAccepted {
			return invocation, errors.New("submission accept supports only receipt-accepted and candidate-accepted transitions")
		}
		if err := requireValues(pathValue("--coordinator-signing-key", options.CoordinatorSigningKey), pathValue("--out-dir", options.OutDir)); err != nil {
			return invocation, err
		}
		invocation.Command, invocation.Options = CommandSubmissionAccept, options
		return invocation, nil
	}
	if args[0] != "sign" {
		return Invocation{}, &usageError{message: fmt.Sprintf("unknown submission command %q", args[0]), topic: []string{"submission"}}
	}
	var options SubmissionSignOptions
	fs := commandFlagSet("submission sign")
	addCeremonyTrustFlags(fs, &options.CeremonyPath, &options.CeremonySignaturePath, &options.CoordinatorPublicKeyFile)
	fs.StringVar(&options.ArtifactRoot, "artifact-root", "", "root containing the complete fetched checkpoint ancestry")
	fs.StringVar(&options.CheckpointPath, "checkpoint", "", "exact allocation checkpoint")
	fs.StringVar(&options.CheckpointSignaturePath, "checkpoint-signature", "", "allocation checkpoint signature")
	fs.StringVar(&options.AttemptID, "attempt-id", "", "globally unique preallocated attempt ID")
	fs.StringVar(&options.ParticipantSigningKey, "participant-signing-key", "", "assigned participant private key")
	fs.StringVar(&options.ReceiptPath, "receipt", "", "exact signed receipt record for a receipt slot")
	fs.StringVar(&options.ReceiptSignaturePath, "receipt-signature", "", "detached receipt signature")
	fs.StringVar(&options.CandidateDir, "candidate-dir", "", "completed candidate directory for a candidate slot")
	fs.StringVar(&options.OutDir, "out-dir", "", "fresh atomic envelope output directory")
	if err := parseFlags(fs, args[1:]); err != nil {
		return invocation, err
	}
	if err := requireValues(
		pathValue("--ceremony", options.CeremonyPath), pathValue("--ceremony-signature", options.CeremonySignaturePath),
		pathValue("--coordinator-public-key-file", options.CoordinatorPublicKeyFile), pathValue("--artifact-root", options.ArtifactRoot),
		pathValue("--checkpoint", options.CheckpointPath), pathValue("--checkpoint-signature", options.CheckpointSignaturePath),
		value("--attempt-id", options.AttemptID), pathValue("--participant-signing-key", options.ParticipantSigningKey), pathValue("--out-dir", options.OutDir),
	); err != nil {
		return invocation, err
	}
	receipt := options.ReceiptPath != "" || options.ReceiptSignaturePath != ""
	candidate := options.CandidateDir != ""
	if receipt == candidate {
		return invocation, errors.New("supply exactly one payload form: --receipt with --receipt-signature, or --candidate-dir")
	}
	if receipt {
		if err := requireValues(pathValue("--receipt", options.ReceiptPath), pathValue("--receipt-signature", options.ReceiptSignaturePath)); err != nil {
			return invocation, err
		}
	}
	invocation.Command, invocation.Options = CommandSubmissionSign, options
	return invocation, nil
}

func executeSubmissionSign(options SubmissionSignOptions) (CommandResult, error) {
	checkpoint, checkpointBytes, err := verifyStoredCheckpointAncestry(CheckpointVerifyStoredOptions{
		InspectCheckpointOptions: InspectCheckpointOptions{InspectDefinitionOptions: InspectDefinitionOptions{CeremonyPath: options.CeremonyPath, CeremonySignaturePath: options.CeremonySignaturePath, CoordinatorPublicKeyFile: options.CoordinatorPublicKeyFile}, CheckpointPath: options.CheckpointPath, CheckpointSignaturePath: options.CheckpointSignaturePath},
		ArtifactRoot:             options.ArtifactRoot,
	}, options.CheckpointPath, options.CheckpointSignaturePath, make(map[string]struct{}), 0)
	if err != nil {
		return CommandResult{}, fmt.Errorf("allocation checkpoint ancestry: %w", err)
	}
	slot, err := allocatedSlotByAttempt(checkpoint, options.AttemptID)
	if err != nil {
		return CommandResult{}, err
	}
	trusted, definitionBytes, definitionSignatureBytes, err := loadExactInspectionCeremony(InspectDefinitionOptions{CeremonyPath: options.CeremonyPath, CeremonySignaturePath: options.CeremonySignaturePath, CoordinatorPublicKeyFile: options.CoordinatorPublicKeyFile})
	if err != nil {
		return CommandResult{}, err
	}
	payloads, err := submissionPayloadRefs(options, slot)
	if err != nil {
		return CommandResult{}, err
	}
	envelope := mpcceremony.SubmissionEnvelopeV1{
		Schema: mpcceremony.SubmissionEnvelopeSchemaV1, Workflow: checkpoint.Workflow,
		CeremonyID: checkpoint.CeremonyID,
		Definition: mpcceremony.SignedArtifactRefs{
			Record:    mpcceremony.ArtifactRef{Name: checkpoint.Definition.Record.Name, Digest: mpcceremony.NewDigest(definitionBytes)},
			Signature: mpcceremony.ArtifactRef{Name: checkpoint.Definition.Signature.Name, Digest: mpcceremony.NewDigest(definitionSignatureBytes)},
		},
		RelayReleaseID: checkpoint.RelayReleaseID,
		SubmitterID:    slot.IdentityID, SubmitterKeyID: participantKeyID(trusted.Definition, slot.IdentityID), SubmitterRole: mpcceremony.SubmissionRoleParticipant,
		Kind: slot.Kind, Phase: slot.Phase, Index: slot.Index, ParentCheckpointSHA256: slot.BasisCheckpointSHA256,
		AllocationCheckpointSHA256: mpcceremony.NewDigest(checkpointBytes).SHA256, ParentHeadID: slot.ParentHeadID,
		AttemptID: slot.AttemptID, ManifestKey: slot.ManifestKey, Payloads: payloads,
	}
	// Kind-specific semantic verification happens before the private key is loaded.
	if slot.Kind == mpcceremony.CheckpointSubmissionReceipt {
		if err := verifyReceiptEnvelopePayloads(options.ArtifactRoot, trusted, checkpoint, envelope); err != nil {
			return CommandResult{}, err
		}
	} else if err := verifyCandidateSubmissionFiles(options.CandidateDir, trusted.Definition, slot, payloads); err != nil {
		return CommandResult{}, err
	}
	key, _, err := keybundle.LoadExistingPrivateKey(options.ParticipantSigningKey)
	if err != nil {
		return CommandResult{}, err
	}
	record, signature, err := mpcceremony.SignSubmissionEnvelope(trusted.Definition, checkpoint, slot, envelope, key)
	if err != nil {
		return CommandResult{}, err
	}
	if err := writeAtomicSubmissionDir(options.OutDir, map[string][]byte{"envelope.json": record, "envelope.sig": signature}); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: checkpoint.CeremonyID, Phase: string(slot.Phase), Summary: fmt.Sprintf("signed authenticated %s submission for preallocated attempt", slot.Kind), Outputs: map[string]string{"envelope": filepath.Join(options.OutDir, "envelope.json"), "envelope_signature": filepath.Join(options.OutDir, "envelope.sig")}}, nil
}

func executeSubmissionAccept(options SubmissionAcceptOptions) (CommandResult, error) {
	var acknowledgementBytes, acknowledgementSignature []byte
	var coordinatorKey ed25519.PrivateKey
	options.AcceptanceSigner = func(trusted *mpcceremony.TrustedCeremony, checkpoint mpcceremony.Checkpoint, slot mpcceremony.CheckpointSubmissionSlot, envelope mpcceremony.SubmissionEnvelopeV1, envelopeRefs mpcceremony.SignedArtifactRefs, manifest mpcceremony.ArtifactRef) ([]byte, []byte, mpcceremony.SignedArtifactRefs, error) {
		ack := mpcceremony.SubmissionAcknowledgementV1{
			Schema: mpcceremony.SubmissionAcknowledgementSchemaV1, Workflow: envelope.Workflow,
			CeremonyID: envelope.CeremonyID, Definition: envelope.Definition, RelayReleaseID: envelope.RelayReleaseID,
			CoordinatorID: trusted.Definition.Coordinator.ID, CoordinatorKeyID: trusted.Definition.Coordinator.KeyID,
			SubmitterID: envelope.SubmitterID, SubmitterKeyID: envelope.SubmitterKeyID, SubmitterRole: envelope.SubmitterRole,
			Kind: envelope.Kind, Phase: envelope.Phase, Index: envelope.Index,
			ParentCheckpointSHA256: envelope.ParentCheckpointSHA256, AllocationCheckpointSHA256: envelope.AllocationCheckpointSHA256,
			ParentHeadID: envelope.ParentHeadID, AttemptID: envelope.AttemptID, ManifestKey: envelope.ManifestKey,
			Envelope: envelopeRefs, Manifest: manifest, Result: mpcceremony.SubmissionAccepted,
		}
		key, _, err := keybundle.LoadExistingPrivateKey(options.CoordinatorSigningKey)
		if err != nil {
			return nil, nil, mpcceremony.SignedArtifactRefs{}, err
		}
		record, signature, err := mpcceremony.SignSubmissionAcknowledgement(trusted.Definition, checkpoint, slot, envelope, envelopeRefs, manifest, ack, key)
		if err != nil {
			return nil, nil, mpcceremony.SignedArtifactRefs{}, err
		}
		base := "acknowledgements/" + slot.AttemptID
		refs := mpcceremony.SignedArtifactRefs{
			Record:    mpcceremony.ArtifactRef{Name: base + "/record.json", Digest: mpcceremony.NewDigest(record)},
			Signature: mpcceremony.ArtifactRef{Name: base + "/record.sig", Digest: mpcceremony.NewDigest(signature)},
		}
		if err := refs.Validate(); err != nil {
			return nil, nil, mpcceremony.SignedArtifactRefs{}, err
		}
		coordinatorKey, acknowledgementBytes, acknowledgementSignature = key, record, signature
		return record, signature, refs, nil
	}
	built, err := buildCheckpointEvidence(options.CheckpointEvidenceOptions)
	if err != nil {
		return CommandResult{}, err
	}
	if len(coordinatorKey) == 0 || len(acknowledgementBytes) == 0 {
		return CommandResult{}, errors.New("acceptance evidence did not reach authenticated signing boundary")
	}
	_, checkpointSignature, err := mpcceremony.SignRecord(built.checkpoint, built.trusted.Definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		return CommandResult{}, err
	}
	files := map[string][]byte{"acknowledgement.json": acknowledgementBytes, "acknowledgement.sig": acknowledgementSignature, "checkpoint.json": built.canonical, "checkpoint.sig": checkpointSignature}
	if err := writeAtomicSubmissionDir(options.OutDir, files); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: built.checkpoint.CeremonyID, Sequence: int(built.checkpoint.Sequence), Summary: fmt.Sprintf("accepted authenticated submission and signed checkpoint %d as one atomic result", built.checkpoint.Sequence), Outputs: map[string]string{
		"acknowledgement": filepath.Join(options.OutDir, "acknowledgement.json"), "acknowledgement_signature": filepath.Join(options.OutDir, "acknowledgement.sig"),
		"checkpoint": filepath.Join(options.OutDir, "checkpoint.json"), "checkpoint_signature": filepath.Join(options.OutDir, "checkpoint.sig"),
	}}, nil
}

func allocatedSlotByAttempt(checkpoint mpcceremony.Checkpoint, attemptID string) (mpcceremony.CheckpointSubmissionSlot, error) {
	var found *mpcceremony.CheckpointSubmissionSlot
	for i := range checkpoint.Submissions {
		slot := checkpoint.Submissions[i]
		if slot.AttemptID != attemptID {
			continue
		}
		if found != nil {
			return mpcceremony.CheckpointSubmissionSlot{}, errors.New("attempt ID is not globally unique in checkpoint")
		}
		copy := slot
		found = &copy
	}
	if found == nil || found.Status != mpcceremony.CheckpointSubmissionAllocated {
		return mpcceremony.CheckpointSubmissionSlot{}, errors.New("attempt ID does not name an allocated submission slot")
	}
	return *found, nil
}

func participantKeyID(definition mpcceremony.CeremonyDefinition, id string) string {
	participant, _ := definition.ParticipantByID(id)
	return participant.Identity.KeyID
}

func submissionPayloadRefs(options SubmissionSignOptions, slot mpcceremony.CheckpointSubmissionSlot) ([]mpcceremony.ArtifactRef, error) {
	if slot.Kind == mpcceremony.CheckpointSubmissionReceipt {
		if options.CandidateDir != "" {
			return nil, errors.New("receipt slot requires receipt payloads")
		}
		base := strings.TrimSuffix(slot.ManifestKey, "/manifest.json")
		refs := make([]mpcceremony.ArtifactRef, 0, 2)
		for _, item := range []struct{ path, name string }{{options.ReceiptPath, base + "/receipt.json"}, {options.ReceiptSignaturePath, base + "/receipt.sig"}} {
			ref, err := submissionFileRef(item.path, item.name)
			if err != nil {
				return nil, err
			}
			refs = append(refs, ref)
		}
		slices.SortFunc(refs, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
		return refs, nil
	}
	if slot.Kind != mpcceremony.CheckpointSubmissionCandidate || options.CandidateDir == "" || options.ReceiptPath != "" || options.ReceiptSignaturePath != "" {
		return nil, errors.New("candidate slot requires only --candidate-dir")
	}
	base := fmt.Sprintf("%s/contributions/%04d", slot.Phase, slot.Index)
	files := []struct{ file, name string }{{"contribution.bin", base + "/contribution.bin"}, {"attestation.json", base + "/attestation.json"}, {"attestation.sig", base + "/attestation.sig"}, {"erasure.json", base + "/erasure.json"}, {"erasure.sig", base + "/erasure.sig"}}
	refs := make([]mpcceremony.ArtifactRef, 0, len(files))
	for _, item := range files {
		ref, err := submissionFileRef(filepath.Join(options.CandidateDir, item.file), item.name)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b mpcceremony.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return refs, nil
}

func submissionFileRef(path, name string) (mpcceremony.ArtifactRef, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	if !info.Mode().IsRegular() {
		return mpcceremony.ArtifactRef{}, errors.New("submission payload must be a regular file, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return mpcceremony.ArtifactRef{}, errors.New("submission payload changed while being opened")
	}
	sha := sha256.New()
	blake, _ := blake2b.New256(nil)
	size, err := io.Copy(io.MultiWriter(sha, blake), f)
	if err != nil {
		return mpcceremony.ArtifactRef{}, err
	}
	if size <= 0 || size != info.Size() {
		return mpcceremony.ArtifactRef{}, errors.New("submission payload is empty or changed while hashing")
	}
	return mpcceremony.ArtifactRef{Name: name, Digest: mpcceremony.Digest{SHA256: fmt.Sprintf("sha256:%x", sha.Sum(nil)), Blake2b256: fmt.Sprintf("blake2b256:%x", blake.Sum(nil)), Size: size}}, nil
}

func verifyCandidateSubmissionFiles(candidateDir string, definition mpcceremony.CeremonyDefinition, slot mpcceremony.CheckpointSubmissionSlot, refs []mpcceremony.ArtifactRef) error {
	participant, ok := definition.ParticipantByID(slot.IdentityID)
	if !ok {
		return errors.New("candidate submitter is not an assigned participant")
	}
	publicBytes, err := hex.DecodeString(participant.Identity.Ed25519PublicKeyHex)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return errors.New("candidate participant has an invalid public key")
	}
	read := func(name string, limit int64) ([]byte, error) {
		return readRegularOperationalFile(filepath.Join(candidateDir, name), limit)
	}
	attestationBytes, err := read("attestation.json", maxOperationalRecordBytes)
	if err != nil {
		return err
	}
	attestationSignature, err := read("attestation.sig", 4096)
	if err != nil {
		return err
	}
	var attestation mpcceremony.ContributionAttestation
	if err := mpcceremony.VerifySignedRecord(attestationBytes, attestationSignature, &attestation, participant.Identity.KeyID, ed25519.PublicKey(publicBytes)); err != nil {
		return fmt.Errorf("candidate attestation: %w", err)
	}
	erasureBytes, err := read("erasure.json", maxOperationalRecordBytes)
	if err != nil {
		return err
	}
	erasureSignature, err := read("erasure.sig", 4096)
	if err != nil {
		return err
	}
	var erasure mpcceremony.ErasureAttestation
	if err := mpcceremony.VerifySignedRecord(erasureBytes, erasureSignature, &erasure, participant.Identity.KeyID, ed25519.PublicKey(publicBytes)); err != nil {
		return fmt.Errorf("candidate cleanup record: %w", err)
	}
	if err := mpcceremony.ValidateErasureForContribution(attestation, erasure); err != nil {
		return err
	}
	if attestation.CeremonyID != definition.CeremonyID || attestation.Phase != slot.Phase || attestation.Index != slot.Index || attestation.ParticipantID != slot.IdentityID || attestation.PreviousAcceptanceID != slot.ParentHeadID {
		return errors.New("candidate attestation does not match the exact allocated slot")
	}
	for _, ref := range refs {
		if strings.HasSuffix(ref.Name, "/contribution.bin") && ref.Digest != attestation.OutputPayload.Digest {
			return errors.New("candidate contribution bytes do not match the signed attestation")
		}
	}
	return nil
}

func writeAtomicSubmissionDir(outDir string, files map[string][]byte) (err error) {
	parent := filepath.Dir(outDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(outDir); err == nil {
		for name, expected := range files {
			actual, readErr := readRegularOperationalFile(filepath.Join(outDir, name), maxOperationalRecordBytes)
			if readErr != nil || !slices.Equal(actual, expected) {
				return errors.New("submission output already exists with conflicting or incomplete contents")
			}
		}
		entries, readErr := os.ReadDir(outDir)
		if readErr != nil || len(entries) != len(files) {
			return errors.New("submission output already exists with conflicting or incomplete contents")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".submission-*")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(tmp)
		}
	}()
	for name, data := range files {
		if err := writeFreshOperationalFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			return err
		}
	}
	if err := syncDirectory(tmp); err != nil {
		return err
	}
	if err := renameDirectoryNoReplace(tmp, outDir); err != nil {
		return err
	}
	complete = true
	return syncDirectory(parent)
}
