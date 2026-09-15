package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

const (
	SubmissionEnvelopeSchemaV1        = "proof-tool-mpc-submission-envelope-v1"
	SubmissionAcknowledgementSchemaV1 = "proof-tool-mpc-submission-acknowledgement-v1"
	SubmissionRoleParticipant         = "participant"
)

type SubmissionAcknowledgementResult string

const (
	SubmissionAccepted SubmissionAcknowledgementResult = "accepted"
	SubmissionRejected SubmissionAcknowledgementResult = "rejected"
)

// SubmissionEnvelopeV1 is the participant-authored, authenticated meaning of
// an inbox submission. The object-store manifest is only transport framing.
type SubmissionEnvelopeV1 struct {
	Schema                     string                   `json:"schema"`
	Workflow                   string                   `json:"workflow"`
	CeremonyID                 string                   `json:"ceremony_id"`
	Definition                 SignedArtifactRefs       `json:"definition"`
	RelayReleaseID             string                   `json:"relay_release_id"`
	SubmitterID                string                   `json:"submitter_id"`
	SubmitterKeyID             string                   `json:"submitter_key_id"`
	SubmitterRole              string                   `json:"submitter_role"`
	Kind                       CheckpointSubmissionKind `json:"kind"`
	Phase                      Phase                    `json:"phase"`
	Index                      uint8                    `json:"index"`
	ParentCheckpointSHA256     string                   `json:"parent_checkpoint_sha256"`
	AllocationCheckpointSHA256 string                   `json:"allocation_checkpoint_sha256"`
	ParentHeadID               string                   `json:"parent_head_id"`
	AttemptID                  string                   `json:"attempt_id"`
	ManifestKey                string                   `json:"manifest_key"`
	Payloads                   []ArtifactRef            `json:"payloads"`
}

func (e SubmissionEnvelopeV1) Validate() error {
	if e.Schema != SubmissionEnvelopeSchemaV1 {
		return fmt.Errorf("submission envelope schema %q, want %q", e.Schema, SubmissionEnvelopeSchemaV1)
	}
	if e.Workflow != StorageFirstWorkflowV1 {
		return fmt.Errorf("submission workflow %q, want %q", e.Workflow, StorageFirstWorkflowV1)
	}
	if err := validateHashID("ceremony_id", e.CeremonyID); err != nil {
		return err
	}
	if err := e.Definition.Validate(); err != nil {
		return fmt.Errorf("definition: %w", err)
	}
	if err := validateHashID("allocation_checkpoint_sha256", e.AllocationCheckpointSHA256); err != nil {
		return err
	}
	if err := validateID("relay_release_id", e.RelayReleaseID); err != nil {
		return err
	}
	if err := validateID("submitter_id", e.SubmitterID); err != nil {
		return err
	}
	if err := validateID("submitter_key_id", e.SubmitterKeyID); err != nil {
		return err
	}
	if e.SubmitterRole != SubmissionRoleParticipant {
		return fmt.Errorf("submitter_role %q, want %q", e.SubmitterRole, SubmissionRoleParticipant)
	}
	slot := CheckpointSubmissionSlot{Kind: e.Kind, Phase: e.Phase, Index: e.Index,
		IdentityID: e.SubmitterID, AttemptID: e.AttemptID, ManifestKey: e.ManifestKey,
		BasisCheckpointSHA256: e.ParentCheckpointSHA256, ParentHeadID: e.ParentHeadID,
		Status: CheckpointSubmissionAllocated}
	if err := slot.Validate(); err != nil {
		return fmt.Errorf("submission scope: %w", err)
	}
	if len(e.Payloads) == 0 || len(e.Payloads) > 64 {
		return errors.New("payloads must contain between 1 and 64 entries")
	}
	for i, payload := range e.Payloads {
		if err := payload.Validate(); err != nil {
			return fmt.Errorf("payloads %d: %w", i, err)
		}
		if payload.Name == e.ManifestKey {
			return errors.New("payload inventory must not contain its transport manifest")
		}
		if i > 0 && e.Payloads[i-1].Name >= payload.Name {
			return errors.New("payloads must be strictly sorted by unique name")
		}
	}
	return nil
}

// ValidateSubmissionEnvelopeBinding proves that the envelope occupies exactly
// one coordinator-preallocated slot in this checkpoint and frozen definition.
func ValidateSubmissionEnvelopeBinding(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot, envelope SubmissionEnvelopeV1) error {
	if err := definition.Validate(); err != nil {
		return fmt.Errorf("definition: %w", err)
	}
	if err := checkpoint.Validate(); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return err
	}
	if checkpoint.CeremonyID != definition.CeremonyID || envelope.CeremonyID != definition.CeremonyID {
		return errors.New("submission ceremony does not match the signed definition and checkpoint")
	}
	if envelope.Workflow != checkpoint.Workflow || envelope.Definition != checkpoint.Definition || envelope.RelayReleaseID != checkpoint.RelayReleaseID {
		return errors.New("submission workflow, definition, or release binding does not match checkpoint")
	}
	if err := slot.Validate(); err != nil {
		return fmt.Errorf("slot: %w", err)
	}
	if slot.Status != CheckpointSubmissionAllocated {
		return errors.New("submission slot is not allocated")
	}
	found := false
	for _, candidate := range checkpoint.Submissions {
		if candidate == slot {
			found = true
			break
		}
	}
	if !found {
		return errors.New("submission slot is not present exactly in checkpoint")
	}
	if envelope.Kind != slot.Kind || envelope.Phase != slot.Phase || envelope.Index != slot.Index ||
		envelope.SubmitterID != slot.IdentityID || envelope.AttemptID != slot.AttemptID ||
		envelope.ManifestKey != slot.ManifestKey || envelope.ParentCheckpointSHA256 != slot.BasisCheckpointSHA256 ||
		envelope.ParentHeadID != slot.ParentHeadID {
		return errors.New("submission envelope does not match its exact allocated slot")
	}
	checkpointBytes, err := MarshalCanonical(checkpoint)
	if err != nil {
		return fmt.Errorf("canonical checkpoint: %w", err)
	}
	if envelope.AllocationCheckpointSHA256 != NewDigest(checkpointBytes).SHA256 {
		return errors.New("submission envelope does not bind the exact checkpoint that allocated its slot")
	}
	participant, ok := definition.ParticipantByID(slot.IdentityID)
	if !ok {
		return errors.New("submission slot identity is not a participant in the signed definition")
	}
	if envelope.SubmitterKeyID != participant.Identity.KeyID {
		return errors.New("submission key does not match assigned participant")
	}
	policy, err := definition.PolicyForPhase(slot.Phase)
	if err != nil {
		return err
	}
	if int(slot.Index) > len(policy.Participants) || policy.Participants[slot.Index-1] != slot.IdentityID {
		return errors.New("submission slot does not match the signed participant order")
	}
	return nil
}

func SignSubmissionEnvelope(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot, envelope SubmissionEnvelopeV1, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if err := ValidateSubmissionEnvelopeBinding(definition, checkpoint, slot, envelope); err != nil {
		return nil, nil, err
	}
	participant, _ := definition.ParticipantByID(envelope.SubmitterID)
	if err := privateKeyMatchesIdentity(privateKey, participant.Identity); err != nil {
		return nil, nil, err
	}
	return SignRecord(envelope, envelope.SubmitterKeyID, privateKey)
}

func VerifySignedSubmissionEnvelope(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot, recordBytes, signatureBytes []byte) (SubmissionEnvelopeV1, error) {
	participant, ok := definition.ParticipantByID(slot.IdentityID)
	if !ok {
		return SubmissionEnvelopeV1{}, errors.New("submission slot identity is not a participant in the signed definition")
	}
	publicKey, err := identityPublicKey(participant.Identity)
	if err != nil {
		return SubmissionEnvelopeV1{}, err
	}
	var envelope SubmissionEnvelopeV1
	if err := VerifySignedRecord(recordBytes, signatureBytes, &envelope, participant.Identity.KeyID, publicKey); err != nil {
		return SubmissionEnvelopeV1{}, fmt.Errorf("submission envelope signature: %w", err)
	}
	if err := ValidateSubmissionEnvelopeBinding(definition, checkpoint, slot, envelope); err != nil {
		return SubmissionEnvelopeV1{}, err
	}
	return envelope, nil
}

// SubmissionAcknowledgementV1 is coordinator-authored. It binds the exact
// participant envelope and exact manifest bytes to one accepted/rejected result.
type SubmissionAcknowledgementV1 struct {
	Schema                     string                          `json:"schema"`
	Workflow                   string                          `json:"workflow"`
	CeremonyID                 string                          `json:"ceremony_id"`
	Definition                 SignedArtifactRefs              `json:"definition"`
	RelayReleaseID             string                          `json:"relay_release_id"`
	CoordinatorID              string                          `json:"coordinator_id"`
	CoordinatorKeyID           string                          `json:"coordinator_key_id"`
	SubmitterID                string                          `json:"submitter_id"`
	SubmitterKeyID             string                          `json:"submitter_key_id"`
	SubmitterRole              string                          `json:"submitter_role"`
	Kind                       CheckpointSubmissionKind        `json:"kind"`
	Phase                      Phase                           `json:"phase"`
	Index                      uint8                           `json:"index"`
	ParentCheckpointSHA256     string                          `json:"parent_checkpoint_sha256"`
	AllocationCheckpointSHA256 string                          `json:"allocation_checkpoint_sha256"`
	ParentHeadID               string                          `json:"parent_head_id"`
	AttemptID                  string                          `json:"attempt_id"`
	ManifestKey                string                          `json:"manifest_key"`
	Envelope                   SignedArtifactRefs              `json:"envelope"`
	Manifest                   ArtifactRef                     `json:"manifest"`
	Result                     SubmissionAcknowledgementResult `json:"result"`
	ReasonCode                 string                          `json:"reason_code,omitempty"`
}

func (a SubmissionAcknowledgementV1) Validate() error {
	if a.Schema != SubmissionAcknowledgementSchemaV1 {
		return fmt.Errorf("submission acknowledgement schema %q, want %q", a.Schema, SubmissionAcknowledgementSchemaV1)
	}
	if a.Workflow != StorageFirstWorkflowV1 {
		return fmt.Errorf("submission workflow %q, want %q", a.Workflow, StorageFirstWorkflowV1)
	}
	if err := validateHashID("ceremony_id", a.CeremonyID); err != nil {
		return err
	}
	if err := a.Definition.Validate(); err != nil {
		return fmt.Errorf("definition: %w", err)
	}
	if err := validateHashID("allocation_checkpoint_sha256", a.AllocationCheckpointSHA256); err != nil {
		return err
	}
	if err := validateID("relay_release_id", a.RelayReleaseID); err != nil {
		return err
	}
	if err := validateID("coordinator_id", a.CoordinatorID); err != nil {
		return err
	}
	if err := validateID("coordinator_key_id", a.CoordinatorKeyID); err != nil {
		return err
	}
	if err := validateID("submitter_id", a.SubmitterID); err != nil {
		return err
	}
	if err := validateID("submitter_key_id", a.SubmitterKeyID); err != nil {
		return err
	}
	if a.SubmitterRole != SubmissionRoleParticipant {
		return fmt.Errorf("submitter_role %q, want %q", a.SubmitterRole, SubmissionRoleParticipant)
	}
	slot := CheckpointSubmissionSlot{Kind: a.Kind, Phase: a.Phase, Index: a.Index, IdentityID: a.SubmitterID,
		AttemptID: a.AttemptID, ManifestKey: a.ManifestKey, BasisCheckpointSHA256: a.ParentCheckpointSHA256,
		ParentHeadID: a.ParentHeadID, Status: CheckpointSubmissionAllocated}
	if err := slot.Validate(); err != nil {
		return fmt.Errorf("submission scope: %w", err)
	}
	if err := a.Envelope.Validate(); err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	if err := a.Manifest.Validate(); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	if a.Manifest.Name != a.ManifestKey {
		return errors.New("manifest reference name does not match preallocated manifest key")
	}
	switch a.Result {
	case SubmissionAccepted:
		if a.ReasonCode != "" {
			return errors.New("accepted acknowledgement must not contain a reason_code")
		}
	case SubmissionRejected:
		if err := validateReasonCode(a.ReasonCode); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported acknowledgement result %q", a.Result)
	}
	return nil
}

func ValidateSubmissionAcknowledgementBinding(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot, envelope SubmissionEnvelopeV1, envelopeRefs SignedArtifactRefs, manifest ArtifactRef, acknowledgement SubmissionAcknowledgementV1) error {
	if err := ValidateSubmissionEnvelopeBinding(definition, checkpoint, slot, envelope); err != nil {
		return err
	}
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	if acknowledgement.Workflow != envelope.Workflow || acknowledgement.CeremonyID != envelope.CeremonyID ||
		acknowledgement.Definition != envelope.Definition || acknowledgement.RelayReleaseID != envelope.RelayReleaseID ||
		acknowledgement.SubmitterID != envelope.SubmitterID || acknowledgement.SubmitterKeyID != envelope.SubmitterKeyID ||
		acknowledgement.SubmitterRole != envelope.SubmitterRole || acknowledgement.Kind != envelope.Kind ||
		acknowledgement.Phase != envelope.Phase || acknowledgement.Index != envelope.Index ||
		acknowledgement.ParentCheckpointSHA256 != envelope.ParentCheckpointSHA256 || acknowledgement.ParentHeadID != envelope.ParentHeadID ||
		acknowledgement.AllocationCheckpointSHA256 != envelope.AllocationCheckpointSHA256 ||
		acknowledgement.AttemptID != envelope.AttemptID || acknowledgement.ManifestKey != envelope.ManifestKey {
		return errors.New("acknowledgement does not bind the exact submission envelope scope")
	}
	if acknowledgement.CoordinatorID != definition.Coordinator.ID || acknowledgement.CoordinatorKeyID != definition.Coordinator.KeyID {
		return errors.New("acknowledgement coordinator does not match the signed definition")
	}
	if acknowledgement.Envelope != envelopeRefs {
		return errors.New("acknowledgement does not bind the exact signed envelope bytes")
	}
	if acknowledgement.Manifest != manifest {
		return errors.New("acknowledgement does not bind the exact manifest bytes")
	}
	return nil
}

func SignSubmissionAcknowledgement(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot, envelope SubmissionEnvelopeV1, envelopeRefs SignedArtifactRefs, manifest ArtifactRef, acknowledgement SubmissionAcknowledgementV1, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if err := ValidateSubmissionAcknowledgementBinding(definition, checkpoint, slot, envelope, envelopeRefs, manifest, acknowledgement); err != nil {
		return nil, nil, err
	}
	if err := privateKeyMatchesIdentity(privateKey, definition.Coordinator); err != nil {
		return nil, nil, err
	}
	return SignRecord(acknowledgement, acknowledgement.CoordinatorKeyID, privateKey)
}

// VerifySignedSubmissionAcknowledgement authenticates both signature roles and
// derives every acknowledgement digest from the supplied exact bytes.
func VerifySignedSubmissionAcknowledgement(definition CeremonyDefinition, checkpoint Checkpoint, slot CheckpointSubmissionSlot,
	envelopeName, envelopeSignatureName string, envelopeBytes, envelopeSignatureBytes []byte,
	manifestName string, manifestBytes, acknowledgementBytes, acknowledgementSignatureBytes []byte) (SubmissionAcknowledgementV1, error) {
	envelope, err := VerifySignedSubmissionEnvelope(definition, checkpoint, slot, envelopeBytes, envelopeSignatureBytes)
	if err != nil {
		return SubmissionAcknowledgementV1{}, err
	}
	envelopeRefs := SignedArtifactRefs{
		Record:    ArtifactRef{Name: envelopeName, Digest: NewDigest(envelopeBytes)},
		Signature: ArtifactRef{Name: envelopeSignatureName, Digest: NewDigest(envelopeSignatureBytes)},
	}
	manifest := ArtifactRef{Name: manifestName, Digest: NewDigest(manifestBytes)}
	publicKey, err := identityPublicKey(definition.Coordinator)
	if err != nil {
		return SubmissionAcknowledgementV1{}, err
	}
	var acknowledgement SubmissionAcknowledgementV1
	if err := VerifySignedRecord(acknowledgementBytes, acknowledgementSignatureBytes, &acknowledgement, definition.Coordinator.KeyID, publicKey); err != nil {
		return SubmissionAcknowledgementV1{}, fmt.Errorf("submission acknowledgement signature: %w", err)
	}
	if err := ValidateSubmissionAcknowledgementBinding(definition, checkpoint, slot, envelope, envelopeRefs, manifest, acknowledgement); err != nil {
		return SubmissionAcknowledgementV1{}, err
	}
	return acknowledgement, nil
}

func privateKeyMatchesIdentity(privateKey ed25519.PrivateKey, identity Identity) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("Ed25519 private key is %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	publicKey, err := identityPublicKey(identity)
	if err != nil {
		return err
	}
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, publicKey) {
		return fmt.Errorf("private key does not match identity %q", identity.ID)
	}
	return nil
}

func validateReasonCode(value string) error {
	if value == "" || len(value) > 64 || value != strings.TrimSpace(value) {
		return errors.New("rejected acknowledgement requires a short reason_code")
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return errors.New("reason_code must use lowercase letters, numbers, and hyphens")
		}
	}
	return nil
}
