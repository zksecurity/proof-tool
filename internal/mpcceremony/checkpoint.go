package mpcceremony

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

const (
	CheckpointSchemaV1               = "proof-tool-mpc-checkpoint-v1"
	CheckpointSchema                 = "proof-tool-mpc-checkpoint-v2"
	StorageFirstWorkflowV1           = "storage-first-v1"
	CheckpointSigningRequestSchemaV1 = "proof-tool-mpc-checkpoint-signing-request-v1"
	// A full 255-participant Phase 1 retains roughly twenty immutable public
	// references per turn. Keep a hard parser bound while allowing the protocol
	// maximum plus future evidence growth.
	MaxCheckpointArtifacts = 8192
)

// CheckpointSigningRequest lets an isolated coordinator signer confirm that it
// is signing the exact checkpoint bytes re-derived from authenticated evidence.
type CheckpointSigningRequest struct {
	Schema           string `json:"schema"`
	CeremonyID       string `json:"ceremony_id"`
	CoordinatorKeyID string `json:"coordinator_key_id"`
	Checkpoint       Digest `json:"checkpoint"`
}

func NewCheckpointSigningRequest(definition CeremonyDefinition, checkpointBytes []byte) (CheckpointSigningRequest, error) {
	if err := definition.Validate(); err != nil {
		return CheckpointSigningRequest{}, err
	}
	if len(checkpointBytes) == 0 {
		return CheckpointSigningRequest{}, errors.New("checkpoint bytes are required")
	}
	request := CheckpointSigningRequest{
		Schema: CheckpointSigningRequestSchemaV1, CeremonyID: definition.CeremonyID,
		CoordinatorKeyID: definition.Coordinator.KeyID, Checkpoint: NewDigest(checkpointBytes),
	}
	return request, request.Validate()
}

func (r CheckpointSigningRequest) Validate() error {
	if r.Schema != CheckpointSigningRequestSchemaV1 {
		return fmt.Errorf("checkpoint signing request schema %q, want %q", r.Schema, CheckpointSigningRequestSchemaV1)
	}
	if err := validateHashID("ceremony_id", r.CeremonyID); err != nil {
		return err
	}
	if err := validateID("coordinator_key_id", r.CoordinatorKeyID); err != nil {
		return err
	}
	if err := r.Checkpoint.Validate(); err != nil {
		return fmt.Errorf("checkpoint digest: %w", err)
	}
	return nil
}

type CheckpointTransitionKind string

const (
	CheckpointInitial                 CheckpointTransitionKind = "initial"
	CheckpointPhase1OutboundPublished CheckpointTransitionKind = "phase1-outbound-published"
	CheckpointPhase1ReceiptAccepted   CheckpointTransitionKind = "phase1-receipt-accepted"
	CheckpointPhase1CandidateAccepted CheckpointTransitionKind = "phase1-candidate-accepted"
)

type CheckpointSubmissionKind string

const (
	CheckpointSubmissionReceipt   CheckpointSubmissionKind = "receipt"
	CheckpointSubmissionCandidate CheckpointSubmissionKind = "candidate"
)

type CheckpointSubmissionStatus string

const (
	CheckpointSubmissionAllocated CheckpointSubmissionStatus = "allocated"
	CheckpointSubmissionAccepted  CheckpointSubmissionStatus = "accepted"
)

// CheckpointPhaseState is the small authenticated projection needed to decide
// where a phase is. The signed chain remains the authority for its contents;
// this projection never substitutes for chain verification.
type CheckpointPhaseState struct {
	Phase         Phase              `json:"phase"`
	AcceptedCount uint8              `json:"accepted_count"`
	HeadRecordID  string             `json:"head_record_id"`
	HeadPayload   ArtifactRef        `json:"head_payload"`
	Chain         SignedArtifactRefs `json:"chain"`
}

func (s CheckpointPhaseState) Validate() error {
	if s.Phase != Phase1 {
		return fmt.Errorf("checkpoint phase %q, want phase1", s.Phase)
	}
	if s.AcceptedCount > MaxParticipants {
		return fmt.Errorf("accepted_count %d exceeds maximum %d", s.AcceptedCount, MaxParticipants)
	}
	if err := validateHashID("head_record_id", s.HeadRecordID); err != nil {
		return err
	}
	if err := s.HeadPayload.Validate(); err != nil {
		return fmt.Errorf("head_payload: %w", err)
	}
	if err := s.Chain.Validate(); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	return nil
}

// CheckpointSubmissionSlot is coordinator-allocated public protocol state. A
// credential may expire without changing the slot or its attempt identifier.
type CheckpointSubmissionSlot struct {
	Kind                  CheckpointSubmissionKind   `json:"kind"`
	Phase                 Phase                      `json:"phase"`
	Index                 uint8                      `json:"index"`
	IdentityID            string                     `json:"identity_id"`
	AttemptID             string                     `json:"attempt_id"`
	ManifestKey           string                     `json:"manifest_key"`
	BasisCheckpointSHA256 string                     `json:"basis_checkpoint_sha256"`
	ParentHeadID          string                     `json:"parent_head_id"`
	Status                CheckpointSubmissionStatus `json:"status"`
	Acknowledgement       *SignedArtifactRefs        `json:"acknowledgement"`
}

func (s CheckpointSubmissionSlot) Validate() error {
	switch s.Kind {
	case CheckpointSubmissionReceipt, CheckpointSubmissionCandidate:
	default:
		return fmt.Errorf("unsupported checkpoint submission kind %q", s.Kind)
	}
	if s.Phase != Phase1 {
		return fmt.Errorf("submission phase %q, want phase1", s.Phase)
	}
	if s.Index == 0 || s.Index > MaxParticipants {
		return fmt.Errorf("submission index %d must be between 1 and %d", s.Index, MaxParticipants)
	}
	if err := validateID("submission identity_id", s.IdentityID); err != nil {
		return err
	}
	if err := validateHex(s.AttemptID, 16); err != nil {
		return fmt.Errorf("submission attempt_id: %w", err)
	}
	if err := validateArtifactName(s.ManifestKey); err != nil {
		return fmt.Errorf("submission manifest_key: %w", err)
	}
	if err := validatePortableStorageName(s.ManifestKey); err != nil {
		return fmt.Errorf("submission manifest_key: %w", err)
	}
	if !strings.HasSuffix(s.ManifestKey, "/manifest.json") {
		return errors.New("submission manifest_key must end in /manifest.json")
	}
	if err := validateHashID("basis_checkpoint_sha256", s.BasisCheckpointSHA256); err != nil {
		return err
	}
	if err := validateHashID("parent_head_id", s.ParentHeadID); err != nil {
		return err
	}
	switch s.Status {
	case CheckpointSubmissionAllocated:
		if s.Acknowledgement != nil {
			return errors.New("allocated submission must not have an acknowledgement")
		}
	case CheckpointSubmissionAccepted:
		if s.Acknowledgement == nil {
			return errors.New("accepted submission requires an acknowledgement")
		}
		if err := s.Acknowledgement.Validate(); err != nil {
			return fmt.Errorf("submission acknowledgement: %w", err)
		}
	default:
		return fmt.Errorf("unsupported checkpoint submission status %q", s.Status)
	}
	return nil
}

func (s CheckpointSubmissionSlot) key() string {
	kindOrder := "1"
	if s.Kind == CheckpointSubmissionReceipt {
		kindOrder = "0"
	}
	return string(s.Phase) + "\x00" + fmt.Sprintf("%03d", s.Index) + "\x00" + s.IdentityID + "\x00" + kindOrder + "\x00" + s.AttemptID
}

// CheckpointTransition states the one protocol edge represented by a child
// checkpoint. Record identifies the role-authored input; acknowledgement is
// present only for coordinator acceptance edges.
type CheckpointTransition struct {
	Kind            CheckpointTransitionKind `json:"kind"`
	Phase           Phase                    `json:"phase"`
	Index           uint8                    `json:"index"`
	ParticipantID   string                   `json:"participant_id"`
	AttemptID       string                   `json:"attempt_id"`
	NextAttemptID   string                   `json:"next_attempt_id"`
	Record          *SignedArtifactRefs      `json:"record"`
	Acknowledgement *SignedArtifactRefs      `json:"acknowledgement"`
	Evidence        []ArtifactRef            `json:"evidence"`
}

func (t CheckpointTransition) Validate() error {
	if t.Kind == CheckpointInitial {
		if t.Phase != "" || t.Index != 0 || t.ParticipantID != "" || t.AttemptID != "" ||
			t.NextAttemptID != "" || t.Record != nil || t.Acknowledgement != nil || len(t.Evidence) != 0 {
			return errors.New("initial transition must not contain turn fields")
		}
		return nil
	}
	if t.Phase != Phase1 {
		return fmt.Errorf("transition phase %q, want phase1", t.Phase)
	}
	if t.Index == 0 || t.Index > MaxParticipants {
		return fmt.Errorf("transition index %d must be between 1 and %d", t.Index, MaxParticipants)
	}
	if err := validateID("transition participant_id", t.ParticipantID); err != nil {
		return err
	}
	if err := validateHex(t.AttemptID, 16); err != nil {
		return fmt.Errorf("transition attempt_id: %w", err)
	}
	if t.Record == nil {
		return errors.New("transition record is required")
	}
	if err := t.Record.Validate(); err != nil {
		return fmt.Errorf("transition record: %w", err)
	}
	switch t.Kind {
	case CheckpointPhase1OutboundPublished:
		if t.NextAttemptID != "" || t.Acknowledgement != nil || len(t.Evidence) != 0 {
			return errors.New("outbound transition must not contain a next attempt or acknowledgement")
		}
	case CheckpointPhase1ReceiptAccepted:
		if err := validateHex(t.NextAttemptID, 16); err != nil {
			return fmt.Errorf("transition next_attempt_id: %w", err)
		}
		if t.NextAttemptID == t.AttemptID {
			return errors.New("receipt and candidate attempts must be distinct")
		}
		if t.Acknowledgement == nil {
			return errors.New("receipt acceptance requires an acknowledgement")
		}
		if err := t.Acknowledgement.Validate(); err != nil {
			return fmt.Errorf("transition acknowledgement: %w", err)
		}
		if err := validateCheckpointTransitionEvidence(t.Evidence); err != nil {
			return err
		}
	case CheckpointPhase1CandidateAccepted:
		if t.NextAttemptID != "" || t.Acknowledgement == nil {
			return errors.New("candidate acceptance requires an acknowledgement and no next attempt")
		}
		if err := t.Acknowledgement.Validate(); err != nil {
			return fmt.Errorf("transition acknowledgement: %w", err)
		}
		if err := validateCheckpointTransitionEvidence(t.Evidence); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported checkpoint transition kind %q", t.Kind)
	}
	return nil
}

func validateCheckpointTransitionEvidence(evidence []ArtifactRef) error {
	if len(evidence) < 2 || len(evidence) > 65 {
		return errors.New("accepted submission transition requires between 2 and 65 evidence artifacts")
	}
	for i, ref := range evidence {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("transition evidence %d: %w", i, err)
		}
		if i > 0 && evidence[i-1].Name >= ref.Name {
			return errors.New("transition evidence must be strictly sorted by unique name")
		}
	}
	return nil
}

// Checkpoint is canonical coordinator-authored state. Object-store pointers,
// provider versions, credentials and grants deliberately do not appear here.
type Checkpoint struct {
	Schema             string                     `json:"schema"`
	Workflow           string                     `json:"workflow"`
	CeremonyID         string                     `json:"ceremony_id"`
	Definition         SignedArtifactRefs         `json:"definition"`
	AssurancePolicy    *AssurancePolicy           `json:"assurance_policy,omitempty"`
	RelayReleaseID     string                     `json:"relay_release_id"`
	Sequence           uint64                     `json:"sequence"`
	PreviousCheckpoint *SignedArtifactRefs        `json:"previous_checkpoint"`
	Transition         CheckpointTransition       `json:"transition"`
	Phase1             CheckpointPhaseState       `json:"phase1"`
	AcceptedArtifacts  []ArtifactRef              `json:"accepted_artifacts"`
	Submissions        []CheckpointSubmissionSlot `json:"submissions"`
}

func (c Checkpoint) Validate() error {
	switch c.Schema {
	case CheckpointSchema:
		if c.AssurancePolicy == nil {
			return errors.New("checkpoint v2 requires assurance_policy")
		}
	case CheckpointSchemaV1:
		if c.AssurancePolicy != nil {
			return errors.New("checkpoint v1 must not contain assurance_policy")
		}
	default:
		return fmt.Errorf("checkpoint schema %q, want %q or %q", c.Schema, CheckpointSchemaV1, CheckpointSchema)
	}
	if c.Workflow != StorageFirstWorkflowV1 {
		return fmt.Errorf("checkpoint workflow %q, want %q", c.Workflow, StorageFirstWorkflowV1)
	}
	if err := validateHashID("ceremony_id", c.CeremonyID); err != nil {
		return err
	}
	if err := c.Definition.Validate(); err != nil {
		return fmt.Errorf("definition: %w", err)
	}
	if err := validateID("relay_release_id", c.RelayReleaseID); err != nil {
		return err
	}
	if c.Sequence == 0 {
		if c.PreviousCheckpoint != nil || c.Transition.Kind != CheckpointInitial {
			return errors.New("sequence zero must be the initial checkpoint with no predecessor")
		}
	} else {
		if c.PreviousCheckpoint == nil {
			return errors.New("non-initial checkpoint requires previous_checkpoint")
		}
		if err := c.PreviousCheckpoint.Validate(); err != nil {
			return fmt.Errorf("previous_checkpoint: %w", err)
		}
		if c.Transition.Kind == CheckpointInitial {
			return errors.New("initial transition is permitted only at sequence zero")
		}
	}
	if err := c.Transition.Validate(); err != nil {
		return fmt.Errorf("transition: %w", err)
	}
	if err := c.Phase1.Validate(); err != nil {
		return fmt.Errorf("phase1: %w", err)
	}
	if c.Sequence == 0 && (c.Phase1.AcceptedCount != 0 || len(c.Submissions) != 0) {
		return errors.New("initial checkpoint must start before contributions and submissions")
	}
	if len(c.AcceptedArtifacts) == 0 || len(c.AcceptedArtifacts) > MaxCheckpointArtifacts {
		return fmt.Errorf("accepted_artifacts must contain between 1 and %d entries", MaxCheckpointArtifacts)
	}
	for i, artifact := range c.AcceptedArtifacts {
		if err := artifact.Validate(); err != nil {
			return fmt.Errorf("accepted_artifacts %d: %w", i, err)
		}
		if err := validatePortableStorageName(artifact.Name); err != nil {
			return fmt.Errorf("accepted_artifacts %d: %w", i, err)
		}
		if i > 0 && c.AcceptedArtifacts[i-1].Name >= artifact.Name {
			return errors.New("accepted_artifacts must be strictly sorted by unique name")
		}
	}
	if c.PreviousCheckpoint != nil {
		for label, ref := range map[string]ArtifactRef{"record": c.PreviousCheckpoint.Record, "signature": c.PreviousCheckpoint.Signature} {
			if err := validatePortableStorageName(ref.Name); err != nil {
				return fmt.Errorf("previous checkpoint %s: %w", label, err)
			}
		}
	}
	attempts := make(map[string]struct{}, len(c.Submissions))
	manifests := make(map[string]struct{}, len(c.Submissions))
	for i, slot := range c.Submissions {
		if err := slot.Validate(); err != nil {
			return fmt.Errorf("submissions %d: %w", i, err)
		}
		if i > 0 && c.Submissions[i-1].key() >= slot.key() {
			return errors.New("submissions must be strictly sorted with no duplicate attempt")
		}
		if _, exists := attempts[slot.AttemptID]; exists {
			return errors.New("submission attempt IDs must be globally unique within a checkpoint")
		}
		attempts[slot.AttemptID] = struct{}{}
		if _, exists := manifests[slot.ManifestKey]; exists {
			return errors.New("submission manifest keys must be globally unique within a checkpoint")
		}
		manifests[slot.ManifestKey] = struct{}{}
		if slot.Acknowledgement != nil &&
			(!slices.Contains(c.AcceptedArtifacts, slot.Acknowledgement.Record) ||
				!slices.Contains(c.AcceptedArtifacts, slot.Acknowledgement.Signature)) {
			return fmt.Errorf("submissions %d acknowledgement must be present in accepted_artifacts", i)
		}
	}
	if err := c.requireTransitionArtifacts(); err != nil {
		return err
	}
	for label, ref := range map[string]ArtifactRef{
		"definition record":      c.Definition.Record,
		"definition signature":   c.Definition.Signature,
		"phase1 head payload":    c.Phase1.HeadPayload,
		"phase1 chain":           c.Phase1.Chain.Record,
		"phase1 chain signature": c.Phase1.Chain.Signature,
	} {
		if !slices.Contains(c.AcceptedArtifacts, ref) {
			return fmt.Errorf("%s must be present in accepted_artifacts", label)
		}
	}
	return nil
}

// Storage-first names are materialized on both Linux and macOS. Restricting
// them to lowercase ASCII prevents case-folding and Unicode-normalization
// collisions on default Mac filesystems while retaining the existing clean
// relative-path rule.
func validatePortableStorageName(name string) error {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '/' || r == '.' || r == '-' || r == '_' {
			continue
		}
		return errors.New("storage-first artifact names must use lowercase ASCII letters, numbers, slash, dot, dash, or underscore")
	}
	return nil
}

func (c Checkpoint) requireTransitionArtifacts() error {
	contains := func(ref ArtifactRef) bool {
		return slices.Contains(c.AcceptedArtifacts, ref)
	}
	for label, signed := range map[string]*SignedArtifactRefs{
		"record":          c.Transition.Record,
		"acknowledgement": c.Transition.Acknowledgement,
	} {
		if signed != nil && (!contains(signed.Record) || !contains(signed.Signature)) {
			return fmt.Errorf("transition %s must be present in accepted_artifacts", label)
		}
	}
	for _, ref := range c.Transition.Evidence {
		if !contains(ref) {
			return errors.New("transition evidence must be present in accepted_artifacts")
		}
	}
	return nil
}

// VerifySignedCheckpoint authenticates exact canonical checkpoint bytes with
// the coordinator identity from the signed ceremony definition. The caller
// still verifies every referenced protocol artifact required by the edge.
func VerifySignedCheckpoint(definition CeremonyDefinition, definitionBytes, definitionSignatureBytes, checkpointBytes, signatureBytes []byte) (Checkpoint, error) {
	if err := definition.Validate(); err != nil {
		return Checkpoint{}, err
	}
	publicKey, err := identityPublicKey(definition.Coordinator)
	if err != nil {
		return Checkpoint{}, err
	}
	var authenticatedDefinition CeremonyDefinition
	if err := VerifySignedRecord(definitionBytes, definitionSignatureBytes, &authenticatedDefinition, definition.Coordinator.KeyID, publicKey); err != nil {
		return Checkpoint{}, fmt.Errorf("definition signature: %w", err)
	}
	if !reflect.DeepEqual(authenticatedDefinition, definition) {
		return Checkpoint{}, errors.New("authenticated definition bytes do not match supplied definition")
	}
	var checkpoint Checkpoint
	if err := VerifySignedRecord(checkpointBytes, signatureBytes, &checkpoint, definition.Coordinator.KeyID, ed25519.PublicKey(publicKey)); err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint signature: %w", err)
	}
	if checkpoint.CeremonyID != definition.CeremonyID {
		return Checkpoint{}, errors.New("checkpoint ceremony_id does not match definition")
	}
	if checkpoint.Definition.Record.Digest != NewDigest(definitionBytes) || checkpoint.Definition.Signature.Digest != NewDigest(definitionSignatureBytes) {
		return Checkpoint{}, errors.New("checkpoint definition references do not match authenticated definition bytes")
	}
	if err := validateCheckpointDefinitionVersion(definition, checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func validateCheckpointDefinitionVersion(definition CeremonyDefinition, checkpoint Checkpoint) error {
	if definition.Schema == DefinitionSchema {
		if checkpoint.Schema != CheckpointSchema || checkpoint.AssurancePolicy == nil || *checkpoint.AssurancePolicy != *definition.AssurancePolicy {
			return errors.New("definition v3 requires a checkpoint v2 with exactly matching assurance_policy")
		}
		return nil
	}
	if checkpoint.Schema != CheckpointSchemaV1 || checkpoint.AssurancePolicy != nil {
		return errors.New("legacy definition requires checkpoint v1 semantics")
	}
	return nil
}

// ValidateCheckpointTransition verifies the legal structural edge between two
// canonical checkpoints. It does not replace authentication of the signed
// chain and role-authored records referenced by that edge.
func ValidateCheckpointTransition(previous, next Checkpoint) error {
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("previous checkpoint: %w", err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("next checkpoint: %w", err)
	}
	previousBytes, err := MarshalCanonical(previous)
	if err != nil {
		return err
	}
	wantPrevious := NewDigest(previousBytes)
	if next.PreviousCheckpoint == nil || next.PreviousCheckpoint.Record.Digest != wantPrevious {
		return errors.New("next checkpoint does not bind the exact previous checkpoint")
	}
	if next.Sequence != previous.Sequence+1 {
		return fmt.Errorf("next checkpoint sequence %d, want %d", next.Sequence, previous.Sequence+1)
	}
	if next.Schema != previous.Schema || next.Workflow != previous.Workflow ||
		next.CeremonyID != previous.CeremonyID || next.Definition != previous.Definition ||
		next.RelayReleaseID != previous.RelayReleaseID {
		return errors.New("checkpoint immutable ceremony, workflow, definition, or release binding changed")
	}
	if !reflect.DeepEqual(next.AssurancePolicy, previous.AssurancePolicy) {
		return errors.New("checkpoint assurance policy changed")
	}
	if !artifactSubset(previous.AcceptedArtifacts, next.AcceptedArtifacts) {
		return errors.New("accepted artifact inventory is not append-only")
	}
	switch next.Transition.Kind {
	case CheckpointPhase1OutboundPublished:
		return validateOutboundTransition(previous, next)
	case CheckpointPhase1ReceiptAccepted:
		return validateReceiptTransition(previous, next)
	case CheckpointPhase1CandidateAccepted:
		return validateCandidateTransition(previous, next)
	default:
		return fmt.Errorf("transition %q cannot follow another checkpoint", next.Transition.Kind)
	}
}

func artifactSubset(previous, next []ArtifactRef) bool {
	for _, ref := range previous {
		if !slices.Contains(next, ref) {
			return false
		}
	}
	return true
}

func samePhaseState(a, b CheckpointPhaseState) bool { return a == b }

func transitionScopeMatchesSlot(t CheckpointTransition, s CheckpointSubmissionSlot, kind CheckpointSubmissionKind) bool {
	return s.Kind == kind && s.Phase == t.Phase && s.Index == t.Index &&
		s.IdentityID == t.ParticipantID && s.AttemptID == t.AttemptID
}

func slotEqual(a, b CheckpointSubmissionSlot) bool { return reflect.DeepEqual(a, b) }

func slotsEqual(a, b []CheckpointSubmissionSlot) bool { return reflect.DeepEqual(a, b) }

func signedArtifacts(refs *SignedArtifactRefs) []ArtifactRef {
	if refs == nil {
		return nil
	}
	return []ArtifactRef{refs.Record, refs.Signature}
}

func exactArtifactDelta(previous, next []ArtifactRef, expected ...ArtifactRef) bool {
	var actual []ArtifactRef
	for _, ref := range next {
		if !slices.Contains(previous, ref) {
			actual = append(actual, ref)
		}
	}
	slices.SortFunc(actual, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(expected, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	return slices.Equal(actual, expected)
}

func validateOutboundTransition(previous, next Checkpoint) error {
	t := next.Transition
	if !samePhaseState(previous.Phase1, next.Phase1) || t.Index != previous.Phase1.AcceptedCount+1 {
		return errors.New("outbound publication must preserve the head and target the next index")
	}
	if len(next.Submissions) != len(previous.Submissions)+1 || !slotsEqual(previous.Submissions, next.Submissions[:len(previous.Submissions)]) {
		return errors.New("outbound publication must append exactly one submission slot")
	}
	slot := next.Submissions[len(next.Submissions)-1]
	if !transitionScopeMatchesSlot(t, slot, CheckpointSubmissionReceipt) || slot.Status != CheckpointSubmissionAllocated ||
		slot.ParentHeadID != previous.Phase1.HeadRecordID || slot.BasisCheckpointSHA256 != next.PreviousCheckpoint.Record.Digest.SHA256 {
		return errors.New("outbound publication must allocate the matching receipt attempt for the current head")
	}
	if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, signedArtifacts(t.Record)...) {
		return errors.New("outbound publication accepted an unexpected artifact set")
	}
	return nil
}

func validateReceiptTransition(previous, next Checkpoint) error {
	t := next.Transition
	if !samePhaseState(previous.Phase1, next.Phase1) || len(next.Submissions) != len(previous.Submissions)+1 {
		return errors.New("receipt acceptance must preserve the head and append one candidate slot")
	}
	changed := -1
	for i := range previous.Submissions {
		before, after := previous.Submissions[i], next.Submissions[i]
		if slotEqual(before, after) {
			continue
		}
		if changed >= 0 || !transitionScopeMatchesSlot(t, before, CheckpointSubmissionReceipt) ||
			before.Status != CheckpointSubmissionAllocated || after.Status != CheckpointSubmissionAccepted ||
			before.Kind != after.Kind || before.Phase != after.Phase || before.Index != after.Index ||
			before.IdentityID != after.IdentityID || before.AttemptID != after.AttemptID ||
			before.ManifestKey != after.ManifestKey || before.BasisCheckpointSHA256 != after.BasisCheckpointSHA256 ||
			before.ParentHeadID != after.ParentHeadID || after.Acknowledgement == nil ||
			*after.Acknowledgement != *t.Acknowledgement {
			return errors.New("receipt acceptance changed a slot other than its acknowledgement and status")
		}
		changed = i
	}
	if changed < 0 {
		return errors.New("receipt acceptance did not accept its allocated receipt slot")
	}
	candidate := next.Submissions[len(next.Submissions)-1]
	if candidate.Kind != CheckpointSubmissionCandidate || candidate.Phase != t.Phase || candidate.Index != t.Index ||
		candidate.IdentityID != t.ParticipantID || candidate.AttemptID != t.NextAttemptID ||
		candidate.Status != CheckpointSubmissionAllocated || candidate.ParentHeadID != previous.Phase1.HeadRecordID ||
		candidate.BasisCheckpointSHA256 != next.PreviousCheckpoint.Record.Digest.SHA256 {
		return errors.New("receipt acceptance must append the matching candidate attempt")
	}
	expected := append(signedArtifacts(t.Record), signedArtifacts(t.Acknowledgement)...)
	expected = append(expected, t.Evidence...)
	if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, expected...) {
		return errors.New("receipt acceptance accepted an unexpected artifact set")
	}
	return nil
}

func validateCandidateTransition(previous, next Checkpoint) error {
	t := next.Transition
	if next.Phase1.AcceptedCount != previous.Phase1.AcceptedCount+1 || next.Phase1.AcceptedCount != t.Index ||
		next.Phase1.HeadRecordID == previous.Phase1.HeadRecordID || next.Phase1.HeadPayload == previous.Phase1.HeadPayload ||
		next.Phase1.Chain == previous.Phase1.Chain {
		return errors.New("candidate acceptance must advance exactly one phase1 head")
	}
	if len(next.Submissions) != len(previous.Submissions) {
		return errors.New("candidate acceptance must not add or remove submission slots")
	}
	changed := -1
	for i := range previous.Submissions {
		before, after := previous.Submissions[i], next.Submissions[i]
		if slotEqual(before, after) {
			continue
		}
		if changed >= 0 || !transitionScopeMatchesSlot(t, before, CheckpointSubmissionCandidate) ||
			before.Status != CheckpointSubmissionAllocated || after.Status != CheckpointSubmissionAccepted ||
			before.Kind != after.Kind || before.Phase != after.Phase || before.Index != after.Index ||
			before.IdentityID != after.IdentityID || before.AttemptID != after.AttemptID ||
			before.ManifestKey != after.ManifestKey || before.BasisCheckpointSHA256 != after.BasisCheckpointSHA256 ||
			before.ParentHeadID != after.ParentHeadID || after.Acknowledgement == nil ||
			*after.Acknowledgement != *t.Acknowledgement {
			return errors.New("candidate acceptance changed a slot other than its acknowledgement and status")
		}
		changed = i
	}
	if changed < 0 {
		return errors.New("candidate acceptance did not accept its allocated candidate slot")
	}
	expected := append(signedArtifacts(t.Record), signedArtifacts(t.Acknowledgement)...)
	expected = append(expected, t.Evidence...)
	// The accepted head payload is one of the submission envelope payloads and
	// therefore already appears in transition evidence.  The new signed chain
	// is coordinator-authored state and is added separately.
	expected = append(expected, next.Phase1.Chain.Record, next.Phase1.Chain.Signature)
	if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, expected...) {
		return errors.New("candidate acceptance accepted an unexpected artifact set")
	}
	return nil
}
