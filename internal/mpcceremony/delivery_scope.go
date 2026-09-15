package mpcceremony

import (
	"errors"
	"fmt"
)

// ContributionScope identifies protocol work, independently of how its files
// are delivered. No storage location, launcher release, or delivery attempt is
// part of a participant's existing signed contribution.
type ContributionScope struct {
	CeremonyID    string `json:"ceremony_id"`
	Phase         Phase  `json:"phase"`
	Index         uint8  `json:"index"`
	ParticipantID string `json:"participant_id"`
	ParentHeadID  string `json:"parent_head_id"`
}

func (s ContributionScope) Validate() error {
	if err := validateHashID("ceremony_id", s.CeremonyID); err != nil {
		return err
	}
	if err := s.Phase.Validate(); err != nil {
		return err
	}
	if s.Index == 0 || s.Index > MaxParticipants {
		return errors.New("contribution scope requires a scheduled nonzero index")
	}
	if err := validateID("participant_id", s.ParticipantID); err != nil {
		return err
	}
	return validateHashID("parent_head_id", s.ParentHeadID)
}

// ValidateAssignment checks the frozen schedule, not whether this is the
// current turn. Checkpoint verification checks the authenticated current head.
func (s ContributionScope) ValidateAssignment(d CeremonyDefinition) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if s.CeremonyID != d.CeremonyID {
		return errors.New("contribution scope belongs to another ceremony")
	}
	policy := d.Phase1Policy
	if s.Phase == Phase2 {
		policy = d.Phase2Policy
	}
	if int(s.Index) > len(policy.Participants) || policy.Participants[int(s.Index)-1] != s.ParticipantID {
		return errors.New("contribution scope does not match the signed participant order")
	}
	return nil
}

const CandidateInventorySchemaV1 = "proof-tool-mpc-candidate-inventory-v1"

// CandidateInventory is a closed description of all submitted candidate bytes.
// Names are protocol-local basenames, not object-store keys or host paths.
// It is not another participant envelope and is not separately signed. Its
// domain-separated ID lets a coordinator checkpoint reject these exact bytes
// even when they are delivered again using a different attempt.
type CandidateInventory struct {
	Schema string            `json:"schema"`
	Scope  ContributionScope `json:"scope"`
	Files  []ArtifactRef     `json:"files"`
}

func (c CandidateInventory) Validate() error {
	if c.Schema != CandidateInventorySchemaV1 {
		return errors.New("unsupported candidate inventory schema")
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	expected := []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"}
	if len(c.Files) == 7 {
		expected = append(expected, "return-handoff.json", "return-handoff.sig")
	}
	if len(c.Files) != len(expected) {
		return errors.New("candidate requires contribution, signed attestation, signed cleanup, and either both return-handoff files or neither")
	}
	for i, ref := range c.Files {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("candidate file %d: %w", i, err)
		}
		if ref.Name != expected[i] {
			return fmt.Errorf("candidate file %d must be %s", i, expected[i])
		}
		limit := int64(maxSignedRecordBytes)
		if ref.Name == "contribution.bin" {
			limit = MaxArtifactSize
		} else if ref.Name == "attestation.sig" || ref.Name == "erasure.sig" || ref.Name == "return-handoff.sig" {
			limit = 4096
		}
		if ref.Digest.Size <= 0 || ref.Digest.Size > limit {
			return fmt.Errorf("candidate file %s exceeds its protocol size bound", ref.Name)
		}
	}
	return nil
}

// ID identifies bytes, not validity. Signature/cleanup/math verification and
// applicable return-custody requirements remain separate acceptance checks.
// Changed bytes produce a different candidate and require fresh verification.
func (c CandidateInventory) ID() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return canonicalHash("proof-tool/mpc-candidate-inventory/v1", c)
}

type DeliveryStatus string

const (
	DeliveryAllocated DeliveryStatus = "allocated"
	DeliveryAccepted  DeliveryStatus = "accepted"
	DeliveryRetired   DeliveryStatus = "retired"
	DeliveryRejected  DeliveryStatus = "rejected"
	// Bounds include successful attempts. They limit the signed state size and
	// require an explicit future format change rather than unbounded retry history.
	MaxDeliverySlotsV2                 = 4096
	MaxDeliveryAttemptsPerSubmissionV2 = 16
)

// DeliverySlotV2 is coordinator-authored tracking, not a claim that the
// participant approved a particular attempt ID. A retired delivery may carry
// the same valid bytes in a replacement slot; a rejected candidate may not.
type DeliverySlotV2 struct {
	Scope                ContributionScope        `json:"scope"`
	Kind                 CheckpointSubmissionKind `json:"kind"`
	AttemptID            string                   `json:"attempt_id"`
	Status               DeliveryStatus           `json:"status"`
	ContributionResultID string                   `json:"contribution_result_id,omitempty"`
}

func (s DeliverySlotV2) Validate() error {
	if err := s.Scope.Validate(); err != nil {
		return err
	}
	if s.Kind != CheckpointSubmissionReceipt && s.Kind != CheckpointSubmissionCandidate {
		return errors.New("unsupported delivery kind")
	}
	if err := validateHex(s.AttemptID, 16); err != nil {
		return fmt.Errorf("delivery attempt: %w", err)
	}
	switch s.Status {
	case DeliveryAllocated, DeliveryRetired:
		if s.ContributionResultID != "" {
			return errors.New("unaccepted delivery must not assert a candidate disposition")
		}
	case DeliveryAccepted:
		if s.Kind == CheckpointSubmissionReceipt {
			if s.ContributionResultID != "" {
				return errors.New("receipt delivery must not identify a candidate")
			}
			return nil
		}
		return validateHashID("contribution_result_id", s.ContributionResultID)
	case DeliveryRejected:
		if s.Kind != CheckpointSubmissionCandidate {
			return errors.New("retire an invalid receipt delivery; candidate rejection is only for candidate bytes")
		}
		return validateHashID("contribution_result_id", s.ContributionResultID)
	default:
		return errors.New("unsupported delivery status")
	}
	return nil
}

// ValidateDeliveryHistoryV2 checks the entire retained allocation history.
// Entries stay in allocation order; terminal dispositions are never discarded.
// Only AdvanceDeliveryV2 may change a currently allocated entry during a
// checkpoint transition. This function alone does not authenticate a history.
func ValidateDeliveryHistoryV2(slots []DeliverySlotV2) error {
	if slots == nil || len(slots) > MaxDeliverySlotsV2 {
		return errors.New("delivery history requires an explicit array within the protocol limit")
	}
	type group struct {
		scope                   ContributionScope
		count, active, accepted int
	}
	type groupKey struct {
		CeremonyID    string
		Phase         Phase
		Index         uint8
		ParticipantID string
		Kind          CheckpointSubmissionKind
	}
	groups := map[groupKey]*group{}
	attempts := map[string]bool{}
	rejected := map[string]bool{}
	accepted := map[string]bool{}
	for _, s := range slots {
		if err := s.Validate(); err != nil {
			return err
		}
		if attempts[s.AttemptID] {
			return errors.New("delivery attempt IDs must be globally unique")
		}
		attempts[s.AttemptID] = true
		key := groupKey{s.Scope.CeremonyID, s.Scope.Phase, s.Scope.Index, s.Scope.ParticipantID, s.Kind}
		g := groups[key]
		if g == nil {
			g = &group{scope: s.Scope}
			groups[key] = g
		}
		if g.scope != s.Scope {
			return errors.New("replacement delivery changed its predecessor")
		}
		g.count++
		if g.count > MaxDeliveryAttemptsPerSubmissionV2 {
			return errors.New("delivery retry limit reached for this submission")
		}
		switch s.Status {
		case DeliveryAllocated:
			g.active++
		case DeliveryAccepted:
			g.accepted++
			if s.ContributionResultID != "" {
				accepted[s.ContributionResultID] = true
			}
		case DeliveryRejected:
			rejected[s.ContributionResultID] = true
		}
		if g.active+g.accepted > 1 {
			return errors.New("a submission may have only one active allocation or one terminal acceptance")
		}
	}
	for id := range accepted {
		if rejected[id] {
			return errors.New("a rejected contribution result cannot be accepted through another delivery")
		}
	}
	return nil
}

// AllocateDeliveryV2 creates one fresh transport attempt. The checkpoint layer
// must additionally require the current scheduled turn and prerequisite record.
// No participant signature is requested for a delivery attempt.
func AllocateDeliveryV2(previous []DeliverySlotV2, scope ContributionScope, kind CheckpointSubmissionKind, attemptID string) ([]DeliverySlotV2, error) {
	if err := ValidateDeliveryHistoryV2(previous); err != nil {
		return nil, err
	}
	next := append(append([]DeliverySlotV2{}, previous...), DeliverySlotV2{Scope: scope, Kind: kind, AttemptID: attemptID, Status: DeliveryAllocated})
	if err := ValidateDeliveryHistoryV2(next); err != nil {
		return nil, err
	}
	return next, nil
}

// AdvanceDeliveryV2 records a disposition only for an active allocation. A
// rejected result remains in history. Retirement is for delivery problems and
// deliberately records no result ID. Inventory describes exact complete bytes;
// acceptance still requires the protocol/math verification performed by its
// checkpoint authoring command.
func AdvanceDeliveryV2(previous []DeliverySlotV2, attemptID string, status DeliveryStatus, inventory *CandidateInventory) ([]DeliverySlotV2, error) {
	if err := ValidateDeliveryHistoryV2(previous); err != nil {
		return nil, err
	}
	if status != DeliveryAccepted && status != DeliveryRetired && status != DeliveryRejected {
		return nil, errors.New("delivery transition requires a terminal disposition")
	}
	next := append([]DeliverySlotV2{}, previous...)
	index := -1
	for i, s := range previous {
		if s.AttemptID == attemptID {
			index = i
			break
		}
	}
	if index == -1 || next[index].Status != DeliveryAllocated {
		return nil, errors.New("only a currently allocated delivery may change")
	}
	slot := &next[index]
	needsInventory := slot.Kind == CheckpointSubmissionCandidate && (status == DeliveryAccepted || status == DeliveryRejected)
	if needsInventory != (inventory != nil) {
		return nil, errors.New("candidate disposition requires its exact inventory; other delivery changes must not include one")
	}
	if inventory != nil {
		if inventory.Scope != slot.Scope {
			return nil, errors.New("candidate inventory does not match delivery scope")
		}
		id, err := inventory.ID()
		if err != nil {
			return nil, err
		}
		slot.ContributionResultID = id
	}
	slot.Status = status
	if err := ValidateDeliveryHistoryV2(next); err != nil {
		return nil, err
	}
	return next, nil
}
