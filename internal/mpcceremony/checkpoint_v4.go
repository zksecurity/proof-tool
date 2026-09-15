package mpcceremony

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
)

const (
	CheckpointSchemaV4                                        = "proof-tool-mpc-checkpoint-v4"
	StorageFirstWorkflowV2                                    = "storage-first-v2"
	MaxCheckpointSequenceV4                                   = 16384
	CheckpointDeliveryRetired        CheckpointTransitionKind = "delivery-retired"
	CheckpointContributionRejected   CheckpointTransitionKind = "contribution-rejected"
	CheckpointDeliveryReallocated    CheckpointTransitionKind = "delivery-reallocated"
	CheckpointEnrollmentRecorded     CheckpointTransitionKind = "enrollment-recorded"
	CheckpointMirrorRecorded         CheckpointTransitionKind = "mirror-recorded"
	CheckpointWitnessRecorded        CheckpointTransitionKind = "witness-recorded"
	CheckpointBeaconEvidenceRecorded CheckpointTransitionKind = "beacon-evidence-recorded"
)

// CheckpointProgressV4 is the protocol projection used for guidance. It is not
// proof that referenced files have been downloaded or mathematically replayed.
type CheckpointProgressV4 struct {
	Phase1         CheckpointPhaseState  `json:"phase1"`
	Phase1Closure  *SignedArtifactRefs   `json:"phase1_closure,omitempty"`
	Phase1Beacon   *SignedArtifactRefs   `json:"phase1_beacon,omitempty"`
	Phase1Seal     *SignedArtifactRefs   `json:"phase1_seal,omitempty"`
	Phase2         *CheckpointPhaseState `json:"phase2,omitempty"`
	Phase2Closure  *SignedArtifactRefs   `json:"phase2_closure,omitempty"`
	Phase2Beacon   *SignedArtifactRefs   `json:"phase2_beacon,omitempty"`
	FinalCandidate *SignedArtifactRefs   `json:"final_candidate,omitempty"`
	FinalRelease   *SignedArtifactRefs   `json:"final_release,omitempty"`
}

type CheckpointTransitionV4 struct {
	Kind               CheckpointTransitionKind        `json:"kind"`
	Scope              *ContributionScope              `json:"scope,omitempty"`
	AttemptID          string                          `json:"attempt_id,omitempty"`
	NextAttemptID      string                          `json:"next_attempt_id,omitempty"`
	Record             *SignedArtifactRefs             `json:"record,omitempty"`
	Evidence           []ArtifactRef                   `json:"evidence"`
	Contribution       *CandidateInventory             `json:"contribution,omitempty"`
	ReplayVerification *CheckpointReplayVerificationV4 `json:"replay_verification,omitempty"`
}

// This is the coordinator's authenticated replay claim, not a proof that an
// untrusted coordinator actually ran the computation.
type CheckpointReplayVerificationV4 struct {
	Method     string `json:"method"`
	ToolBinary Digest `json:"tool_binary"`
}

// CheckpointV4 deliberately has no backend object key, release-image ID,
// participant delivery envelope, or separate coordinator acknowledgement.
// The coordinator signature commits the disposition and exact protocol files.
// Definition V1–V3 never use this type or its less demanding signer-replay rule.
type CheckpointV4 struct {
	Schema              string                 `json:"schema"`
	Workflow            string                 `json:"workflow"`
	CeremonyID          string                 `json:"ceremony_id"`
	Definition          SignedArtifactRefs     `json:"definition"`
	AssurancePolicy     *AssurancePolicy       `json:"assurance_policy"`
	ReleaseVerification string                 `json:"release_verification"`
	Sequence            uint64                 `json:"sequence"`
	PreviousCheckpoint  *SignedArtifactRefs    `json:"previous_checkpoint,omitempty"`
	Transition          CheckpointTransitionV4 `json:"transition"`
	Progress            CheckpointProgressV4   `json:"progress"`
	AcceptedArtifacts   []ArtifactRef          `json:"accepted_artifacts"`
	Deliveries          []DeliverySlotV2       `json:"deliveries"`
}

func validateV4ArtifactSet(refs []ArtifactRef, maximum int) error {
	if refs == nil || len(refs) > maximum {
		return errors.New("artifact list must be explicit and bounded")
	}
	names := map[string]bool{}
	for i, ref := range refs {
		if err := ref.Validate(); err != nil {
			return err
		}
		if err := validatePortableStorageName(ref.Name); err != nil {
			return err
		}
		if i > 0 && refs[i-1].Name >= ref.Name {
			return errors.New("artifact names must be sorted, unique, and must not overlap as files and directories")
		}
		for offset, r := range ref.Name {
			if r == '/' && names[ref.Name[:offset]] {
				return errors.New("artifact names overlap as files and directories")
			}
		}
		names[ref.Name] = true
	}
	return nil
}

func (c CheckpointV4) Validate() error {
	if c.Schema != CheckpointSchemaV4 || c.Workflow != StorageFirstWorkflowV2 || c.ReleaseVerification != CoordinatorReplayReleaseV1 {
		return errors.New("checkpoint v4 requires the explicit trusted-coordinator workflow")
	}
	if err := validateHashID("ceremony_id", c.CeremonyID); err != nil {
		return err
	}
	if err := c.Definition.Validate(); err != nil {
		return err
	}
	if c.AssurancePolicy == nil {
		return errors.New("checkpoint v4 requires explicit assurance policy")
	}
	if c.Sequence > MaxCheckpointSequenceV4 {
		return errors.New("checkpoint sequence exceeds protocol limit")
	}
	if (c.Sequence == 0) != (c.PreviousCheckpoint == nil) || (c.Sequence == 0) != (c.Transition.Kind == CheckpointInitial) {
		return errors.New("only the initial checkpoint has sequence zero and no predecessor")
	}
	if c.PreviousCheckpoint != nil {
		if err := c.PreviousCheckpoint.Validate(); err != nil {
			return err
		}
		for _, ref := range signedArtifacts(c.PreviousCheckpoint) {
			if err := validatePortableStorageName(ref.Name); err != nil {
				return err
			}
		}
	}
	if err := validateV4ArtifactSet(c.AcceptedArtifacts, MaxCheckpointArtifacts); err != nil {
		return err
	}
	if err := ValidateDeliveryHistoryV2(c.Deliveries); err != nil {
		return err
	}
	if err := c.Transition.Validate(); err != nil {
		return err
	}
	if err := c.Progress.Phase1.Validate(); err != nil {
		return err
	}
	if c.Progress.Phase1.Phase != Phase1 {
		return errors.New("phase1 projection identifies another phase")
	}
	refs := []ArtifactRef{c.Definition.Record, c.Definition.Signature, c.Progress.Phase1.HeadPayload, c.Progress.Phase1.Chain.Record, c.Progress.Phase1.Chain.Signature}
	if c.Progress.Phase2 != nil {
		if c.Progress.Phase1Seal == nil || c.Progress.Phase2.Phase != Phase2 {
			return errors.New("phase2 requires a sealed phase1")
		}
		if err := c.Progress.Phase2.Validate(); err != nil {
			return err
		}
		refs = append(refs, c.Progress.Phase2.HeadPayload, c.Progress.Phase2.Chain.Record, c.Progress.Phase2.Chain.Signature)
	}
	stages := []*SignedArtifactRefs{c.Progress.Phase1Closure, c.Progress.Phase1Beacon, c.Progress.Phase1Seal, c.Progress.Phase2Closure, c.Progress.Phase2Beacon, c.Progress.FinalCandidate, c.Progress.FinalRelease}
	missing := false
	for i, stage := range stages {
		if stage == nil {
			missing = true
			continue
		}
		if missing || (i >= 3 && c.Progress.Phase2 == nil) {
			return errors.New("checkpoint skipped a required lifecycle stage")
		}
		if err := stage.Validate(); err != nil {
			return err
		}
		refs = append(refs, stage.Record, stage.Signature)
	}
	refs = append(refs, signedArtifacts(c.Transition.Record)...)
	refs = append(refs, c.Transition.Evidence...)
	for _, ref := range refs {
		if !slices.Contains(c.AcceptedArtifacts, ref) {
			return errors.New("checkpoint references an artifact outside its accepted inventory")
		}
	}
	for _, slot := range c.Deliveries {
		if slot.Scope.CeremonyID != c.CeremonyID {
			return errors.New("delivery belongs to another ceremony")
		}
		if slot.Status == DeliveryAllocated {
			if err := c.Progress.currentTurn(slot.Scope); err != nil {
				return err
			}
		}
	}
	if c.Sequence == 0 {
		if c.Progress.Phase1.AcceptedCount != 0 || c.Progress.Phase2 != nil || c.Progress.Phase1Closure != nil || len(c.Deliveries) != 0 || len(c.AcceptedArtifacts) != 5 {
			return errors.New("initial checkpoint must contain exactly the signed definition and genesis chain/payload")
		}
	}
	return nil
}

func (t CheckpointTransitionV4) Validate() error {
	if t.Kind == CheckpointFinalCandidateRecorded {
		if t.ReplayVerification == nil || t.ReplayVerification.Method != CoordinatorReplayReleaseV1 {
			return errors.New("final candidate requires the explicit coordinator full replay claim")
		}
		if err := t.ReplayVerification.ToolBinary.Validate(); err != nil {
			return err
		}
	} else if t.ReplayVerification != nil {
		return errors.New("only final candidate preparation records full replay verification")
	}
	if err := validateV4ArtifactSet(t.Evidence, MaxCheckpointArtifacts); err != nil {
		return err
	}
	if t.Kind == CheckpointInitial {
		if t.Scope != nil || t.AttemptID != "" || t.NextAttemptID != "" || t.Record != nil || t.Contribution != nil || len(t.Evidence) != 0 {
			return errors.New("initial transition has extra fields")
		}
		return nil
	}
	turn := t.Kind == CheckpointPhase1OutboundPublished || t.Kind == CheckpointPhase2OutboundPublished || t.Kind == CheckpointPhase1ReceiptAccepted || t.Kind == CheckpointPhase2ReceiptAccepted || t.Kind == CheckpointPhase1CandidateAccepted || t.Kind == CheckpointPhase2CandidateAccepted || t.Kind == CheckpointDeliveryRetired || t.Kind == CheckpointContributionRejected || t.Kind == CheckpointDeliveryReallocated
	if turn {
		if t.Scope == nil {
			return errors.New("turn transition requires contribution scope")
		}
		if err := t.Scope.Validate(); err != nil {
			return err
		}
		if err := validateHex(t.AttemptID, 16); err != nil {
			return err
		}
		wantPhase := Phase1
		if t.Kind == CheckpointPhase2OutboundPublished || t.Kind == CheckpointPhase2ReceiptAccepted || t.Kind == CheckpointPhase2CandidateAccepted {
			wantPhase = Phase2
		}
		if t.Kind != CheckpointDeliveryRetired && t.Kind != CheckpointContributionRejected && t.Kind != CheckpointDeliveryReallocated && t.Scope.Phase != wantPhase {
			return errors.New("transition kind and phase disagree")
		}
		replacement := t.Kind == CheckpointPhase1ReceiptAccepted || t.Kind == CheckpointPhase2ReceiptAccepted || t.Kind == CheckpointDeliveryReallocated || ((t.Kind == CheckpointDeliveryRetired || t.Kind == CheckpointContributionRejected) && t.NextAttemptID != "")
		if replacement {
			if err := validateHex(t.NextAttemptID, 16); err != nil {
				return err
			}
			if t.NextAttemptID == t.AttemptID {
				return errors.New("replacement delivery requires a fresh attempt ID")
			}
		} else if t.NextAttemptID != "" {
			return errors.New("unexpected next attempt")
		}
		candidate := t.Kind == CheckpointPhase1CandidateAccepted || t.Kind == CheckpointPhase2CandidateAccepted || t.Kind == CheckpointContributionRejected
		if candidate != (t.Contribution != nil) {
			return errors.New("candidate disposition requires its complete inventory and other transitions forbid it")
		}
		if candidate {
			if err := t.Contribution.Validate(); err != nil {
				return err
			}
			if t.Contribution.Scope != *t.Scope {
				return errors.New("transition inventory scope differs")
			}
		}
		if t.Kind == CheckpointDeliveryRetired || t.Kind == CheckpointContributionRejected || t.Kind == CheckpointDeliveryReallocated {
			if t.Record != nil || len(t.Evidence) != 0 {
				return errors.New("delivery-only changes must not publish payloads as accepted evidence")
			}
			return nil
		}
	} else {
		if t.Scope != nil || t.AttemptID != "" || t.NextAttemptID != "" || t.Contribution != nil {
			return errors.New("lifecycle transition must not contain turn fields")
		}
		switch t.Kind {
		case CheckpointEnrollmentRecorded:
			if len(t.Evidence) != 1 {
				return errors.New("enrollment transition requires its disclosure artifact")
			}
		case CheckpointMirrorRecorded, CheckpointWitnessRecorded:
			if len(t.Evidence) != 0 {
				return errors.New("observer evidence edge adds only its signed receipt")
			}
		case CheckpointBeaconEvidenceRecorded:
			if len(t.Evidence) < 2 || len(t.Evidence) > 16 {
				return errors.New("beacon evidence edge requires two to sixteen raw responses")
			}
		case CheckpointPhase1Closed, CheckpointPhase2Closed:
			if len(t.Evidence) != 0 {
				return errors.New("closure transition only adds the signed closure")
			}
		case CheckpointPhase1BeaconRecorded, CheckpointPhase2BeaconRecorded, CheckpointPhase1Sealed, CheckpointPhase2Initialized:
			if len(t.Evidence) != 1 {
				return errors.New("lifecycle transition requires exactly one payload artifact")
			}
		case CheckpointFinalCandidateRecorded, CheckpointFinalReleaseRecorded:
			if len(t.Evidence) == 0 {
				return errors.New("final transition requires its closed file inventory")
			}
		default:
			return errors.New("unsupported v4 checkpoint transition")
		}
	}
	if t.Record == nil {
		return errors.New("transition requires the existing signed protocol record")
	}
	return t.Record.Validate()
}

// VerifySignedCheckpointV4 authenticates coordinator state and frozen policy.
// The caller verifies the predecessor edge and the referenced artifact bytes.
// This function deliberately performs no contribution algebra for routine sync.
func VerifySignedCheckpointV4(d CeremonyDefinition, definitionBytes, definitionSignature, checkpointBytes, signature []byte) (CheckpointV4, error) {
	var c CheckpointV4
	if err := d.Validate(); err != nil {
		return c, err
	}
	if d.Schema != DefinitionSchemaV4 {
		return c, errors.New("checkpoint v4 requires definition v4")
	}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return c, err
	}
	var actual CeremonyDefinition
	if err := VerifySignedRecord(definitionBytes, definitionSignature, &actual, d.Coordinator.KeyID, key); err != nil {
		return c, err
	}
	if !reflect.DeepEqual(actual, d) {
		return c, errors.New("supplied definition differs from authenticated bytes")
	}
	if err := VerifySignedRecord(checkpointBytes, signature, &c, d.Coordinator.KeyID, key); err != nil {
		return CheckpointV4{}, err
	}
	if err := validateCheckpointDefinitionBindingV4(d, definitionBytes, definitionSignature, c); err != nil {
		return CheckpointV4{}, err
	}
	return c, nil
}

func validateCheckpointDefinitionBindingV4(d CeremonyDefinition, definitionBytes, definitionSignature []byte, c CheckpointV4) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if d.Schema != DefinitionSchemaV4 {
		return errors.New("checkpoint v4 requires definition v4")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.CeremonyID != d.CeremonyID || c.Definition.Record.Digest != NewDigest(definitionBytes) || c.Definition.Signature.Digest != NewDigest(definitionSignature) || !reflect.DeepEqual(c.AssurancePolicy, d.AssurancePolicy) || c.ReleaseVerification != d.ReleaseVerification {
		return errors.New("checkpoint changed its exact definition or signed policy")
	}
	if claim := c.Transition.ReplayVerification; claim != nil && !d.Software.AllowsToolBinary(claim.ToolBinary) {
		return errors.New("checkpoint replay claim names an unapproved executable")
	}
	for _, slot := range c.Deliveries {
		if err := slot.Scope.ValidateAssignment(d); err != nil {
			return err
		}
	}
	if c.Transition.Scope != nil {
		if err := c.Transition.Scope.ValidateAssignment(d); err != nil {
			return err
		}
	}
	if int(c.Progress.Phase1.AcceptedCount) > len(d.Phase1Policy.Participants) || c.Progress.Phase2 != nil && int(c.Progress.Phase2.AcceptedCount) > len(d.Phase2Policy.Participants) {
		return errors.New("checkpoint contribution count exceeds signed schedule")
	}
	if c.Progress.Phase1Closure != nil && c.Progress.Phase1.AcceptedCount < d.Phase1Policy.Minimum || c.Progress.Phase2Closure != nil && c.Progress.Phase2.AcceptedCount < d.Phase2Policy.Minimum {
		return errors.New("closure precedes required contribution minimum")
	}
	if c.Sequence == 0 && c.Progress.Phase1.HeadPayload != d.Phase1Genesis {
		return errors.New("initial checkpoint changed definition genesis payload")
	}
	return nil
}

func (p CheckpointProgressV4) currentTurn(scope ContributionScope) error {
	state := p.Phase1
	if scope.Phase == Phase1 {
		if p.Phase1Closure != nil || p.Phase2 != nil {
			return errors.New("phase1 is no longer accepting contributions")
		}
	} else {
		if p.Phase2 == nil || p.Phase2Closure != nil {
			return errors.New("phase2 is not accepting contributions")
		}
		state = *p.Phase2
	}
	if int(scope.Index) != int(state.AcceptedCount)+1 || scope.ParentHeadID != state.HeadRecordID {
		return errors.New("turn does not follow the exact accepted head")
	}
	return nil
}

// ValidateCheckpointTransitionV4 validates a structural edge without replaying
// mathematics. Authoring must first verify the actual signed protocol records
// and perform the existing coordinator verification for candidate acceptance.
// This structs-only check cannot compare predecessor signature bytes. Sync
// callers must use VerifyCheckpointEdgeV4, then hash referenced artifact bytes.
func ValidateCheckpointTransitionV4(previous, next CheckpointV4) error {
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("previous checkpoint: %w", err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("next checkpoint: %w", err)
	}
	before, err := MarshalCanonical(previous)
	if err != nil {
		return err
	}
	if next.PreviousCheckpoint == nil || next.PreviousCheckpoint.Record.Digest != NewDigest(before) || next.Sequence != previous.Sequence+1 {
		return errors.New("checkpoint does not follow its exact predecessor")
	}
	if previous.CeremonyID != next.CeremonyID || previous.Definition != next.Definition || !reflect.DeepEqual(previous.AssurancePolicy, next.AssurancePolicy) || previous.ReleaseVerification != next.ReleaseVerification {
		return errors.New("checkpoint changed immutable ceremony policy")
	}
	if !artifactSubset(previous.AcceptedArtifacts, next.AcceptedArtifacts) {
		return errors.New("accepted artifact inventory must remain append-only")
	}
	t := next.Transition
	if t.Kind == CheckpointEnrollmentRecorded || t.Kind == CheckpointMirrorRecorded || t.Kind == CheckpointWitnessRecorded || t.Kind == CheckpointBeaconEvidenceRecorded {
		if previous.Progress.FinalRelease != nil {
			return errors.New("cannot add assurance evidence after final release")
		}
		if !reflect.DeepEqual(previous.Progress, next.Progress) || !reflect.DeepEqual(previous.Deliveries, next.Deliveries) {
			return errors.New("evidence edge changed protocol progress or deliveries")
		}
		if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, append(signedArtifacts(t.Record), t.Evidence...)...) {
			return errors.New("evidence edge changed unrelated artifacts")
		}
		return nil
	}
	if t.Scope != nil {
		if t.Scope.CeremonyID != next.CeremonyID {
			return errors.New("transition belongs to another ceremony")
		}
		if err := previous.Progress.currentTurn(*t.Scope); err != nil {
			return err
		}
		return validateV4TurnTransition(previous, next)
	}
	if !reflect.DeepEqual(previous.Deliveries, next.Deliveries) {
		return errors.New("lifecycle edge changed delivery history")
	}
	for _, s := range previous.Deliveries {
		if s.Status == DeliveryAllocated {
			return errors.New("resolve allocated deliveries before advancing lifecycle")
		}
	}
	want := previous.Progress
	switch t.Kind {
	case CheckpointPhase1Closed:
		if want.Phase1Closure != nil || want.Phase2 != nil {
			return errors.New("phase1 already closed")
		}
		want.Phase1Closure = t.Record
	case CheckpointPhase1BeaconRecorded:
		if want.Phase1Closure == nil || want.Phase1Beacon != nil {
			return errors.New("phase1 beacon requires unsealed closure")
		}
		want.Phase1Beacon = t.Record
	case CheckpointPhase1Sealed:
		if want.Phase1Beacon == nil || want.Phase1Seal != nil {
			return errors.New("phase1 seal requires its beacon")
		}
		want.Phase1Seal = t.Record
	case CheckpointPhase2Initialized:
		if want.Phase1Seal == nil || want.Phase2 != nil || next.Progress.Phase2 == nil {
			return errors.New("phase2 genesis requires sealed phase1 and no existing phase2")
		}
		state := next.Progress.Phase2
		if state.AcceptedCount != 0 || state.Chain != *t.Record || state.HeadPayload != t.Evidence[0] {
			return errors.New("phase2 initialization does not match its signed genesis")
		}
		want.Phase2 = state
	case CheckpointPhase2Closed:
		if want.Phase2 == nil || want.Phase2Closure != nil {
			return errors.New("phase2 closure requires open phase2")
		}
		want.Phase2Closure = t.Record
	case CheckpointPhase2BeaconRecorded:
		if want.Phase2Closure == nil || want.Phase2Beacon != nil {
			return errors.New("phase2 beacon requires its closure")
		}
		want.Phase2Beacon = t.Record
	case CheckpointFinalCandidateRecorded:
		if want.Phase2Beacon == nil || want.FinalCandidate != nil {
			return errors.New("final candidate requires both completed phases")
		}
		want.FinalCandidate = t.Record
	case CheckpointFinalReleaseRecorded:
		if want.FinalCandidate == nil || want.FinalRelease != nil {
			return errors.New("final release requires a frozen final candidate")
		}
		want.FinalRelease = t.Record
	default:
		return errors.New("unsupported lifecycle edge")
	}
	if !reflect.DeepEqual(want, next.Progress) {
		return errors.New("lifecycle edge changed unrelated ceremony state")
	}
	expected := append(signedArtifacts(t.Record), t.Evidence...)
	if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, expected...) {
		return errors.New("lifecycle edge published an unexpected artifact set")
	}
	return nil
}

func validateV4TurnTransition(previous, next CheckpointV4) error {
	t := next.Transition
	scope := *t.Scope
	wantProgress := previous.Progress
	var want []DeliverySlotV2
	var err error
	findActive := func(kind CheckpointSubmissionKind) error {
		for _, slot := range previous.Deliveries {
			if slot.AttemptID == t.AttemptID && slot.Kind == kind && slot.Scope == scope && slot.Status == DeliveryAllocated {
				return nil
			}
		}
		return errors.New("transition does not identify its exact active delivery")
	}
	switch t.Kind {
	case CheckpointPhase1OutboundPublished, CheckpointPhase2OutboundPublished:
		if len(t.Evidence) != 0 {
			return errors.New("outbound edge adds only its signed handoff")
		}
		for _, slot := range previous.Deliveries {
			if slot.Status == DeliveryAllocated {
				return errors.New("another delivery is still active")
			}
		}
		want, err = AllocateDeliveryV2(previous.Deliveries, scope, CheckpointSubmissionReceipt, t.AttemptID)
	case CheckpointPhase1ReceiptAccepted, CheckpointPhase2ReceiptAccepted:
		if len(t.Evidence) != 0 {
			return errors.New("receipt edge adds only its signed receipt")
		}
		if err = findActive(CheckpointSubmissionReceipt); err != nil {
			return err
		}
		want, err = AdvanceDeliveryV2(previous.Deliveries, t.AttemptID, DeliveryAccepted, nil)
		if err == nil {
			want, err = AllocateDeliveryV2(want, scope, CheckpointSubmissionCandidate, t.NextAttemptID)
		}
	case CheckpointPhase1CandidateAccepted, CheckpointPhase2CandidateAccepted:
		if len(t.Contribution.Files) != 7 {
			return errors.New("candidate acceptance requires the signed return handoff")
		}
		if err = findActive(CheckpointSubmissionCandidate); err != nil {
			return err
		}
		want, err = AdvanceDeliveryV2(previous.Deliveries, t.AttemptID, DeliveryAccepted, t.Contribution)
		state := next.Progress.Phase1
		if scope.Phase == Phase2 {
			if next.Progress.Phase2 == nil {
				return errors.New("candidate acceptance lost phase2")
			}
			state = *next.Progress.Phase2
		}
		if state.AcceptedCount != scope.Index || state.Chain != *t.Record || state.HeadRecordID == scope.ParentHeadID {
			return errors.New("candidate acceptance must advance exactly one signed head")
		}
		base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
		if len(t.Evidence) != len(t.Contribution.Files)+3 {
			return errors.New("candidate acceptance requires complete candidate, verification and signed return receipt")
		}
		for _, ref := range t.Contribution.Files {
			logical := ArtifactRef{Name: base + ref.Name, Digest: ref.Digest}
			if !slices.Contains(t.Evidence, logical) {
				return errors.New("accepted evidence differs from complete contribution inventory")
			}
			if ref.Name == "contribution.bin" && state.HeadPayload != logical {
				return errors.New("accepted payload differs from candidate bytes")
			}
		}
		if !slices.ContainsFunc(t.Evidence, func(ref ArtifactRef) bool { return ref.Name == base+"verification.json" }) {
			return errors.New("candidate acceptance lacks coordinator verification record")
		}
		for _, name := range []string{"return-receipt.json", "return-receipt.sig"} {
			if !slices.ContainsFunc(t.Evidence, func(ref ArtifactRef) bool { return ref.Name == base+name }) {
				return errors.New("candidate acceptance lacks signed return receipt")
			}
		}
		if scope.Phase == Phase1 {
			wantProgress.Phase1 = state
		} else {
			wantProgress.Phase2 = &state
		}
	case CheckpointDeliveryRetired, CheckpointContributionRejected:
		kind := CheckpointSubmissionCandidate
		for _, slot := range previous.Deliveries {
			if slot.AttemptID == t.AttemptID {
				kind = slot.Kind
			}
		}
		if err = findActive(kind); err != nil {
			return err
		}
		status := DeliveryRetired
		if t.Kind == CheckpointContributionRejected {
			status = DeliveryRejected
		}
		want, err = AdvanceDeliveryV2(previous.Deliveries, t.AttemptID, status, t.Contribution)
		if err == nil && t.NextAttemptID != "" {
			want, err = AllocateDeliveryV2(want, scope, kind, t.NextAttemptID)
		}
	case CheckpointDeliveryReallocated:
		index := -1
		for i, slot := range previous.Deliveries {
			if slot.AttemptID == t.AttemptID {
				index = i
			}
		}
		if index < 0 {
			return errors.New("replacement must name a retained terminal delivery")
		}
		old := previous.Deliveries[index]
		if old.Scope != scope || (old.Status != DeliveryRetired && old.Status != DeliveryRejected) {
			return errors.New("replacement requires the same retired or rejected scope")
		}
		for _, slot := range previous.Deliveries[index+1:] {
			if slot.Scope == scope && slot.Kind == old.Kind {
				return errors.New("replacement must follow the most recent delivery for this submission")
			}
		}
		want, err = AllocateDeliveryV2(previous.Deliveries, scope, old.Kind, t.NextAttemptID)
	default:
		return errors.New("unsupported turn transition")
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(want, next.Deliveries) {
		return errors.New("turn edge changed unexpected delivery history")
	}
	if !reflect.DeepEqual(wantProgress, next.Progress) {
		return errors.New("turn edge changed unrelated ceremony state")
	}
	expected := append(signedArtifacts(t.Record), t.Evidence...)
	if !exactArtifactDelta(previous.AcceptedArtifacts, next.AcceptedArtifacts, expected...) {
		return errors.New("turn edge published an unexpected artifact set")
	}
	return nil
}

// VerifyCheckpointEdgeV4 authenticates both exact checkpoint/signature pairs,
// checks both predecessor digests, and verifies the structural state change.
// Referenced protocol files and math are separate explicit verification layers.
func VerifyCheckpointEdgeV4(d CeremonyDefinition, definitionBytes, definitionSignature, previousBytes, previousSignature, nextBytes, nextSignature []byte) (CheckpointV4, error) {
	previous, err := VerifySignedCheckpointV4(d, definitionBytes, definitionSignature, previousBytes, previousSignature)
	if err != nil {
		return CheckpointV4{}, fmt.Errorf("previous checkpoint: %w", err)
	}
	next, err := VerifySignedCheckpointV4(d, definitionBytes, definitionSignature, nextBytes, nextSignature)
	if err != nil {
		return CheckpointV4{}, fmt.Errorf("next checkpoint: %w", err)
	}
	if next.PreviousCheckpoint == nil || next.PreviousCheckpoint.Record.Digest != NewDigest(previousBytes) || next.PreviousCheckpoint.Signature.Digest != NewDigest(previousSignature) {
		return CheckpointV4{}, errors.New("checkpoint does not reference the exact predecessor record and signature")
	}
	if err := ValidateCheckpointTransitionV4(previous, next); err != nil {
		return CheckpointV4{}, err
	}
	return next, nil
}
