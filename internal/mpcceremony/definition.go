package mpcceremony

import (
	"errors"
	"fmt"
)

// WARNING: THIS BRANCH IS NOT FIT FOR A REAL CEREMONY.
//
// The released value is 24 hours. It is the window in which a public witness
// can observe a phase closure before the randomness that seals that phase
// exists, which is what stops a coordinator who already knows the beacon
// output from closing the phase around it. Two phase closes make it 48 hours
// of mandated waiting, and that is the intended cost.
//
// It is reduced to 10 minutes here for one purpose: exercising the production
// code path end to end in hours instead of days, so the audit can reach the
// finalize, audit, release, and decision stages that no rehearsal run touches.
//
// Any transcript produced from this branch is a test artifact. It records this
// commit in its software binding, so a verifier who fetches the named revision
// finds this comment; do not merge this branch, and do not present its output
// as a ceremony.
const ProductionMinimumWitnessLeadSeconds uint32 = 10 * 60

// ProductionWitnessObservationWindowSeconds is the observation time a
// production close must reserve for public witnesses on top of the signed
// minimum witness lead.
//
// The signed minimum is measured from two different anchors: ValidateClose
// measures roundTime-closedAt, while witness receipts measure
// roundTime-observedAt with observedAt strictly after closedAt. A close at
// exactly the signed minimum therefore leaves witnesses no time in which a
// valid receipt can exist, and the mismatch surfaces only when the evidence
// bundle is assembled at release, when the round is already pinned inside the
// signed closure. Reserving an explicit window at close keeps the witness
// requirement satisfiable. Rehearsals are exempt: their leads are minutes and
// their witness receipts are same-host fixtures.
//
// TEST BRANCH: cut from one hour to two minutes, proportionally with the
// 10-minute lead above, so the reproduction still exercises the reserved
// window without restoring the multi-hour wait. Same caveat: do not merge.
const ProductionWitnessObservationWindowSeconds uint32 = 2 * 60

type CeremonyDefinition struct {
	Schema          string          `json:"schema"`
	CeremonyID      string          `json:"ceremony_id"`
	Mode            string          `json:"mode"`
	CreatedAt       string          `json:"created_at"`
	SessionNonceHex string          `json:"session_nonce_hex"`
	Circuit         CircuitBinding  `json:"circuit"`
	Software        SoftwareBinding `json:"software"`
	Coordinator     Identity        `json:"coordinator"`
	ReleaseSigner   Identity        `json:"release_signer"`
	Auditors        []Identity      `json:"auditors"`
	Roster          []Participant   `json:"roster"`
	Phase1Policy    PhasePolicy     `json:"phase1_policy"`
	Phase2Policy    PhasePolicy     `json:"phase2_policy"`
	BeaconPolicy    BeaconPolicy    `json:"beacon_policy"`
	Phase1Genesis   ArtifactRef     `json:"phase1_genesis"`
}

type DefinitionOptions struct {
	Mode            string
	CreatedAt       string
	SessionNonceHex string
	Circuit         CircuitBinding
	Software        SoftwareBinding
	Coordinator     Identity
	ReleaseSigner   Identity
	Auditors        []Identity
	Roster          []Participant
	Phase1Policy    PhasePolicy
	Phase2Policy    PhasePolicy
	BeaconPolicy    BeaconPolicy
	Phase1Genesis   ArtifactRef
}

func NewCeremonyDefinition(options DefinitionOptions) (CeremonyDefinition, error) {
	definition := CeremonyDefinition{
		Schema:          DefinitionSchema,
		Mode:            options.Mode,
		CreatedAt:       options.CreatedAt,
		SessionNonceHex: options.SessionNonceHex,
		Circuit:         options.Circuit,
		Software:        options.Software,
		Coordinator:     options.Coordinator,
		ReleaseSigner:   options.ReleaseSigner,
		Auditors:        append([]Identity(nil), options.Auditors...),
		Roster:          append([]Participant(nil), options.Roster...),
		Phase1Policy:    clonePhasePolicy(options.Phase1Policy),
		Phase2Policy:    clonePhasePolicy(options.Phase2Policy),
		BeaconPolicy:    options.BeaconPolicy,
		Phase1Genesis:   options.Phase1Genesis,
	}
	id, err := ComputeCeremonyID(definition)
	if err != nil {
		return CeremonyDefinition{}, err
	}
	definition.CeremonyID = id
	if err := definition.Validate(); err != nil {
		return CeremonyDefinition{}, err
	}
	return definition, nil
}

// FinalizeCeremonyDefinition validates an assembled definition and fills its
// content-derived CeremonyID. It is useful to decouple expensive circuit
// compilation from metadata construction.
func FinalizeCeremonyDefinition(definition CeremonyDefinition) (CeremonyDefinition, error) {
	definition.Schema = DefinitionSchema
	definition.CeremonyID = ""
	id, err := ComputeCeremonyID(definition)
	if err != nil {
		return CeremonyDefinition{}, err
	}
	definition.CeremonyID = id
	if err := definition.Validate(); err != nil {
		return CeremonyDefinition{}, err
	}
	return definition, nil
}

func ComputeCeremonyID(definition CeremonyDefinition) (string, error) {
	definition.CeremonyID = ""
	if err := definition.validate(false); err != nil {
		return "", err
	}
	return canonicalHash("proof-tool/mpc-ceremony/root/v1", definition)
}

func (d CeremonyDefinition) Validate() error {
	if err := d.validate(true); err != nil {
		return err
	}
	expected, err := ComputeCeremonyID(d)
	if err != nil {
		return err
	}
	if d.CeremonyID != expected {
		return fmt.Errorf("ceremony_id %q, want %q", d.CeremonyID, expected)
	}
	return nil
}

func (d CeremonyDefinition) validate(requireID bool) error {
	if d.Schema != DefinitionSchema {
		return fmt.Errorf("definition schema %q, want %q", d.Schema, DefinitionSchema)
	}
	if requireID {
		if err := validateTaggedHex(d.CeremonyID, "sha256:", 32); err != nil {
			return fmt.Errorf("ceremony_id: %w", err)
		}
	} else if d.CeremonyID != "" {
		return errors.New("ceremony_id must be empty while computing the definition identity")
	}
	switch d.Mode {
	case ModeRehearsal:
	case ModeProduction:
		// The circuit registry accepts a tiny rehearsal circuit so the ceremony
		// machinery can be exercised at a small domain. Production must never
		// see it: a transcript at domain 2^16 proves nothing about a 2^21
		// ceremony, and the exact-k21-rehearsal gate exists precisely so a
		// smaller run cannot satisfy it. This is the only place that knows the
		// mode, so it is the only place the restriction can live, and it is
		// decided before any environment-dependent check so the failure is
		// about the definition rather than the host.
		if d.Circuit.KeyVersion != KeyVersionDestinationV2 {
			return fmt.Errorf(
				"production ceremony must use key_version %q, not %q",
				KeyVersionDestinationV2, d.Circuit.KeyVersion,
			)
		}
		if d.Software.SourceDirty {
			return errors.New("production ceremony requires a clean source tree")
		}
		if err := validateProductionBuildProfile(
			d.Software.GoVersion,
			d.Software.GoOS,
			d.Software.GoArch,
			d.Software.GoAMD64,
			d.Software.Compiler,
			d.Software.BuildMode,
			d.Software.CGOEnabled,
			d.Software.TrimPath,
		); err != nil {
			return fmt.Errorf("production software profile: %w", err)
		}
	default:
		return fmt.Errorf("mode %q, want %q or %q", d.Mode, ModeRehearsal, ModeProduction)
	}
	if err := validateTimestamp("created_at", d.CreatedAt); err != nil {
		return err
	}
	if err := validateHex(d.SessionNonceHex, 32); err != nil {
		return fmt.Errorf("session_nonce_hex: %w", err)
	}
	if err := d.Circuit.Validate(); err != nil {
		return fmt.Errorf("circuit: %w", err)
	}
	if err := d.Software.Validate(); err != nil {
		return fmt.Errorf("software: %w", err)
	}
	if err := d.Coordinator.Validate(); err != nil {
		return fmt.Errorf("coordinator: %w", err)
	}
	if err := d.ReleaseSigner.Validate(); err != nil {
		return fmt.Errorf("release_signer: %w", err)
	}
	if d.ReleaseSigner.ID == d.Coordinator.ID || d.ReleaseSigner.KeyID == d.Coordinator.KeyID {
		return errors.New("release signer must be distinct from coordinator")
	}
	if len(d.Auditors) < 2 {
		return errors.New("at least two independent auditors are required")
	}
	if len(d.Auditors) > MaxAuditors {
		return fmt.Errorf("auditors exceed maximum %d recordable in the final transcript", MaxAuditors)
	}
	identityIDs := map[string]string{
		d.Coordinator.ID:   "coordinator",
		d.ReleaseSigner.ID: "release signer",
	}
	keyIDs := map[string]string{
		d.Coordinator.KeyID:   "coordinator",
		d.ReleaseSigner.KeyID: "release signer",
	}
	publicKeyFingerprints := map[string]string{
		d.Coordinator.PublicKeyFingerprint: "coordinator",
	}
	if previous, exists := publicKeyFingerprints[d.ReleaseSigner.PublicKeyFingerprint]; exists {
		return fmt.Errorf("release signer public key duplicates %s", previous)
	}
	publicKeyFingerprints[d.ReleaseSigner.PublicKeyFingerprint] = "release signer"
	for index, auditor := range d.Auditors {
		if err := auditor.Validate(); err != nil {
			return fmt.Errorf("auditor %d: %w", index, err)
		}
		if previous, exists := identityIDs[auditor.ID]; exists {
			return fmt.Errorf("auditor identity %q duplicates %s", auditor.ID, previous)
		}
		if previous, exists := keyIDs[auditor.KeyID]; exists {
			return fmt.Errorf("auditor key %q duplicates %s", auditor.KeyID, previous)
		}
		if previous, exists := publicKeyFingerprints[auditor.PublicKeyFingerprint]; exists {
			return fmt.Errorf("auditor public key duplicates %s", previous)
		}
		identityIDs[auditor.ID] = "auditor"
		keyIDs[auditor.KeyID] = "auditor"
		publicKeyFingerprints[auditor.PublicKeyFingerprint] = "auditor"
	}
	if len(d.Roster) == 0 || len(d.Roster) > MaxParticipants {
		return fmt.Errorf("roster must contain between 1 and %d participants", MaxParticipants)
	}
	roster := make(map[string]Participant, len(d.Roster))
	for index, participant := range d.Roster {
		if err := participant.Validate(); err != nil {
			return fmt.Errorf("roster participant %d: %w", index, err)
		}
		id := participant.Identity.ID
		keyID := participant.Identity.KeyID
		if _, duplicate := roster[id]; duplicate {
			return fmt.Errorf("roster participant %q is duplicated", id)
		}
		if previous, exists := identityIDs[id]; exists {
			return fmt.Errorf("participant identity %q duplicates %s", id, previous)
		}
		if previous, exists := keyIDs[keyID]; exists {
			return fmt.Errorf("participant key %q duplicates %s", keyID, previous)
		}
		if previous, exists := publicKeyFingerprints[participant.Identity.PublicKeyFingerprint]; exists {
			return fmt.Errorf("participant public key duplicates %s", previous)
		}
		roster[id] = participant
		identityIDs[id] = "participant"
		keyIDs[keyID] = "participant"
		publicKeyFingerprints[participant.Identity.PublicKeyFingerprint] = "participant"
	}
	if err := d.Phase1Policy.Validate(roster); err != nil {
		return fmt.Errorf("phase1_policy: %w", err)
	}
	if err := d.Phase2Policy.Validate(roster); err != nil {
		return fmt.Errorf("phase2_policy: %w", err)
	}
	if d.Mode == ModeProduction {
		if d.BeaconPolicy.MinimumWitnessLeadSeconds < ProductionMinimumWitnessLeadSeconds {
			return fmt.Errorf(
				"production beacon minimum_witness_lead_seconds %d is below required %d",
				d.BeaconPolicy.MinimumWitnessLeadSeconds,
				ProductionMinimumWitnessLeadSeconds,
			)
		}
		if len(d.Roster) < 2 {
			return errors.New("production ceremony requires at least two distinct roster participants")
		}
		if len(d.Phase1Policy.Participants) < 2 {
			return errors.New("production phase1 policy requires at least two scheduled participants")
		}
		if int(d.Phase1Policy.Minimum) != len(d.Phase1Policy.Participants) {
			return errors.New("production phase1 minimum must equal the complete scheduled participant count")
		}
		if len(d.Phase2Policy.Participants) < 2 {
			return errors.New("production phase2 policy requires at least two scheduled participants")
		}
		if int(d.Phase2Policy.Minimum) != len(d.Phase2Policy.Participants) {
			return errors.New("production phase2 minimum must equal the complete scheduled participant count")
		}
	}
	if err := d.BeaconPolicy.Validate(); err != nil {
		return fmt.Errorf("beacon_policy: %w", err)
	}
	if err := d.Phase1Genesis.Validate(); err != nil {
		return fmt.Errorf("phase1_genesis: %w", err)
	}
	return nil
}

func (d CeremonyDefinition) PolicyForPhase(phase Phase) (PhasePolicy, error) {
	switch phase {
	case Phase1:
		return clonePhasePolicy(d.Phase1Policy), nil
	case Phase2:
		return clonePhasePolicy(d.Phase2Policy), nil
	default:
		return PhasePolicy{}, fmt.Errorf("unsupported phase %q", phase)
	}
}

func (d CeremonyDefinition) ParticipantByID(id string) (Participant, bool) {
	for _, participant := range d.Roster {
		if participant.Identity.ID == id {
			return participant, true
		}
	}
	return Participant{}, false
}

func ComputePhaseID(ceremonyID string, phase Phase, genesis ArtifactRef, parentSealID string) (string, error) {
	if err := validateTaggedHex(ceremonyID, "sha256:", 32); err != nil {
		return "", fmt.Errorf("ceremony_id: %w", err)
	}
	if err := phase.Validate(); err != nil {
		return "", err
	}
	if err := genesis.Validate(); err != nil {
		return "", fmt.Errorf("genesis: %w", err)
	}
	if phase == Phase1 && parentSealID != "" {
		return "", errors.New("phase1 must not have a parent seal")
	}
	if phase == Phase2 {
		if err := validateTaggedHex(parentSealID, "sha256:", 32); err != nil {
			return "", fmt.Errorf("phase2 parent seal: %w", err)
		}
	}
	value := struct {
		CeremonyID   string      `json:"ceremony_id"`
		Phase        Phase       `json:"phase"`
		Genesis      ArtifactRef `json:"genesis"`
		ParentSealID string      `json:"parent_seal_id"`
	}{ceremonyID, phase, genesis, parentSealID}
	return canonicalHash("proof-tool/mpc-ceremony/phase/v1", value)
}

func clonePhasePolicy(policy PhasePolicy) PhasePolicy {
	return PhasePolicy{
		Participants: append([]string(nil), policy.Participants...),
		Minimum:      policy.Minimum,
	}
}
