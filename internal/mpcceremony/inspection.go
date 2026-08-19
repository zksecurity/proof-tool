package mpcceremony

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"proof-tool/internal/keybundle"
)

// ParticipantSigningKeyMatch is the immutable public result of matching an
// existing participant signing key to the authenticated ceremony roster.
type ParticipantSigningKeyMatch struct {
	ParticipantID        string
	KeyID                string
	PublicKeyFingerprint string
	Phase1Position       *uint8
	Phase2Position       *uint8
}

// InspectParticipantSigningKey loads an existing Ed25519 private key with the
// same hardened rules used by contribution commands, derives only its public
// key, and matches that public key to exactly one roster participant. It never
// signs or writes anything.
func InspectParticipantSigningKey(
	definition CeremonyDefinition,
	privateKeyPath string,
) (ParticipantSigningKeyMatch, error) {
	if err := definition.Validate(); err != nil {
		return ParticipantSigningKeyMatch{}, err
	}
	privateKey, publicKey, err := keybundle.LoadExistingPrivateKey(privateKeyPath)
	if err != nil {
		return ParticipantSigningKeyMatch{}, err
	}
	defer clear(privateKey)

	matches := make([]Identity, 0, 1)
	for _, participant := range definition.Roster {
		expected, err := identityPublicKey(participant.Identity)
		if err != nil {
			return ParticipantSigningKeyMatch{}, err
		}
		if bytes.Equal(publicKey, expected) {
			matches = append(matches, participant.Identity)
		}
	}
	if len(matches) > 1 {
		return ParticipantSigningKeyMatch{}, errors.New("participant signing key matches more than one roster identity")
	}
	if len(matches) == 0 {
		for _, identity := range nonParticipantCeremonyIdentities(definition) {
			expected, err := identityPublicKey(identity)
			if err != nil {
				return ParticipantSigningKeyMatch{}, err
			}
			if bytes.Equal(publicKey, expected) {
				return ParticipantSigningKeyMatch{}, fmt.Errorf(
					"signing key matches non-participant ceremony identity %q",
					identity.ID,
				)
			}
		}
		return ParticipantSigningKeyMatch{}, errors.New("signing key does not match any participant in the authenticated roster")
	}

	identity := matches[0]
	return ParticipantSigningKeyMatch{
		ParticipantID:        identity.ID,
		KeyID:                identity.KeyID,
		PublicKeyFingerprint: identity.PublicKeyFingerprint,
		Phase1Position:       participantSchedulePosition(definition.Phase1Policy.Participants, identity.ID),
		Phase2Position:       participantSchedulePosition(definition.Phase2Policy.Participants, identity.ID),
	}, nil
}

func participantSchedulePosition(schedule []string, participantID string) *uint8 {
	for index, id := range schedule {
		if id == participantID {
			position := uint8(index + 1)
			return &position
		}
	}
	return nil
}

func nonParticipantCeremonyIdentities(definition CeremonyDefinition) []Identity {
	identities := make([]Identity, 0, 2+len(definition.Auditors))
	identities = append(identities, definition.Coordinator, definition.ReleaseSigner)
	identities = append(identities, definition.Auditors...)
	return identities
}

// LoadSignedCloseExact authenticates an exact coordinator-signed closure,
// validates its definition-level binding, and returns the safe transcript name
// derived from the same root used to constrain both input paths.
func LoadSignedCloseExact(
	trusted *TrustedCeremony,
	transcriptRoot, closePath, signaturePath string,
) (AuthenticatedCloseEvidence, string, error) {
	if err := validateTrustedCeremony(trusted); err != nil {
		return AuthenticatedCloseEvidence{}, "", err
	}
	if strings.TrimSpace(transcriptRoot) == "" || strings.TrimSpace(closePath) == "" ||
		strings.TrimSpace(signaturePath) == "" {
		return AuthenticatedCloseEvidence{}, "", errors.New("transcript root, closure, and closure signature paths are required")
	}
	closeName, err := logicalPathWithin(transcriptRoot, closePath)
	if err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("closure path: %w", err)
	}
	if _, err := logicalPathWithin(transcriptRoot, signaturePath); err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("closure signature path: %w", err)
	}
	closeBytes, err := readRegularBounded(closePath, maxSignedRecordBytes)
	if err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("load signed closure: %w", err)
	}
	signatureBytes, err := readRegularBounded(signaturePath, maxSignedRecordBytes)
	if err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("load signed closure: %w", err)
	}
	var closeRecord CloseRecord
	if err := VerifySignedRecord(
		closeBytes,
		signatureBytes,
		&closeRecord,
		trusted.Definition.Coordinator.KeyID,
		trusted.CoordinatorPublicKey,
	); err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("load signed closure: %w", err)
	}
	if err := validatePublicWitnessCloseBinding(trusted.Definition, closeRecord); err != nil {
		return AuthenticatedCloseEvidence{}, "", fmt.Errorf("closure against definition: %w", err)
	}
	return AuthenticatedCloseEvidence{
		Record:         closeRecord,
		RecordBytes:    closeBytes,
		SignatureBytes: signatureBytes,
	}, closeName, nil
}
