package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectParticipantSigningKeyMatchesRosterAndSchedule(t *testing.T) {
	definition := adversarialDefinition(t)
	keyPath := writeInspectionPrivateKey(t, adversarialPrivateKey(0x12))
	match, err := InspectParticipantSigningKey(definition, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := definition.Roster[1].Identity
	if match.ParticipantID != identity.ID || match.KeyID != identity.KeyID ||
		match.PublicKeyFingerprint != identity.PublicKeyFingerprint {
		t.Fatalf("participant match = %#v", match)
	}
	if match.Phase1Position == nil || *match.Phase1Position != 2 ||
		match.Phase2Position == nil || *match.Phase2Position != 2 {
		t.Fatalf("participant positions = phase1 %v, phase2 %v", match.Phase1Position, match.Phase2Position)
	}
	if position := participantSchedulePosition([]string{"participant-01"}, identity.ID); position != nil {
		t.Fatalf("absent participant position = %d, want nil", *position)
	}
}

func TestInspectParticipantSigningKeyRejectsUnknownMalformedAndNonParticipants(t *testing.T) {
	definition := adversarialDefinition(t)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "unknown", data: privateKeyHex(adversarialPrivateKey(0xee))},
		{name: "malformed", data: []byte("not-hex\n")},
		{name: "coordinator", data: privateKeyHex(adversarialPrivateKey(0x01))},
		{name: "release signer", data: privateKeyHex(adversarialPrivateKey(0x02))},
		{name: "auditor", data: privateKeyHex(adversarialPrivateKey(0x03))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.private.hex")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectParticipantSigningKey(definition, path); err == nil {
				t.Fatal("non-participant or malformed key unexpectedly accepted")
			}
		})
	}
}

func TestVerifyEnrollmentProofOfPossessionSupportsWitnessAndMirror(t *testing.T) {
	definition := adversarialDefinition(t)
	definitionBytes, err := MarshalCanonical(definition)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		role EnrollmentRole
		id   string
		fill byte
	}{
		{role: EnrollmentPublicWitness, id: "public-witness-01", fill: 0x91},
		{role: EnrollmentMirrorOperator, id: "mirror-operator-01", fill: 0xa1},
	} {
		t.Run(string(test.role), func(t *testing.T) {
			record, recordBytes, signatureBytes := signedExternalEnrollment(
				t, definition, definitionBytes, test.role, test.id, test.fill,
			)
			verified, err := VerifyEnrollmentProofOfPossession(
				definition, definitionBytes, recordBytes, signatureBytes,
			)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Identity != record.Identity || verified.Role != test.role {
				t.Fatalf("verified enrollment = %#v", verified)
			}

			altered := record
			altered.EnrolledAt = "2026-07-23T12:00:02Z"
			alteredBytes, err := MarshalCanonical(altered)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyEnrollmentProofOfPossession(
				definition, definitionBytes, alteredBytes, signatureBytes,
			); err == nil {
				t.Fatal("altered enrollment unexpectedly accepted")
			}

			var signature DetachedSignature
			if err := UnmarshalCanonical(signatureBytes, &signature); err != nil {
				t.Fatal(err)
			}
			signature.SignatureHex = strings.Repeat("00", ed25519.SignatureSize)
			alteredSignature, err := MarshalCanonical(signature)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyEnrollmentProofOfPossession(
				definition, definitionBytes, recordBytes, alteredSignature,
			); err == nil {
				t.Fatal("altered enrollment signature unexpectedly accepted")
			}
		})
	}
}

func TestPreparePublicWitnessReceiptEnforcesRoleIdentityAndObservationTiming(t *testing.T) {
	definition := adversarialDefinition(t)
	definitionBytes, _ := MarshalCanonical(definition)
	witness, _, _ := signedExternalEnrollment(
		t, definition, definitionBytes, EnrollmentPublicWitness, "public-witness-01", 0x91,
	)
	mirror, _, _ := signedExternalEnrollment(
		t, definition, definitionBytes, EnrollmentMirrorOperator, "mirror-operator-01", 0xa1,
	)
	round := uint64(40_000_000)
	roundTime, err := QuicknetRoundTime(round)
	if err != nil {
		t.Fatal(err)
	}
	closeRecord := operationalClose(t, definition, Phase1, round, roundTime.Add(-25*time.Hour))
	closeBytes, err := MarshalCanonical(closeRecord)
	if err != nil {
		t.Fatal(err)
	}
	location := "https://independent.example/phase1/closure.json"
	observedAt := roundTime.Add(-24 * time.Hour).Format(time.RFC3339)
	receipt, canonical, err := PreparePublicWitnessReceipt(
		definition,
		closeRecord,
		closeBytes,
		witness,
		"phase1/closure/record.json",
		location,
		observedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Witness != witness.Identity || receipt.PublicationLocationSHA != taggedSHA256([]byte(location)) {
		t.Fatalf("prepared receipt = %#v", receipt)
	}
	if bytes.Contains(canonical, []byte(location)) {
		t.Fatal("canonical receipt exposed cleartext publication location")
	}

	if _, _, err := PreparePublicWitnessReceipt(
		definition, closeRecord, closeBytes, mirror, "phase1/closure/record.json", location, observedAt,
	); err == nil {
		t.Fatal("mirror enrollment unexpectedly accepted for public-witness receipt")
	}

	overlap := witness
	overlap.Identity = definition.Coordinator
	if _, _, err := PreparePublicWitnessReceipt(
		definition, closeRecord, closeBytes, overlap, "phase1/closure/record.json", location, observedAt,
	); err == nil {
		t.Fatal("witness enrollment overlapping the coordinator unexpectedly accepted")
	}

	for _, test := range []struct {
		name       string
		observedAt time.Time
	}{
		{name: "before closure", observedAt: roundTime.Add(-26 * time.Hour)},
		{name: "at beacon round", observedAt: roundTime},
		{name: "after beacon round", observedAt: roundTime.Add(time.Second)},
		{name: "below minimum lead", observedAt: roundTime.Add(-24*time.Hour + time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := PreparePublicWitnessReceipt(
				definition,
				closeRecord,
				closeBytes,
				witness,
				"phase1/closure/record.json",
				location,
				test.observedAt.Format(time.RFC3339),
			); err == nil {
				t.Fatal("invalid observation time unexpectedly accepted")
			}
		})
	}
}

func writeInspectionPrivateKey(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "participant.private.hex")
	if err := os.WriteFile(path, privateKeyHex(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateKeyHex(key ed25519.PrivateKey) []byte {
	return []byte(hex.EncodeToString(key.Seed()) + "\n")
}

func signedExternalEnrollment(
	t *testing.T,
	definition CeremonyDefinition,
	definitionBytes []byte,
	role EnrollmentRole,
	id string,
	fill byte,
) (EnrollmentRecord, []byte, []byte) {
	t.Helper()
	privateKey := adversarialPrivateKey(fill)
	identity, err := NewIdentity(id, "Test "+id, id+"-key", privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewEnrollmentRecord(
		definition,
		definitionBytes,
		identity,
		role,
		1,
		ArtifactRef{Name: "disclosures/" + id + ".json", Digest: NewDigest([]byte("independent " + id))},
		"2026-07-23T12:00:01Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, signatureBytes, err := SignRecord(record, identity.KeyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return record, recordBytes, signatureBytes
}
