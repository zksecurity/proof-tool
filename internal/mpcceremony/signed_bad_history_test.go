package mpcceremony

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

// A coordinator and participant can sign a structurally coherent history that
// lies about a native transition. Final replay must still check the math.
func TestSignedV5BadPhase1HistoryReachesAndFailsIndependentReplay(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("signed V5 workflow fixture requires Linux executable identity")
	}
	t.Setenv("MPC_WORKFLOW_CHECKPOINT_V4", "1")
	fixture := newDirectAcceptanceFixture(t)
	if fixture.trusted.Definition.Schema != DefinitionSchemaV5 {
		t.Fatal("fixture is not signed V5")
	}
	circuit, err := CompileForKeyVersion(fixture.trusted.Definition.Circuit.KeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCircuitBinding(circuit, fixture.trusted.Definition.Circuit); err != nil {
		t.Fatal(err)
	}
	fixture.circuit = circuit
	chain, _, err := LoadSignedChainExact(fixture.trusted, fixture.phase1Chain1)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Records) != 1 {
		t.Fatalf("first signed chain has %d records", len(chain.Records))
	}
	record := chain.Records[0]
	root := fixture.ceremonyRoot
	readRecord := func(name string, target any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if err := UnmarshalCanonical(data, target); err != nil {
			t.Fatal(err)
		}
	}
	writeRecord := func(name string, value any) ArtifactRef {
		t.Helper()
		data, err := MarshalCanonical(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return ArtifactRef{Name: name, Digest: NewDigest(data)}
	}
	writeSigned := func(recordName, signatureName string, value any, keyPath string, identity Identity) (ArtifactRef, ArtifactRef) {
		t.Helper()
		key, _, err := loadMatchingPrivateKey(keyPath, identity)
		if err != nil {
			t.Fatal(err)
		}
		data, signature, err := SignRecord(value, identity.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(recordName)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(signatureName)), signature, 0o600); err != nil {
			t.Fatal(err)
		}
		return ArtifactRef{Name: recordName, Digest: NewDigest(data)}, ArtifactRef{Name: signatureName, Digest: NewDigest(signature)}
	}

	// This has the right native shape and challenge but was mutated independently
	// of the canonical genesis. Its signed verification claim is deliberately false.
	wrong, err := ContributePhase1(fixture.circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong.Challenge = nil
	bad := new(gnarkmpc.Phase1)
	if err := streamClone(wrong, bad); err != nil {
		t.Fatal(err)
	}
	if err := runGnarkMutation("construct false signed Phase 1 history", bad.Contribute); err != nil {
		t.Fatal(err)
	}
	genesis, _, err := InitializePhase1(fixture.circuit.Binding.DomainSize)
	if err != nil {
		t.Fatal(err)
	}
	genesisHash := sha256.Sum256(serializeEngineArtifact(t, genesis))
	bad.Challenge = bytes.Clone(genesisHash[:])
	badPath := filepath.Join(t.TempDir(), "bad.bin")
	if _, err := WritePhase1FileNoReplace(badPath, bad, Phase1Shape{DomainN: fixture.circuit.Binding.DomainSize, ChallengeLength: contributionChallengeSize}); err != nil {
		t.Fatal(err)
	}
	badBytes, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(record.OutputPayload.Name)), badBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	record.OutputPayload.Digest = NewDigest(badBytes)

	participant, ok := fixture.trusted.Definition.ParticipantByID(record.ParticipantID)
	if !ok {
		t.Fatal("signed participant missing")
	}
	keyPath := filepath.Join(filepath.Dir(root), "identity-keys", record.ParticipantID+".ed25519.private.hex")
	var attestation ContributionAttestation
	readRecord(record.Attestation.Name, &attestation)
	attestation.OutputPayload = record.OutputPayload
	attestation, err = NewContributionAttestation(attestation)
	if err != nil {
		t.Fatal(err)
	}
	record.AttestationID = attestation.AttestationID
	record.Attestation, record.AttestationSignature = writeSigned(record.Attestation.Name, record.AttestationSignature.Name, attestation, keyPath, participant.Identity)

	var erasure ErasureAttestation
	readRecord(record.Erasure.Name, &erasure)
	erasure.OutputPayload = record.OutputPayload
	erasure.ContributionAttestationID = attestation.AttestationID
	erasure, err = NewErasureAttestation(erasure)
	if err != nil {
		t.Fatal(err)
	}
	record.ErasureID = erasure.ErasureID
	record.Erasure, record.ErasureSignature = writeSigned(record.Erasure.Name, record.ErasureSignature.Name, erasure, keyPath, participant.Identity)

	var verification ContributionVerification
	readRecord(record.Verification.Name, &verification)
	verification.OutputPayload = record.OutputPayload
	verification.AttestationID = record.AttestationID
	verification.ErasureID = record.ErasureID
	record.Verification = writeRecord(record.Verification.Name, verification)
	record, err = NewChainRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	chain.Records[0] = record
	if err := chain.ValidateAgainstDefinition(fixture.trusted.Definition); err != nil {
		t.Fatal(err)
	}
	coordinator, _, err := loadMatchingPrivateKey(fixture.coordinatorKeyPath, fixture.trusted.Definition.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	chainBytes, signatureBytes, err := SignRecord(chain, fixture.trusted.Definition.Coordinator.KeyID, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.phase1Chain1.ChainPath, chainBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.phase1Chain1.ChainSignaturePath, signatureBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := loadVerifiedPhase1Files(fixture.trusted, fixture.circuit, fixture.phase1Chain1)
	if err != nil {
		t.Fatalf("signed coherent history failed before native replay: %v", err)
	}
	if _, err := canonicalPhase1Genesis(fixture.trusted, fixture.circuit, verified); err != nil {
		t.Fatalf("signed history failed canonical genesis before native replay: %v", err)
	}
	if _, err := LoadReplayPhase1Files(fixture.trusted, fixture.circuit, fixture.phase1Chain1); err == nil {
		t.Fatal("independent replay accepted signed false native transition")
	}
}
