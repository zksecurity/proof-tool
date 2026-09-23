package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

func TestContributeFromAuthenticatedHeadPreservesBytes(t *testing.T) {
	circuit := compileEngineCircuit(t)
	phase1, _, err := InitializePhase1(circuit.Binding.DomainSize)
	if err != nil {
		t.Fatal(err)
	}
	phase1Before := serializeEngineArtifact(t, phase1)
	phase1Digest, err := writerDigest(phase1)
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	report := func(stage string, index, total int) {
		if total != 5 || index != len(stages)+3 {
			t.Fatalf("unexpected contribution stage %d/%d", index, total)
		}
		stages = append(stages, stage)
	}
	first, err := contributePhase1FromAuthenticatedHead(circuit.Binding.DomainSize, phase1, phase1Digest, report)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []string{"Creating your contribution", "Checking your contribution"}) {
		t.Fatalf("Phase 1 stages = %v", stages)
	}
	firstBefore := serializeEngineArtifact(t, first)
	if err := requireChallengeMatchesDigest(first.Challenge, phase1Digest); err != nil {
		t.Fatal(err)
	}
	checkPhase1 := new(gnarkmpc.Phase1)
	if err := streamClone(first, checkPhase1); err != nil {
		t.Fatal(err)
	}
	if err := verifyPhase1Transition(circuit.Binding.DomainSize, phase1, checkPhase1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(phase1Before, serializeEngineArtifact(t, phase1)) || !bytes.Equal(firstBefore, serializeEngineArtifact(t, first)) {
		t.Fatal("Phase 1 own-check changed retained input or output bytes")
	}
	commons, err := SealPhase1(circuit.Binding.DomainSize, bytes.Repeat([]byte{0x51}, contributionChallengeSize), []*gnarkmpc.Phase1{first})
	if err != nil {
		t.Fatal(err)
	}
	phase2, _, err := InitializePhase2(circuit, commons)
	if err != nil {
		t.Fatal(err)
	}
	phase2Before := serializeEngineArtifact(t, phase2)
	phase2Digest, err := writerDigest(phase2)
	if err != nil {
		t.Fatal(err)
	}
	stages = nil
	second, err := contributePhase2FromAuthenticatedHead(phase2, phase2Digest, report)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []string{"Creating your contribution", "Checking your contribution"}) {
		t.Fatalf("Phase 2 stages = %v", stages)
	}
	secondBefore := serializeEngineArtifact(t, second)
	if err := requireChallengeMatchesDigest(second.Challenge, phase2Digest); err != nil {
		t.Fatal(err)
	}
	checkPhase2 := new(gnarkmpc.Phase2)
	if err := streamClone(second, checkPhase2); err != nil {
		t.Fatal(err)
	}
	if err := verifyPhase2Transition(phase2, checkPhase2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(phase2Before, serializeEngineArtifact(t, phase2)) || !bytes.Equal(secondBefore, serializeEngineArtifact(t, second)) {
		t.Fatal("Phase 2 own-check changed retained input or output bytes")
	}
}

func TestOwnTransitionCheckDoesNotCertifyEarlierPhase1Math(t *testing.T) {
	circuit := compileEngineCircuit(t)
	canonical, _, err := InitializePhase1(circuit.Binding.DomainSize)
	if err != nil {
		t.Fatal(err)
	}
	canonicalHash := sha256.Sum256(serializeEngineArtifact(t, canonical))
	wrong, err := ContributePhase1(circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong.Challenge = nil
	bad := new(gnarkmpc.Phase1)
	if err := streamClone(wrong, bad); err != nil {
		t.Fatal(err)
	}
	if err := runGnarkMutation("test invalid earlier Phase 1 contribution", bad.Contribute); err != nil {
		t.Fatal(err)
	}
	bad.Challenge = bytes.Clone(canonicalHash[:])
	if err := ReplayPhase1(circuit.Binding.DomainSize, []*gnarkmpc.Phase1{bad}); err == nil {
		t.Fatal("mathematically invalid earlier contribution passed independent replay")
	}
	digest, err := writerDigest(bad)
	if err != nil {
		t.Fatal(err)
	}
	next, err := contributePhase1FromAuthenticatedHead(circuit.Binding.DomainSize, bad, digest)
	if err != nil {
		t.Fatalf("own transition from authenticated but invalid history: %v", err)
	}
	if err := ReplayPhase1(circuit.Binding.DomainSize, []*gnarkmpc.Phase1{bad, next}); err == nil {
		t.Fatal("full replay accepted the invalid earlier contribution")
	}
}

func TestSignedNativeValidWrongPhase1GenesisRejectsCanonicalCheck(t *testing.T) {
	circuit := compileEngineCircuit(t)
	wrong, err := ContributePhase1(circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong.Challenge = nil
	root := t.TempDir()
	genesisPath := filepath.Join(root, "phase1", "genesis.bin")
	if err := os.MkdirAll(filepath.Dir(genesisPath), 0700); err != nil {
		t.Fatal(err)
	}
	wrongDigest, err := WritePhase1FileNoReplace(genesisPath, wrong, Phase1Shape{DomainN: circuit.Binding.DomainSize})
	if err != nil {
		t.Fatal(err)
	}
	d := adversarialDefinition(t)
	d.Mode = ModeRehearsal
	d.AssurancePolicy.ExternalSecurityAuditSignoffs = 0
	d.Circuit = circuit.Binding
	d.Schema = DefinitionSchemaV5
	d.ReleaseVerification = CoordinatorReplayReleaseV1
	d.Phase1Genesis = ArtifactRef{Name: "phase1/genesis.bin", Digest: modelDigest(wrongDigest)}
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	key := adversarialPrivateKey(0x01)
	writeSigned := func(name string, record any) {
		t.Helper()
		raw, sig, err := SignRecord(record, d.Coordinator.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name+".sig"), sig, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeSigned("ceremony", d)
	if err := os.WriteFile(filepath.Join(root, "coordinator.hex"), []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0600); err != nil {
		t.Fatal(err)
	}
	phaseID, err := ComputePhaseID(d.CeremonyID, Phase1, d.Phase1Genesis, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewChain(d.CeremonyID, Phase1, phaseID, d.Phase1Genesis)
	if err != nil {
		t.Fatal(err)
	}
	writeSigned("phase1/chain-0000", chain)
	trusted, err := LoadSignedDefinition(TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(root, "coordinator.hex")})
	if err != nil {
		t.Fatal(err)
	}
	paths := PhaseTranscriptPaths{RootDir: root, ChainPath: filepath.Join(root, "phase1", "chain-0000.json"), ChainSignaturePath: filepath.Join(root, "phase1", "chain-0000.sig")}
	verified, _, err := loadVerifiedPhase1FilesExact(trusted, circuit, paths)
	if err != nil {
		t.Fatalf("signed wrong genesis should pass evidence authentication: %v", err)
	}
	if _, err := canonicalPhase1Genesis(trusted, circuit, verified); err == nil {
		t.Fatal("signed native-valid but noncanonical Phase 1 genesis passed")
	}
	if _, err := LoadReplayPhase1Files(trusted, circuit, paths); err == nil {
		t.Fatal("independent Phase 1 replay accepted signed noncanonical genesis")
	}
}

func TestNoncanonicalPhase1GenesisCanHaveValidNativeShape(t *testing.T) {
	contribution, err := ContributePhase1(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	contribution.Challenge = nil
	path := filepath.Join(t.TempDir(), "genesis.bin")
	if _, err := WritePhase1FileNoReplace(path, contribution, Phase1Shape{DomainN: 2}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPhase1File(path, Phase1Shape{DomainN: 2}); err != nil {
		t.Fatal(err)
	}
}
