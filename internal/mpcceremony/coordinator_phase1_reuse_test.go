package mpcceremony

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCoordinatorPhase1AcceptanceBasedCommons(t *testing.T) {
	testCoordinatorPhase1AcceptanceBasedCommons(t, DefinitionSchemaV5)
}

func testCoordinatorPhase1AcceptanceBasedCommons(t *testing.T, schema string) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("signed workflow fixture requires Linux executable identity")
	}
	t.Setenv("MPC_WORKFLOW_CHECKPOINT_V4", "1")
	t.Setenv("MPC_WORKFLOW_CHECK_P1_REUSE", "1")
	t.Setenv("MPC_WORKFLOW_STOP_AFTER_P1_REUSE", "1")
	fixture := newDirectAcceptanceFixture(t)
	actualCircuit, compileErr := CompileForKeyVersion(fixture.trusted.Definition.Circuit.KeyVersion)
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	if err := ValidateCircuitBinding(actualCircuit, fixture.trusted.Definition.Circuit); err != nil {
		t.Fatal(err)
	}
	fixture.circuit = actualCircuit
	if fixture.trusted.Definition.Schema != schema {
		t.Fatalf("signed fixture schema = %s, expected %s", fixture.trusted.Definition.Schema, schema)
	}
	load := func(method phase1VerificationMethod) ([]byte, error) {
		commons, _, _, err := loadPhase1CommonsWithMethod(fixture.trusted, fixture.circuit, fixture.ceremonyRoot, fixture.phase1SealPath, fixture.phase1SealSignature, method)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		_, err = commons.WriteTo(&out)
		return out.Bytes(), err
	}
	independent, err := load(phase1IndependentReplay)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := load(phase1CoordinatorAcceptance)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(independent, accepted) {
		t.Fatal("acceptance-derived commons differ from full replay")
	}
	if _, err := load(phase1VerificationMethod("unknown")); err == nil {
		t.Fatal("unknown method accepted")
	}
	legacy := *fixture.trusted
	legacy.Definition.Schema = DefinitionSchemaV3
	if _, _, _, err := loadPhase1CommonsWithMethod(&legacy, fixture.circuit, fixture.ceremonyRoot, fixture.phase1SealPath, fixture.phase1SealSignature, phase1CoordinatorAcceptance); err == nil {
		t.Fatal("legacy accepted coordinator V4 shortcut")
	}
	t.Run("validly signed wrong commons", func(t *testing.T) {
		var seal SealRecord
		if err := loadCoordinatorSignedRecord(fixture.trusted, fixture.phase1SealPath, fixture.phase1SealSignature, &seal); err != nil {
			t.Fatal(err)
		}
		commonsPath := filepath.Join(fixture.ceremonyRoot, seal.Outputs[0].Name)
		paths := []string{commonsPath, fixture.phase1SealPath, fixture.phase1SealSignature}
		originals := make([][]byte, len(paths))
		for i, path := range paths {
			var err error
			originals[i], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for i, path := range paths {
				if err := os.WriteFile(path, originals[i], 0600); err != nil {
					t.Fatal(err)
				}
			}
		}()
		commons, _, err := ReadCommonsFile(commonsPath, CommonsShape{DomainN: fixture.circuit.Binding.DomainSize})
		if err != nil {
			t.Fatal(err)
		}
		commons.G1.Tau[1].SetInfinity()
		var encoded bytes.Buffer
		if _, err := commons.WriteTo(&encoded); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(encoded.Bytes(), originals[0]) {
			t.Fatal("wrong-commons fixture did not change serialized bytes")
		}
		seal.Outputs[0].Digest = NewDigest(encoded.Bytes())
		seal, err = NewSealRecord(seal)
		if err != nil {
			t.Fatal(err)
		}
		key, _, err := loadMatchingPrivateKey(fixture.coordinatorKeyPath, fixture.trusted.Definition.Coordinator)
		if err != nil {
			t.Fatal(err)
		}
		record, signature, err := SignRecord(seal, fixture.trusted.Definition.Coordinator.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		for i, data := range [][]byte{encoded.Bytes(), record, signature} {
			if err := os.WriteFile(paths[i], data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := load(phase1CoordinatorAcceptance); err == nil {
			t.Fatal("signed commons differing from beacon application accepted")
		}
	})
	for _, name := range []string{"phase1/contributions/0001/contribution.bin", "phase1/contributions/0001/verification.json", "phase1/contributions/0001/attestation.sig", "phase1/contributions/0001/erasure.sig", "phase1/sealed/commons.bin", "phase1/beacon/record.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixture.ceremonyRoot, name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}()
			changed := bytes.Clone(original)
			changed[len(changed)/2] ^= 1
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := load(phase1CoordinatorAcceptance); err == nil {
				t.Fatal("changed artifact accepted")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := load(phase1CoordinatorAcceptance); err == nil {
				t.Fatal("missing artifact accepted")
			}
		})
	}
}
