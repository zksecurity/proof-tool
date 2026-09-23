package mpcceremony

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestK11CircuitIdentity(t *testing.T) {
	tiny, err := CompileForKeyVersion(KeyVersionRehearsal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCanonicalCeremonyCircuit(tiny.Binding); err != nil {
		t.Fatal(err)
	}
	circuit, err := CompileForKeyVersion(KeyVersionRehearsalK11)
	if err != nil {
		t.Fatal(err)
	}
	if circuit.Binding.DomainSize != 1<<11 {
		t.Fatalf("K11 domain = %d, want %d", circuit.Binding.DomainSize, 1<<11)
	}
	if err := ValidateCanonicalCeremonyCircuit(circuit.Binding); err != nil {
		t.Fatal(err)
	}
	altered := circuit.Binding
	altered.R1CS.Digest.SHA256 = tiny.Binding.R1CS.Digest.SHA256
	if err := ValidateCanonicalCeremonyCircuit(altered); err == nil {
		t.Fatal("accepted a different K11 circuit digest")
	}
}

func TestProductionDefinitionBindsReviewedTestCircuits(t *testing.T) {
	for _, keyVersion := range []string{KeyVersionRehearsal, KeyVersionRehearsalK11} {
		t.Run(keyVersion, func(t *testing.T) {
			circuit, err := CompileForKeyVersion(keyVersion)
			if err != nil {
				t.Fatal(err)
			}
			definition := adversarialDefinition(t)
			definition.Circuit = circuit.Binding
			definition.CeremonyID = ""
			definition, err = FinalizeCeremonyDefinition(definition)
			if err != nil {
				t.Fatalf("production-mode test circuit definition: %v", err)
			}
			if err := definition.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProductionModeTestCircuitSignedInitialization(t *testing.T) {
	for _, keyVersion := range []string{KeyVersionRehearsal, KeyVersionRehearsalK11} {
		t.Run(keyVersion, func(t *testing.T) {
			circuit, err := CompileForKeyVersion(keyVersion)
			if err != nil {
				t.Fatal(err)
			}
			template := adversarialDefinition(t)
			root := t.TempDir()
			keyPath := filepath.Join(root, "coordinator.key")
			if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(adversarialPrivateKey(0x01))), 0o600); err != nil {
				t.Fatal(err)
			}
			initialized, err := InitializeCeremonyFiles(InitFilesOptions{
				RootDir: filepath.Join(root, "ceremony"), Circuit: circuit,
				CoordinatorPrivateKeyPath: keyPath,
				Definition: DefinitionOptions{
					Mode: ModeProduction, ReleaseVerification: CoordinatorReplayReleaseV1,
					CreatedAt: template.CreatedAt, SessionNonceHex: template.SessionNonceHex,
					Software: template.Software, Coordinator: template.Coordinator,
					ReleaseSigner: template.ReleaseSigner, Auditors: template.Auditors,
					Roster: template.Roster, Phase1Policy: template.Phase1Policy,
					Phase2Policy: template.Phase2Policy, BeaconPolicy: template.BeaconPolicy,
					AssurancePolicy: template.AssurancePolicy,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := LoadSignedDefinition(TrustPaths{
				DefinitionPath:           initialized.DefinitionPath,
				DefinitionSignaturePath:  initialized.DefinitionSignaturePath,
				CoordinatorPublicKeyPath: initialized.CoordinatorPublicKeyPath,
			})
			if err != nil {
				t.Fatal(err)
			}
			if trusted.Definition.Mode != ModeProduction || trusted.Definition.Schema != DefinitionSchemaV5 ||
				trusted.Definition.Circuit.KeyVersion != keyVersion {
				t.Fatalf("wrong signed production-mode circuit: %+v", trusted.Definition.Circuit)
			}
			if _, err := ReadR1CSFile(initialized.R1CSPath, trusted.Definition.Circuit); err != nil {
				t.Fatalf("signed R1CS: %v", err)
			}
		})
	}
}
