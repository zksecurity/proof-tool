package main

import "testing"

func TestParseCheckpointInitializeV4RequiresOnlyAuthenticatedGenesisInputs(t *testing.T) {
	o, err := parseCheckpointV4("initialize-v4", []string{
		"--ceremony", "/public/ceremony.json",
		"--ceremony-signature", "/public/ceremony.sig",
		"--coordinator-public-key-file", "/trust/coordinator.hex",
		"--artifact-root", "/public",
		"--coordinator-signing-key", "/keys/signing.hex",
		"--out-dir", "/public/checkpoints/initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.CheckpointPath != "" || o.ProposalPath != "" || o.OutDir != "/public/checkpoints/initial" {
		t.Fatalf("initialization accepted caller-authored state: %+v", o)
	}
}

func TestParseCheckpointInitializeV4RejectsPredecessor(t *testing.T) {
	_, err := parseCheckpointV4("initialize-v4", []string{
		"--ceremony", "/public/ceremony.json",
		"--ceremony-signature", "/public/ceremony.sig",
		"--coordinator-public-key-file", "/trust/coordinator.hex",
		"--artifact-root", "/public",
		"--coordinator-signing-key", "/keys/signing.hex",
		"--out-dir", "/public/checkpoints/initial",
		"--checkpoint", "/public/checkpoints/another.json",
	})
	if err == nil {
		t.Fatal("initialization accepted a caller-supplied predecessor")
	}
}
