package main

import (
	"fmt"
	"os"
	"path/filepath"
	"proof-tool/internal/mpcceremony"
)

func checkGenesisVerification(options mpcceremony.VerifyPhase2GenesisFilesOptions, nonempty mpcceremony.PhaseTranscriptPaths) error {
	valid, err := mpcceremony.VerifyPhase2GenesisFiles(options)
	if err != nil {
		return fmt.Errorf("valid genesis: %w", err)
	}
	wrongPhase := filepath.Join(options.TranscriptRoot, "phase1", "chain-0001.json")
	for _, path := range []string{wrongPhase, nonempty.ChainPath} {
		bad := options
		bad.Phase2ChainPath, bad.Phase2ChainSignaturePath = path, mpcceremony.DefaultSignaturePath(path)
		if _, err := mpcceremony.VerifyPhase2GenesisFiles(bad); err == nil {
			return fmt.Errorf("accepted wrong phase or nonzero chain")
		}
	}
	path := filepath.Join(options.TranscriptRoot, filepath.FromSlash(valid.Genesis.Name))
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)/2] ^= 1
	if err := os.WriteFile(path, mutated, 0600); err != nil {
		return err
	}
	_, verifyErr := mpcceremony.VerifyPhase2GenesisFiles(options)
	if err := os.WriteFile(path, original, 0600); err != nil {
		return err
	}
	if verifyErr == nil {
		return fmt.Errorf("accepted mutated genesis bytes")
	}
	if _, err := mpcceremony.VerifyPhase2GenesisFiles(options); err != nil {
		return fmt.Errorf("restored genesis: %w", err)
	}
	return nil
}
