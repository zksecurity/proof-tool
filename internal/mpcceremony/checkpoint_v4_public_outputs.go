package mpcceremony

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"
	"proof-tool/internal/prover"
)

// These are the unchanged export checks used by legacy VerifyRelease. Neither
// key generation nor contribution replay is performed.
func verifyCandidateKeyExports(d CeremonyDefinition, candidate CandidateMetadata, dir string) (groth16.VerifyingKey, error) {
	if _, err := ReadR1CSFile(filepath.Join(dir, candidate.ConstraintSystem.Name), d.Circuit); err != nil {
		return nil, err
	}
	vk, err := prover.LoadVK(filepath.Join(dir, NativeVerifyingKeyFile))
	if err != nil {
		return nil, err
	}
	if err := verifyCardanoFiles(dir, candidate, vk); err != nil {
		return nil, err
	}
	return vk, nil
}

// V4 verifies the published example proof without regenerating the setup keys.
// Do not silently add this gate to older released schema verification.
func verifyCandidatePublicOutputsV4(d CeremonyDefinition, candidate CandidateMetadata, dir string) error {
	vk, err := verifyCandidateKeyExports(d, candidate, dir)
	if err != nil {
		return err
	}
	cardano, format, err := prover.SerializeCardanoVK(vk)
	if err != nil {
		return err
	}
	var report VerificationReport
	if _, err := readCanonicalFile(filepath.Join(dir, candidate.VerificationReport.Name), &report); err != nil {
		return err
	}
	if err := validateCandidatePublicReport(report, cardano, format); err != nil {
		return err
	}
	if _, _, _, err := loadAndVerifyPublicEvidence(filepath.Join(dir, candidate.PublicEvidence.Name), d.CeremonyID, vk, cardano, candidate.CardanoVerifyingKey); err != nil {
		return fmt.Errorf("V4 public proof verification: %w", err)
	}
	return nil
}
