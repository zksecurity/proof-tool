package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

func decisionTrustV4(ceremony, signature, key string) mpcceremony.TrustPaths {
	return mpcceremony.TrustPaths{DefinitionPath: ceremony, DefinitionSignaturePath: signature, CoordinatorPublicKeyPath: key}
}

func executeDecisionPrepareV4(o DecisionPrepareOptions, ceremonyID string, draft []byte) (CommandResult, error) {
	if err := validateDecisionOutputV4(o.EvidenceRoot, o.OutPath); err != nil {
		return CommandResult{}, err
	}
	d, data, err := mpcceremony.PrepareProductionDecisionV4(decisionTrustV4(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile), o.EvidenceRoot, draft)
	if err != nil {
		return CommandResult{}, err
	}
	if err := checkDecisionCeremonyV4(d, ceremonyID); err != nil {
		return CommandResult{}, err
	}
	if err := writeFreshOperationalFile(o.OutPath, data, 0o600); err != nil {
		return CommandResult{}, err
	}
	return decisionCommandResultV4(d, "Prepared exact decision and verified local evidence; no decision signature or publication was created.", map[string]string{"decision": o.OutPath}), nil
}

func executeDecisionSignV4(o DecisionSignOptions, ceremonyID string, data []byte) (CommandResult, error) {
	if err := validateDecisionOutputV4(o.EvidenceRoot, o.OutPath); err != nil {
		return CommandResult{}, err
	}
	verification := mpcceremony.VerifyProductionDecisionEvidenceV4Options{
		Trust: decisionTrustV4(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile), ArtifactRoot: o.EvidenceRoot, DecisionBytes: data,
	}
	verified, err := mpcceremony.VerifyProductionDecisionEvidenceV4(verification)
	if err != nil {
		return CommandResult{}, fmt.Errorf("refuse to sign unverified decision evidence: %w", err)
	}
	if err := checkDecisionCeremonyV4(verified.Decision, ceremonyID); err != nil {
		return CommandResult{}, err
	}
	// Evidence must pass before loading the private key. The signing API rechecks it.
	privateKey, _, err := keybundle.LoadExistingPrivateKey(o.SigningKey)
	if err != nil {
		return CommandResult{}, err
	}
	signature, err := mpcceremony.SignProductionDecisionV4(verification, mpcceremony.DecisionSignerRole(o.Role), o.SignerID, privateKey)
	if err != nil {
		return CommandResult{}, err
	}
	if err := writeFreshOperationalFile(o.OutPath, signature, 0o600); err != nil {
		return CommandResult{}, err
	}
	return decisionCommandResultV4(verified.Decision, "Signed this exact decision with one role key; this alone does not establish the required signature set or publish files.", map[string]string{"decision": o.DecisionPath, "signature": o.OutPath}), nil
}

func executeDecisionVerifyV4(o DecisionVerifyOptions, ceremonyID string, data []byte, signatures [][]byte) (CommandResult, error) {
	if o.EvidenceRoot == "" {
		return CommandResult{}, errors.New("--evidence-root is required for definition v4 decisions")
	}
	verified, err := mpcceremony.VerifyProductionDecisionV4(mpcceremony.VerifyProductionDecisionV4Options{
		VerifyProductionDecisionEvidenceV4Options: mpcceremony.VerifyProductionDecisionEvidenceV4Options{
			Trust: decisionTrustV4(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile), ArtifactRoot: o.EvidenceRoot, DecisionBytes: data,
		}, SignatureBytes: signatures,
	})
	if err != nil {
		return CommandResult{}, err
	}
	if err := checkDecisionCeremonyV4(verified.Decision, ceremonyID); err != nil {
		return CommandResult{}, err
	}
	return decisionCommandResultV4(verified.Decision, fmt.Sprintf("Verified %s decision, %d exact role signatures and local release/evidence bindings; no files were published.", verified.Decision.Decision, len(verified.VerifiedSigners)), map[string]string{"decision": o.DecisionPath, "evidence_root": o.EvidenceRoot}), nil
}

func checkDecisionCeremonyV4(d mpcceremony.ProductionDecisionV3, expected string) error {
	if d.CeremonyID != expected {
		return errors.New("authenticated ceremony changed during decision verification")
	}
	return nil
}

func decisionCommandResultV4(d mpcceremony.ProductionDecisionV3, summary string, outputs map[string]string) CommandResult {
	return CommandResult{CeremonyID: d.CeremonyID, Decision: string(d.Decision), DecisionID: d.DecisionID,
		ReleaseID: d.Release.ReleaseID, CandidateID: d.Release.CandidateID, SourceCommit: d.SourceRelease.SourceCommit,
		Summary: summary, Outputs: outputs}
}

// Decision files belong outside the closed release package. The fresh writer
// still requires an existing parent and refuses to replace any existing leaf.
func validateDecisionOutputV4(root, out string) error {
	if root == "" {
		return errors.New("--evidence-root is required for definition v4 decisions")
	}
	packagePath, err := filepath.Abs(filepath.Join(root, "final", "release"))
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	inside := func(base, path string) bool {
		rel, err := filepath.Rel(base, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if inside(packagePath, outputPath) {
		return errors.New("decision output must be outside the immutable final/release package")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(outputPath))
	if err != nil {
		return err
	}
	if inside(filepath.Join(resolvedRoot, "final", "release"), filepath.Join(parent, filepath.Base(outputPath))) {
		return errors.New("decision output resolves inside the immutable final/release package")
	}
	return nil
}
