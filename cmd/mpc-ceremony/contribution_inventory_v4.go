package main

import m "proof-tool/internal/mpcceremony"

type ContributionInventoryOptionsV4 struct {
	InspectChainOptions
	ScopePath    string
	CandidateDir string
}

type ContributionInventoryInspectionV4 struct {
	Schema                  string                              `json:"schema"`
	Depth                   string                              `json:"depth"`
	Inventory               m.ContributionInventoryInspectionV4 `json:"inventory"`
	SignaturesVerified      bool                                `json:"signatures_verified"`
	PayloadDigestVerified   bool                                `json:"payload_digest_verified"`
	MathematicsReplayed     bool                                `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                                `json:"global_freshness_verified"`
	PhysicalErasureVerified bool                                `json:"physical_erasure_verified"`
}

func parseContributionInventoryV4(args []string) (ContributionInventoryOptionsV4, error) {
	var o ContributionInventoryOptionsV4
	fs := commandFlagSet("inspect contribution-inventory-v4")
	addCeremonyTrustFlags(fs, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	fs.StringVar(&o.TranscriptRoot, "transcript-root", "", "local transcript root")
	fs.StringVar(&o.ChainPath, "chain", "", "exact signed predecessor chain")
	fs.StringVar(&o.ChainSignaturePath, "chain-signature", "", "predecessor signature")
	fs.StringVar(&o.ScopePath, "scope", "", "canonical expected contribution scope from authenticated state or retained operation")
	fs.StringVar(&o.CandidateDir, "candidate-dir", "", "retained candidate directory; fixed public filenames only")
	if err := parseFlags(fs, args); err != nil {
		return o, err
	}
	return o, requireValues(pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--transcript-root", o.TranscriptRoot), pathValue("--chain", o.ChainPath), pathValue("--chain-signature", o.ChainSignaturePath), pathValue("--scope", o.ScopePath), pathValue("--candidate-dir", o.CandidateDir))
}

func executeContributionInventoryV4(o ContributionInventoryOptionsV4) (CommandResult, error) {
	trusted, err := loadInspectionCeremony(o.InspectDefinitionOptions)
	if err != nil {
		return CommandResult{}, err
	}
	if err := m.VerifyRunningSoftwareForMode(trusted.Definition.Software, trusted.Definition.Mode); err != nil {
		return CommandResult{}, err
	}
	raw, err := readRegularOperationalFile(o.ScopePath, 4096)
	if err != nil {
		return CommandResult{}, err
	}
	var scope m.ContributionScope
	if err := m.UnmarshalCanonical(raw, &scope); err != nil {
		return CommandResult{}, err
	}
	if err := scope.ValidateAssignment(trusted.Definition); err != nil {
		return CommandResult{}, err
	}
	i, err := m.InspectContributionInventoryV4(trustPaths(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile), m.PhaseTranscriptPaths{RootDir: o.TranscriptRoot, ChainPath: o.ChainPath, ChainSignaturePath: o.ChainSignaturePath}, scope, o.CandidateDir)
	if err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: i.Scope.CeremonyID, Phase: string(i.Scope.Phase), Summary: "Verified retained candidate signatures, exact file digests and expected predecessor. No contribution mathematics, acceptance, freshness or physical erasure verified.", ContributionInventoryV4: &ContributionInventoryInspectionV4{Schema: "proof-tool-mpc-contribution-inventory-inspection-v4", Depth: "candidate-signatures-and-digests", Inventory: i, SignaturesVerified: true, PayloadDigestVerified: true}}, nil
}
