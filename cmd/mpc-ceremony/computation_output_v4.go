package main

import m "proof-tool/internal/mpcceremony"

type ComputationOutputInspectionV4 struct {
	Schema                  string                          `json:"schema"`
	Depth                   string                          `json:"depth"`
	Output                  m.ComputationOutputInspectionV4 `json:"output"`
	SignaturesVerified      bool                            `json:"signatures_verified"`
	PayloadDigestVerified   bool                            `json:"payload_digest_verified"`
	CleanupVerified         bool                            `json:"cleanup_verified"`
	MathematicsReplayed     bool                            `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                            `json:"global_freshness_verified"`
	PhysicalErasureVerified bool                            `json:"physical_erasure_verified"`
}

func executeComputationOutputV4(o ContributionInventoryOptionsV4) (CommandResult, error) {
	scope, err := expectedContributionInspectionScopeV4(o)
	if err != nil {
		return CommandResult{}, err
	}
	output, err := m.InspectComputationOutputV4(trustPaths(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile), m.PhaseTranscriptPaths{RootDir: o.TranscriptRoot, ChainPath: o.ChainPath, ChainSignaturePath: o.ChainSignaturePath}, scope, o.CandidateDir)
	if err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: scope.CeremonyID, Phase: string(scope.Phase), Summary: "Verified the three generated public files. Cleanup, process exit, mathematics, freshness and acceptance are not verified.", ComputationOutputV4: &ComputationOutputInspectionV4{Schema: "proof-tool-mpc-computation-output-inspection-v4", Depth: "computation-signatures-and-digests", Output: output, SignaturesVerified: true, PayloadDigestVerified: true}}, nil
}
