package mpcceremony

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

func verifyFinalCandidateV4(options CheckpointPreparationV4, trusted *TrustedCeremony, reader *checkpointReaderV4, previous CheckpointV4) error {
	t := options.Proposal.Transition
	if t.Record.Record.Name != "final/candidate/"+CandidateMetadataFile || t.Record.Signature.Name != "final/candidate/"+CandidateSignatureFile {
		return errors.New("final candidate must use its canonical closed directory")
	}
	if t.ReplayVerification == nil {
		return errors.New("final candidate requires the coordinator replay claim")
	}
	if options.RequireCurrentReplayExecutable {
		running, err := RunningSoftwareBindingForMode(trusted.Definition.Software.ProofToolVersion, trusted.Definition.Mode)
		if err != nil {
			return err
		}
		if t.ReplayVerification.ToolBinary != running.ToolBinary {
			return errors.New("final candidate replay claim must identify the executable performing this replay")
		}
	}
	paths, err := finalReplayPathsV4(options.Trust, trusted.Definition.Coordinator.Ed25519PublicKeyHex, reader.path, previous.Progress)
	if err != nil {
		return err
	}
	_, refs, err := VerifyFinalCandidateCheckpoint(paths, options.Circuit, filepath.Join(reader.path, "final/candidate"))
	if err != nil {
		return err
	}
	for i := range refs {
		refs[i].Name = "final/candidate/" + refs[i].Name
	}
	want := append([]ArtifactRef{t.Record.Record, t.Record.Signature}, t.Evidence...)
	slices.SortFunc(want, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	if !reflect.DeepEqual(refs, want) {
		return errors.New("final candidate checkpoint differs from the complete replayed file inventory")
	}
	return nil
}

// finalReplayPathsV4 derives every replay input from the authenticated previous
// checkpoint. Callers cannot substitute an unrelated, independently valid chain
// or beacon when claiming verification of this particular ceremony state.
func finalReplayPathsV4(trust TrustPaths, coordinatorKey, root string, p CheckpointProgressV4) (ReplayPaths, error) {
	if p.Phase1Closure == nil || p.Phase1Beacon == nil || p.Phase1Seal == nil || p.Phase2 == nil || p.Phase2Closure == nil || p.Phase2Beacon == nil {
		return ReplayPaths{}, errors.New("final replay requires both completed phases")
	}
	path := func(ref ArtifactRef) string { return filepath.Join(root, filepath.FromSlash(ref.Name)) }
	return ReplayPaths{
		TranscriptRoot: root, CoordinatorPublicKeyHex: coordinatorKey,
		DefinitionPath: trust.DefinitionPath, DefinitionSignaturePath: trust.DefinitionSignaturePath,
		Phase1ChainPath: path(p.Phase1.Chain.Record), Phase1ChainSignaturePath: path(p.Phase1.Chain.Signature),
		Phase1ClosePath: path(p.Phase1Closure.Record), Phase1CloseSignaturePath: path(p.Phase1Closure.Signature),
		Phase1BeaconPath: path(p.Phase1Beacon.Record), Phase1BeaconSignaturePath: path(p.Phase1Beacon.Signature),
		Phase1SealPath: path(p.Phase1Seal.Record), Phase1SealSignaturePath: path(p.Phase1Seal.Signature),
		Phase2ChainPath: path(p.Phase2.Chain.Record), Phase2ChainSignaturePath: path(p.Phase2.Chain.Signature),
		Phase2ClosePath: path(p.Phase2Closure.Record), Phase2CloseSignaturePath: path(p.Phase2Closure.Signature),
		Phase2BeaconPath: path(p.Phase2Beacon.Record), Phase2BeaconSignaturePath: path(p.Phase2Beacon.Signature),
	}, nil
}
