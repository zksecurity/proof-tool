package main

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"proof-tool/internal/keybundle"
	m "proof-tool/internal/mpcceremony"
)

type CheckpointOptionsV4 struct {
	InspectDefinitionOptions
	ArtifactRoot, ProposalPath, RejectedCandidateDir string
	CheckpointPath, CheckpointSignaturePath          string
	CoordinatorSigningKey, OutPath                   string
}

type CheckpointInspectionV4 struct {
	Schema                  string               `json:"schema"`
	Depth                   string               `json:"depth"`
	Checkpoint              m.CheckpointV4       `json:"checkpoint"`
	CheckpointRefs          m.SignedArtifactRefs `json:"checkpoint_refs"`
	ArtifactsVerified       bool                 `json:"artifacts_verified"`
	MathematicsReplayed     bool                 `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                 `json:"global_freshness_verified"`
}

type CheckpointDiscoveryInspectionV4 struct {
	Schema                  string                  `json:"schema"`
	Depth                   string                  `json:"depth"`
	Discovery               m.CheckpointDiscoveryV4 `json:"discovery"`
	CheckpointRefs          m.SignedArtifactRefs    `json:"checkpoint_refs"`
	AncestryVerified        bool                    `json:"ancestry_verified"`
	ArtifactsVerified       bool                    `json:"artifacts_verified"`
	MathematicsReplayed     bool                    `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                    `json:"global_freshness_verified"`
}

func parseCheckpointV4(action string, args []string) (CheckpointOptionsV4, error) {
	var o CheckpointOptionsV4
	fs := commandFlagSet("checkpoint " + action)
	addCeremonyTrustFlags(fs, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	fs.StringVar(&o.ArtifactRoot, "artifact-root", "", "local root containing protocol artifacts")
	if action == "verify-stored-v4" || action == "inspect-signed-v4" {
		fs.StringVar(&o.CheckpointPath, "checkpoint", "", "exact checkpoint under artifact-root")
		fs.StringVar(&o.CheckpointSignaturePath, "checkpoint-signature", "", "exact detached checkpoint signature under artifact-root")
	} else {
		fs.StringVar(&o.ProposalPath, "proposal", "", "exact canonical V4 checkpoint proposal")
		fs.StringVar(&o.RejectedCandidateDir, "rejected-candidate-dir", "", "private candidate directory required only for contribution-rejected")
		fs.StringVar(&o.OutPath, "out", "", "fresh output file; parent must exist")
		if action == "sign-v4" {
			fs.StringVar(&o.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
		}
	}
	if err := parseFlags(fs, args); err != nil {
		return o, err
	}
	if err := requireValues(pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--artifact-root", o.ArtifactRoot)); err != nil {
		return o, err
	}
	if action == "verify-stored-v4" || action == "inspect-signed-v4" {
		return o, requireValues(pathValue("--checkpoint", o.CheckpointPath), pathValue("--checkpoint-signature", o.CheckpointSignaturePath))
	}
	if action != "prepare-v4" && action != "sign-v4" {
		return o, errors.New("unknown V4 checkpoint action")
	}
	if o.RejectedCandidateDir != "" {
		if err := validatePathValue("--rejected-candidate-dir", o.RejectedCandidateDir); err != nil {
			return o, err
		}
	}
	if err := requireValues(pathValue("--proposal", o.ProposalPath), pathValue("--out", o.OutPath)); err != nil {
		return o, err
	}
	if action == "sign-v4" {
		return o, requireValues(pathValue("--coordinator-signing-key", o.CoordinatorSigningKey))
	}
	return o, nil
}

func checkpointNeedsCircuitV4(kind m.CheckpointTransitionKind) (bool, error) {
	switch kind {
	case m.CheckpointInitial, m.CheckpointPhase1CandidateAccepted, m.CheckpointPhase2CandidateAccepted,
		m.CheckpointPhase1Sealed, m.CheckpointPhase2Initialized, m.CheckpointFinalCandidateRecorded:
		return true, nil
	case m.CheckpointPhase1OutboundPublished, m.CheckpointPhase2OutboundPublished,
		m.CheckpointPhase1ReceiptAccepted, m.CheckpointPhase2ReceiptAccepted,
		m.CheckpointDeliveryRetired, m.CheckpointDeliveryReallocated, m.CheckpointContributionRejected,
		m.CheckpointPhase1Closed, m.CheckpointPhase2Closed, m.CheckpointPhase1BeaconRecorded, m.CheckpointPhase2BeaconRecorded,
		m.CheckpointFinalReleaseRecorded, m.CheckpointEnrollmentRecorded, m.CheckpointMirrorRecorded,
		m.CheckpointWitnessRecorded, m.CheckpointBeaconEvidenceRecorded, m.CheckpointAuditRecorded,
		m.CheckpointIncidentRecorded, m.CheckpointAborted, m.CheckpointRestarted:
		return false, nil
	default:
		return false, fmt.Errorf("unclassified V4 checkpoint transition %q", kind)
	}
}

func executeCheckpointV4(command Command, o CheckpointOptionsV4) (CommandResult, error) {
	trust := trustPaths(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile)
	trusted, err := m.LoadSignedDefinition(trust)
	if err != nil {
		return CommandResult{}, err
	}
	d := trusted.Definition
	if d.Schema != m.DefinitionSchemaV4 {
		return CommandResult{}, errors.New("V4 checkpoint commands require definition v4")
	}
	if err := m.VerifyRunningSoftwareForMode(d.Software, d.Mode); err != nil {
		return CommandResult{}, err
	}
	if command == CommandCheckpointInspectSignedV4 {
		record, signature, refs, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		db, err := m.MarshalCanonical(d)
		if err != nil {
			return CommandResult{}, err
		}
		ds, err := readRegularOperationalFile(o.CeremonySignaturePath, 4096)
		if err != nil {
			return CommandResult{}, err
		}
		discovery, err := m.DiscoverSignedCheckpointV4(d, db, ds, record, signature)
		if err != nil {
			return CommandResult{}, err
		}
		return CommandResult{CeremonyID: d.CeremonyID,
			Summary:               "Authenticated one checkpoint for file discovery only. Ancestry, referenced evidence, contribution mathematics and freshness are not verified.",
			CheckpointDiscoveryV4: &CheckpointDiscoveryInspectionV4{Schema: "proof-tool-mpc-checkpoint-discovery-v4", Depth: "signed-checkpoint-discovery", Discovery: discovery, CheckpointRefs: refs}}, nil
	}
	if command == CommandCheckpointVerifyStoredV4 {
		_, _, refs, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		c, err := m.VerifyStoredCheckpointV4(trust, o.ArtifactRoot, refs)
		if err != nil {
			return CommandResult{}, err
		}
		if c.CeremonyID != d.CeremonyID {
			return CommandResult{}, errors.New("authenticated ceremony changed during checkpoint inspection")
		}
		return CommandResult{CeremonyID: c.CeremonyID,
			Summary:                "Authenticated checkpoint ancestry and legal metadata transitions. Referenced artifacts, contribution mathematics and global freshness were not verified.",
			CheckpointInspectionV4: &CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: refs}}, nil
	}
	if command != CommandCheckpointPrepareV4 && command != CommandCheckpointSignV4 {
		return CommandResult{}, errors.New("unknown V4 checkpoint command")
	}
	data, err := readRegularOperationalFile(o.ProposalPath, maxOperationalRecordBytes)
	if err != nil {
		return CommandResult{}, err
	}
	var proposal m.CheckpointV4
	if err := m.UnmarshalCanonical(data, &proposal); err != nil {
		return CommandResult{}, err
	}
	if err := proposal.Validate(); err != nil {
		return CommandResult{}, err
	}
	if proposal.CeremonyID != d.CeremonyID {
		return CommandResult{}, errors.New("proposal belongs to another ceremony")
	}
	if (proposal.Transition.Kind == m.CheckpointContributionRejected) != (o.RejectedCandidateDir != "") {
		return CommandResult{}, errors.New("only contribution-rejected requires --rejected-candidate-dir")
	}
	if err := validateCheckpointPathsV4(o); err != nil {
		return CommandResult{}, err
	}
	needsCircuit, err := checkpointNeedsCircuitV4(proposal.Transition.Kind)
	if err != nil {
		return CommandResult{}, err
	}
	var circuit *m.CompiledCircuit
	if needsCircuit {
		// Authenticate the stored circuit bytes; never rebuild a possibly different circuit.
		path := filepath.Join(o.ArtifactRoot, filepath.FromSlash(d.Circuit.R1CS.Name))
		ref, err := checkpointArtifactRef(o.ArtifactRoot, path)
		if err != nil {
			return CommandResult{}, err
		}
		if ref != d.Circuit.R1CS {
			return CommandResult{}, errors.New("stored circuit differs from the signed definition")
		}
		circuit, err = m.ReadR1CSFile(path, d.Circuit)
		if err != nil {
			return CommandResult{}, err
		}
	}
	checked, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: o.ArtifactRoot, Proposal: proposal, Circuit: circuit, RejectedCandidateDir: o.RejectedCandidateDir})
	if err != nil {
		return CommandResult{}, err
	}
	if !bytes.Equal(data, checked) {
		return CommandResult{}, errors.New("checked checkpoint differs from exact proposal bytes")
	}
	summary := "Checked this exact local proposal; it is unsigned and is not published ceremony state."
	outputKind := "proposal"
	if command == CommandCheckpointSignV4 {
		private, public, err := keybundle.LoadExistingPrivateKey(o.CoordinatorSigningKey)
		if err != nil {
			return CommandResult{}, err
		}
		if !bytes.Equal(public, trusted.CoordinatorPublicKey) {
			return CommandResult{}, errors.New("checkpoint signing key is not the authenticated coordinator key")
		}
		signature, err := m.SignExact(checked, d.Coordinator.KeyID, private)
		if err != nil {
			return CommandResult{}, err
		}
		checked, err = m.MarshalCanonical(signature)
		if err != nil {
			return CommandResult{}, err
		}
		summary = "Signed this exact proposal. It is not the published current head until the delivery service uploads the pair and successfully updates the head."
		outputKind = "checkpoint_signature"
	}
	if err := writeFreshOperationalFile(o.OutPath, checked, 0o600); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: d.CeremonyID, Summary: summary, Outputs: map[string]string{outputKind: o.OutPath, "input_proposal": o.ProposalPath}}, nil
}

func validateCheckpointPathsV4(o CheckpointOptionsV4) error {
	for _, path := range []string{o.ProposalPath, o.OutPath} {
		for _, subtree := range []string{"final/candidate", "final/release"} {
			if err := validatePathOutsideTree(o.ArtifactRoot, subtree, path); err != nil {
				return err
			}
		}
		if o.RejectedCandidateDir != "" {
			if err := validatePathOutsideTree(o.RejectedCandidateDir, "", path); err != nil {
				return err
			}
		}
	}
	if o.RejectedCandidateDir != "" {
		// Do not stage private rejected bytes anywhere under the public artifact
		// root, or make that root a child of the private candidate directory.
		public, err := filepath.EvalSymlinks(o.ArtifactRoot)
		if err != nil {
			return err
		}
		private, err := filepath.EvalSymlinks(o.RejectedCandidateDir)
		if err != nil {
			return err
		}
		if err := validatePathOutsideTree(public, "", private); err != nil {
			return errors.New("private rejected candidate and public artifact root must be disjoint")
		}
		if err := validatePathOutsideTree(private, "", public); err != nil {
			return errors.New("private rejected candidate and public artifact root must be disjoint")
		}
	}
	return nil
}
