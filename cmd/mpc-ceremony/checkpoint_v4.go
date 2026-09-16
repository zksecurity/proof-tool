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
	CoordinatorSigningKey, OutPath, OutDir           string
	AttemptID, AllocatedAt, AcceptedAt, CandidateDir string
	TransitionKind, RecordPath, RecordSignaturePath  string
	EvidencePaths                                    []string
}

type CheckpointInspectionV4 struct {
	Schema                  string                    `json:"schema"`
	Depth                   string                    `json:"depth"`
	Checkpoint              m.CheckpointV4            `json:"checkpoint"`
	CheckpointRefs          m.SignedArtifactRefs      `json:"checkpoint_refs"`
	Commitments             m.CheckpointCommitmentsV4 `json:"commitments"`
	ArtifactsVerified       bool                      `json:"artifacts_verified"`
	MathematicsReplayed     bool                      `json:"mathematics_replayed"`
	GlobalFreshnessVerified bool                      `json:"global_freshness_verified"`
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

type EnrollmentMetadataInspectionV4 struct {
	Schema                       string                 `json:"schema"`
	Depth                        string                 `json:"depth"`
	Metadata                     m.EnrollmentMetadataV4 `json:"metadata"`
	EnrollmentSignaturesVerified bool                   `json:"enrollment_signatures_verified"`
	DisclosureContentsVerified   bool                   `json:"disclosure_contents_verified"`
	CompleteRosterVerified       bool                   `json:"complete_roster_verified"`
	GlobalFreshnessVerified      bool                   `json:"global_freshness_verified"`
}

func checkpointReadOnlyActionV4(action string) bool {
	return action == "verify-stored-v4" || action == "inspect-signed-v4" || action == "inspect-enrollments-v4"
}

func parseCheckpointV4(action string, args []string) (CheckpointOptionsV4, error) {
	var o CheckpointOptionsV4
	fs := commandFlagSet("checkpoint " + action)
	addCeremonyTrustFlags(fs, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	fs.StringVar(&o.ArtifactRoot, "artifact-root", "", "local root containing protocol artifacts")
	if checkpointReadOnlyActionV4(action) || action == "initialize-v4" || action == "record-v4" || action == "allocate-v4" || action == "accept-candidate-v4" {
		if action == "initialize-v4" {
			fs.StringVar(&o.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
			fs.StringVar(&o.OutDir, "out-dir", "", "fresh atomic output directory for the signed initial checkpoint pair")
		} else {
			fs.StringVar(&o.CheckpointPath, "checkpoint", "", "exact checkpoint under artifact-root")
			fs.StringVar(&o.CheckpointSignaturePath, "checkpoint-signature", "", "exact detached checkpoint signature under artifact-root")
			if action == "record-v4" {
				fs.StringVar(&o.TransitionKind, "transition", "", "record-backed V4 transition kind")
				fs.StringVar(&o.RecordPath, "record", "", "exact signed protocol record under artifact-root")
				fs.StringVar(&o.RecordSignaturePath, "record-signature", "", "detached protocol record signature under artifact-root")
				fs.Var((*stringList)(&o.EvidencePaths), "evidence", "exact evidence file under artifact-root; repeat for every required file")
				fs.StringVar(&o.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
				fs.StringVar(&o.OutDir, "out-dir", "", "fresh atomic output directory for the signed descendant checkpoint pair")
			}
			if action == "allocate-v4" || action == "accept-candidate-v4" {
				fs.StringVar(&o.AttemptID, "attempt-id", "", "fresh 32-character hexadecimal delivery attempt ID")
				fs.StringVar(&o.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
				fs.StringVar(&o.OutDir, "out-dir", "", "fresh atomic output directory for the signed checkpoint pair")
			}
			if action == "allocate-v4" {
				fs.StringVar(&o.AllocatedAt, "allocated-at", "", "allocation time in RFC3339 format")
			}
			if action == "accept-candidate-v4" {
				fs.StringVar(&o.CandidateDir, "candidate-dir", "", "exact complete candidate directory")
				fs.StringVar(&o.AcceptedAt, "accepted-at", "", "acceptance time in RFC3339 format")
			}
		}
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
	if checkpointReadOnlyActionV4(action) {
		return o, requireValues(pathValue("--checkpoint", o.CheckpointPath), pathValue("--checkpoint-signature", o.CheckpointSignaturePath))
	}
	if action == "initialize-v4" {
		return o, requireValues(pathValue("--coordinator-signing-key", o.CoordinatorSigningKey), pathValue("--out-dir", o.OutDir))
	}
	if action == "record-v4" {
		return o, requireValues(pathValue("--checkpoint", o.CheckpointPath), pathValue("--checkpoint-signature", o.CheckpointSignaturePath), value("--transition", o.TransitionKind), pathValue("--record", o.RecordPath), pathValue("--record-signature", o.RecordSignaturePath), pathValue("--coordinator-signing-key", o.CoordinatorSigningKey), pathValue("--out-dir", o.OutDir))
	}
	if action == "allocate-v4" || action == "accept-candidate-v4" {
		if err := requireValues(pathValue("--checkpoint", o.CheckpointPath), pathValue("--checkpoint-signature", o.CheckpointSignaturePath), value("--attempt-id", o.AttemptID), pathValue("--coordinator-signing-key", o.CoordinatorSigningKey), pathValue("--out-dir", o.OutDir)); err != nil {
			return o, err
		}
		if action == "allocate-v4" {
			return o, requireValues(value("--allocated-at", o.AllocatedAt))
		}
		return o, requireValues(pathValue("--candidate-dir", o.CandidateDir), value("--accepted-at", o.AcceptedAt))
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
	case m.CheckpointPhase1CandidateAllocated, m.CheckpointPhase2CandidateAllocated,
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
	if o.OutDir != "" {
		if err := validateCheckpointAtomicOutputV4(o); err != nil {
			return CommandResult{}, err
		}
	}
	if command == CommandCheckpointInitializeV4 {
		circuit, err := loadCheckpointCircuitV4(o.ArtifactRoot, d)
		if err != nil {
			return CommandResult{}, err
		}
		prepared, err := m.PrepareInitialCheckpointV4(m.InitialCheckpointV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: o.ArtifactRoot})
		if err != nil {
			return CommandResult{}, err
		}
		private, public, err := keybundle.LoadExistingPrivateKey(o.CoordinatorSigningKey)
		if err != nil {
			return CommandResult{}, err
		}
		if !bytes.Equal(public, trusted.CoordinatorPublicKey) {
			return CommandResult{}, errors.New("checkpoint signing key is not the authenticated coordinator key")
		}
		signature, err := m.SignExact(prepared.Canonical, d.Coordinator.KeyID, private)
		if err != nil {
			return CommandResult{}, err
		}
		signatureBytes, err := m.MarshalCanonical(signature)
		if err != nil {
			return CommandResult{}, err
		}
		if err := writeAtomicOutputDir(o.OutDir, map[string][]byte{"checkpoint.json": prepared.Canonical, "checkpoint.sig": signatureBytes}); err != nil {
			return CommandResult{}, err
		}
		return CommandResult{CeremonyID: d.CeremonyID, Phase: string(m.Phase1), Sequence: 0, Summary: "derived and signed the initial checkpoint from the authenticated definition and replayed genesis chain; it is not current until the delivery service publishes it", Outputs: map[string]string{"checkpoint": filepath.Join(o.OutDir, "checkpoint.json"), "checkpoint_signature": filepath.Join(o.OutDir, "checkpoint.sig")}}, nil
	}
	if command == CommandCheckpointRecordV4 {
		_, _, refs, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		record, err := checkpointPairRefs(o.ArtifactRoot, o.RecordPath, o.RecordSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		evidence := make([]m.ArtifactRef, 0, len(o.EvidencePaths))
		for _, path := range o.EvidencePaths {
			ref, err := checkpointArtifactRef(o.ArtifactRoot, path)
			if err != nil {
				return CommandResult{}, err
			}
			evidence = append(evidence, ref)
		}
		kind := m.CheckpointTransitionKind(o.TransitionKind)
		var circuit *m.CompiledCircuit
		if needed, err := checkpointNeedsCircuitV4(kind); err != nil {
			return CommandResult{}, err
		} else if needed {
			circuit, err = loadCheckpointCircuitV4(o.ArtifactRoot, d)
			if err != nil {
				return CommandResult{}, err
			}
		}
		prepared, err := m.PrepareRecordedCheckpointV4(m.RecordedCheckpointV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: o.ArtifactRoot, Checkpoint: refs, Kind: kind, Record: record, Evidence: evidence})
		if err != nil {
			return CommandResult{}, err
		}
		private, public, err := keybundle.LoadExistingPrivateKey(o.CoordinatorSigningKey)
		if err != nil {
			return CommandResult{}, err
		}
		if !bytes.Equal(public, trusted.CoordinatorPublicKey) {
			return CommandResult{}, errors.New("checkpoint signing key is not the authenticated coordinator key")
		}
		signed, err := m.SignExact(prepared.Canonical, d.Coordinator.KeyID, private)
		if err != nil {
			return CommandResult{}, err
		}
		signatureBytes, err := m.MarshalCanonical(signed)
		if err != nil {
			return CommandResult{}, err
		}
		if err := writeAtomicOutputDir(o.OutDir, map[string][]byte{"checkpoint.json": prepared.Canonical, "checkpoint.sig": signatureBytes}); err != nil {
			return CommandResult{}, err
		}
		return CommandResult{CeremonyID: d.CeremonyID, Sequence: int(prepared.Checkpoint.Sequence), Summary: "verified the exact signed protocol record and derived its signed descendant checkpoint; it is not current until the delivery service publishes it", Outputs: map[string]string{"checkpoint": filepath.Join(o.OutDir, "checkpoint.json"), "checkpoint_signature": filepath.Join(o.OutDir, "checkpoint.sig")}}, nil
	}
	if command == CommandCheckpointAllocateV4 || command == CommandCheckpointAcceptCandidateV4 {
		_, _, refs, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		private, public, err := keybundle.LoadExistingPrivateKey(o.CoordinatorSigningKey)
		if err != nil {
			return CommandResult{}, err
		}
		if !bytes.Equal(public, trusted.CoordinatorPublicKey) {
			return CommandResult{}, errors.New("checkpoint signing key is not the authenticated coordinator key")
		}
		var canonical []byte
		var phase string
		var sequence uint64
		if command == CommandCheckpointAllocateV4 {
			prepared, err := m.PrepareCandidateAllocationCheckpointV4(m.CandidateAllocationCheckpointV4Options{Trust: trust, ArtifactRoot: o.ArtifactRoot, Checkpoint: refs, AttemptID: o.AttemptID, AllocatedAt: o.AllocatedAt})
			if err != nil {
				return CommandResult{}, err
			}
			canonical, phase, sequence = prepared.Canonical, string(prepared.Scope.Phase), prepared.Checkpoint.Sequence
		} else {
			circuit, err := loadCheckpointCircuitV4(o.ArtifactRoot, d)
			if err != nil {
				return CommandResult{}, err
			}
			prepared, err := m.VerifyAndAcceptAllocatedCandidateV4(m.AcceptAllocatedCandidateV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: o.ArtifactRoot, Checkpoint: refs, AttemptID: o.AttemptID, CandidateDir: o.CandidateDir, CoordinatorPrivateKeyPath: o.CoordinatorSigningKey, AcceptedAt: o.AcceptedAt})
			if err != nil {
				return CommandResult{}, err
			}
			canonical, phase, sequence = prepared.Canonical, string(prepared.Scope.Phase), prepared.Checkpoint.Sequence
		}
		signature, err := m.SignExact(canonical, d.Coordinator.KeyID, private)
		if err != nil {
			return CommandResult{}, err
		}
		signatureBytes, err := m.MarshalCanonical(signature)
		if err != nil {
			return CommandResult{}, err
		}
		if err := writeAtomicOutputDir(o.OutDir, map[string][]byte{"checkpoint.json": canonical, "checkpoint.sig": signatureBytes}); err != nil {
			return CommandResult{}, err
		}
		action := "allocated the exact next candidate turn"
		if command == CommandCheckpointAcceptCandidateV4 {
			action = "verified and accepted the exact allocated candidate"
		}
		return CommandResult{CeremonyID: d.CeremonyID, Phase: phase, Sequence: int(sequence), Summary: action + "; the signed checkpoint is not current until the delivery service conditionally publishes it", Outputs: map[string]string{"checkpoint": filepath.Join(o.OutDir, "checkpoint.json"), "checkpoint_signature": filepath.Join(o.OutDir, "checkpoint.sig")}}, nil
	}
	if command == CommandCheckpointInspectEnrollmentsV4 {
		_, _, refs, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		checkpoint, commitments, metadata, err := m.InspectCheckpointGuidanceV4(trust, o.ArtifactRoot, refs)
		if err != nil {
			return CommandResult{}, err
		}
		if metadata.CeremonyID != d.CeremonyID || metadata.Checkpoint != refs {
			return CommandResult{}, errors.New("authenticated enrollment metadata changed ceremony or head")
		}
		return CommandResult{CeremonyID: d.CeremonyID, Summary: "Verified checkpoint ancestry and its exact committed enrollment signatures and identities. Disclosure contents and required roster completeness were not checked.", CheckpointInspectionV4: &CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: checkpoint, CheckpointRefs: refs, Commitments: commitments}, EnrollmentMetadataV4: &EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", Metadata: metadata, EnrollmentSignaturesVerified: true}}, nil
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
		c, commitments, err := m.InspectStoredCheckpointV4(trust, o.ArtifactRoot, refs)
		if err != nil {
			return CommandResult{}, err
		}
		if c.CeremonyID != d.CeremonyID {
			return CommandResult{}, errors.New("authenticated ceremony changed during checkpoint inspection")
		}
		return CommandResult{CeremonyID: c.CeremonyID,
			Summary:                "Authenticated checkpoint ancestry and legal metadata transitions. Referenced artifacts, contribution mathematics and global freshness were not verified.",
			CheckpointInspectionV4: &CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", Checkpoint: c, CheckpointRefs: refs, Commitments: commitments}}, nil
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

func loadCheckpointCircuitV4(root string, d m.CeremonyDefinition) (*m.CompiledCircuit, error) {
	path := filepath.Join(root, filepath.FromSlash(d.Circuit.R1CS.Name))
	ref, err := checkpointArtifactRef(root, path)
	if err != nil {
		return nil, err
	}
	if ref != d.Circuit.R1CS {
		return nil, errors.New("stored circuit differs from the signed definition")
	}
	return m.ReadR1CSFile(path, d.Circuit)
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

func validateCheckpointAtomicOutputV4(o CheckpointOptionsV4) error {
	for _, subtree := range []string{"final/candidate", "final/release"} {
		if err := validatePathOutsideTree(o.ArtifactRoot, subtree, o.OutDir); err != nil {
			return err
		}
	}
	if o.CandidateDir != "" {
		if err := validatePathOutsideTree(o.CandidateDir, "", o.OutDir); err != nil {
			return errors.New("checkpoint output must stay outside the fixed candidate directory")
		}
	}
	return nil
}
