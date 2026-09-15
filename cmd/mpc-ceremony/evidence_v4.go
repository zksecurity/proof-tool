package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"proof-tool/internal/keybundle"
	m "proof-tool/internal/mpcceremony"
)

// These commands deliberately take an exact checkpoint pair. Legacy discovery
// and record-signing commands cannot supply that boundary.
type EvidenceOptionsV4 struct {
	InspectDefinitionOptions
	ArtifactRoot, CheckpointPath, CheckpointSignaturePath string
	BundlePath, BundleSignaturePath, OutPath              string
	AssembledAt, ReleasedAt, CoordinatorSigningKey        string
	Reviewed                                              bool
	ReviewedSHA256                                        string
}

const maxEvidenceReportV4Bytes = 64 << 20

type EvidenceInspectionV4 struct {
	Schema            string                `json:"schema"`
	SourceCheckpoint  m.SignedArtifactRefs  `json:"source_checkpoint"`
	OperationalBundle *m.SignedArtifactRefs `json:"operational_bundle,omitempty"`
	AssembledAt       string                `json:"assembled_at,omitempty"`
	ReleasedAt        string                `json:"released_at,omitempty"`
	OutputDigest      m.Digest              `json:"output_digest"`
}

// This projection is a local diagnostic, never an input authority. Consumers
// must authenticate the signed bootstrap and rerun package verification.
type ReleaseInventoryReportV4 struct {
	Schema                      string                   `json:"schema"`
	Release                     m.FinalReleaseEvidenceV4 `json:"release"`
	ManifestSHA256              string                   `json:"manifest_sha256"`
	PackagePrefix               string                   `json:"package_prefix"`
	Artifacts                   []m.ArtifactRef          `json:"artifacts"`
	Depth                       string                   `json:"depth"`
	ArtifactsVerified           bool                     `json:"artifacts_verified"`
	CoordinatorReplayClaimBound bool                     `json:"coordinator_replay_claim_bound"`
	MathematicsReplayed         bool                     `json:"mathematics_replayed"`
	GlobalFreshnessVerified     bool                     `json:"global_freshness_verified"`
	ProductionAuthorized        bool                     `json:"production_authorized"`
	Published                   bool                     `json:"published"`
}

func (r ReleaseInventoryReportV4) Validate() error {
	if r.Schema != "proof-tool-mpc-release-inventory-report-v4" || r.Depth != "final-package" || r.PackagePrefix != m.FinalReleasePackagePrefixV4 {
		return errors.New("unsupported final package inventory report")
	}
	if err := r.Release.Validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(r.ManifestSHA256, "sha256:") || validateBundleReviewV4(EvidenceOptionsV4{Reviewed: true, ReviewedSHA256: strings.TrimPrefix(r.ManifestSHA256, "sha256:")}) != nil {
		return errors.New("manifest digest must be tagged lowercase SHA-256")
	}
	if !r.ArtifactsVerified || !r.CoordinatorReplayClaimBound || r.MathematicsReplayed || r.GlobalFreshnessVerified || r.ProductionAuthorized || r.Published {
		return errors.New("inventory report has unsupported verification claims")
	}
	return m.ValidateFinalReleaseInventoryArtifactsV4(r.Artifacts)
}

func parseEvidenceV4(command Command, args []string) (EvidenceOptionsV4, error) {
	var o EvidenceOptionsV4
	f := commandFlagSet(string(command))
	addCeremonyTrustFlags(f, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	f.StringVar(&o.ArtifactRoot, "artifact-root", "", "local authenticated ceremony artifact root")
	f.StringVar(&o.CheckpointPath, "checkpoint", "", "exact signed checkpoint under artifact-root")
	f.StringVar(&o.CheckpointSignaturePath, "checkpoint-signature", "", "exact checkpoint signature under artifact-root")
	outFlag := "--out"
	switch command {
	case CommandOpsPrepareBundleV4:
		f.StringVar(&o.AssembledAt, "assembled-at", "", "nonzero UTC assembly time")
	case CommandOpsSignBundleV4:
		f.StringVar(&o.BundlePath, "operational-bundle", "", "canonical artifact-root/operational/evidence-bundle.json")
		f.StringVar(&o.CoordinatorSigningKey, "coordinator-signing-key", "", "existing coordinator private key")
		f.BoolVar(&o.Reviewed, "reviewed", false, "owner reviewed these exact bundle bytes")
		f.StringVar(&o.ReviewedSHA256, "reviewed-sha256", "", "lowercase SHA-256 of exact reviewed bytes")
	case CommandReleaseReviewV4:
		f.StringVar(&o.BundlePath, "operational-bundle", "", "canonical operational evidence bundle")
		f.StringVar(&o.BundleSignaturePath, "operational-bundle-signature", "", "canonical operational bundle signature")
		f.StringVar(&o.ReleasedAt, "released-at", "", "nonzero UTC proposed package time")
	case CommandCheckpointVerifyReleaseV4:
		outFlag = "--inventory-out"
	default:
		return o, errors.New("unknown V4 evidence command")
	}
	f.StringVar(&o.OutPath, outFlag[2:], "", "fresh output file; real parent directory must exist")
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	if err := requireValues(pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--artifact-root", o.ArtifactRoot), pathValue("--checkpoint", o.CheckpointPath), pathValue("--checkpoint-signature", o.CheckpointSignaturePath), pathValue(outFlag, o.OutPath)); err != nil {
		return o, err
	}
	switch command {
	case CommandOpsPrepareBundleV4:
		_, err := parseUTCTime("--assembled-at", o.AssembledAt)
		return o, err
	case CommandOpsSignBundleV4:
		if err := validateBundleReviewV4(o); err != nil {
			return o, err
		}
		return o, requireValues(pathValue("--operational-bundle", o.BundlePath), pathValue("--coordinator-signing-key", o.CoordinatorSigningKey))
	case CommandReleaseReviewV4:
		if _, err := parseUTCTime("--released-at", o.ReleasedAt); err != nil {
			return o, err
		}
		return o, requireValues(pathValue("--operational-bundle", o.BundlePath), pathValue("--operational-bundle-signature", o.BundleSignaturePath))
	}
	return o, nil
}

func validateBundleReviewV4(o EvidenceOptionsV4) error {
	if !o.Reviewed || len(o.ReviewedSHA256) != 64 {
		return errors.New("bundle signing requires --reviewed and --reviewed-sha256 of the exact canonical bytes")
	}
	for _, c := range o.ReviewedSHA256 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("reviewed SHA-256 must be 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func executeEvidenceV4(command Command, o EvidenceOptionsV4) (CommandResult, error) {
	trust := trustPaths(o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile)
	trusted, err := m.LoadSignedDefinition(trust)
	if err != nil {
		return CommandResult{}, err
	}
	d := trusted.Definition
	if d.Schema != m.DefinitionSchemaV4 {
		return CommandResult{}, errors.New("V4 evidence commands require definition v4")
	}
	if err := m.VerifyRunningSoftwareForMode(d.Software, d.Mode); err != nil {
		return CommandResult{}, err
	}
	if err := validateEvidenceOutputV4(command, o); err != nil {
		return CommandResult{}, err
	}
	_, _, head, err := checkpointSignedBytes(o.ArtifactRoot, o.CheckpointPath, o.CheckpointSignaturePath)
	if err != nil {
		return CommandResult{}, err
	}
	result := CommandResult{CeremonyID: d.CeremonyID, Outputs: map[string]string{"checkpoint": o.CheckpointPath, "checkpoint_signature": o.CheckpointSignaturePath}}
	result.EvidenceInspectionV4 = &EvidenceInspectionV4{Schema: "proof-tool-mpc-evidence-inspection-v4", SourceCheckpoint: head}
	var data []byte
	limit := maxEvidenceReportV4Bytes
	switch command {
	case CommandOpsPrepareBundleV4, CommandOpsSignBundleV4:
		limit = maxOperationalRecordBytes
		at, timeErr := parseUTCTime("--assembled-at", o.AssembledAt)
		var reviewed []byte
		if command == CommandOpsSignBundleV4 {
			if err := validateBundleReviewV4(o); err != nil {
				return CommandResult{}, err
			}
			if err := requireCanonicalBundlePathV4(o.ArtifactRoot, o.BundlePath, m.OperationalEvidenceBundleFile); err != nil {
				return CommandResult{}, err
			}
			reviewed, _, err = checkpointArtifactBytes(o.ArtifactRoot, o.BundlePath, maxOperationalRecordBytes)
			if err != nil {
				return CommandResult{}, err
			}
			if fmt.Sprintf("%x", sha256.Sum256(reviewed)) != o.ReviewedSHA256 {
				return CommandResult{}, errors.New("bundle changed since owner review")
			}
			var bundle m.OperationalEvidenceBundle
			if err = m.UnmarshalCanonical(reviewed, &bundle); err != nil {
				return CommandResult{}, err
			}
			at, timeErr = parseUTCTime("bundle assembled_at", bundle.AssembledAt)
		}
		if timeErr != nil {
			return CommandResult{}, timeErr
		}
		prepared, err := m.PrepareOperationalBundleV4(trust, o.ArtifactRoot, head, at)
		if err != nil {
			return CommandResult{}, err
		}
		if prepared.SourceCheckpoint != head || prepared.Bundle.CeremonyID != d.CeremonyID {
			return CommandResult{}, errors.New("authenticated ceremony or checkpoint changed during bundle preparation")
		}
		result.EvidenceInspectionV4.AssembledAt = prepared.Bundle.AssembledAt
		data, err = m.MarshalCanonical(prepared.Bundle)
		if err != nil {
			return CommandResult{}, err
		}
		result.Summary = "Prepared an unsigned bundle from this exact checkpoint. Signing must recheck the same checkpoint and reviewed bytes. No contribution replay or release approval occurred."
		result.Outputs["canonical"] = o.OutPath
		if command == CommandOpsSignBundleV4 {
			if !bytes.Equal(data, reviewed) {
				return CommandResult{}, errors.New("reviewed bundle does not match the exact checkpoint; prepare and review the correct bundle")
			}
			private, public, err := keybundle.LoadExistingPrivateKey(o.CoordinatorSigningKey)
			if err != nil {
				return CommandResult{}, err
			}
			if !bytes.Equal(public, trusted.CoordinatorPublicKey) {
				return CommandResult{}, errors.New("bundle signing key is not the authenticated coordinator key")
			}
			sig, err := m.SignExact(data, d.Coordinator.KeyID, private)
			if err != nil {
				return CommandResult{}, err
			}
			data, err = m.MarshalCanonical(sig)
			if err != nil {
				return CommandResult{}, err
			}
			result.Outputs["canonical"] = o.BundlePath
			result.Outputs["signature"] = o.OutPath
			result.Summary = "Signed the reviewed bundle after rederiving it from this exact checkpoint. This does not approve release or establish global freshness."
			limit = 4096
		}
	case CommandReleaseReviewV4:
		at, err := parseUTCTime("--released-at", o.ReleasedAt)
		if err != nil {
			return CommandResult{}, err
		}
		_, _, pair, err := checkpointSignedBytes(o.ArtifactRoot, o.BundlePath, o.BundleSignaturePath)
		if err != nil {
			return CommandResult{}, err
		}
		review, err := m.VerifyReleaseReviewV4(trust, o.ArtifactRoot, head, pair, at)
		if err != nil {
			return CommandResult{}, err
		}
		if review.CeremonyID != d.CeremonyID || review.ReviewCheckpoint != head || review.OperationalBundle != pair {
			return CommandResult{}, errors.New("authenticated ceremony or inputs changed during release review")
		}
		data, err = m.MarshalCanonical(review)
		if err != nil {
			return CommandResult{}, err
		}
		result.Outputs["review"] = o.OutPath
		result.Outputs["artifact_count"] = strconv.Itoa(len(review.RequiredArtifacts))
		result.Outputs["operational_bundle"] = o.BundlePath
		result.Outputs["operational_bundle_signature"] = o.BundleSignaturePath
		result.Outputs["released_at"] = review.ReleasedAt
		result.EvidenceInspectionV4.OperationalBundle = &pair
		result.EvidenceInspectionV4.ReleasedAt = review.ReleasedAt
		result.Summary = "Verified exact review files, signatures, required evidence and coordinator replay binding. This unsigned report is not an authorization or signing input; release signing recomputes it. No contribution replay, freshness check or publication occurred."
	case CommandCheckpointVerifyReleaseV4:
		verified, inventory, err := m.VerifyFinalReleaseCheckpointV4(trust, o.ArtifactRoot, head)
		if err != nil {
			return CommandResult{}, err
		}
		if verified.Transcript.CeremonyID != d.CeremonyID {
			return CommandResult{}, errors.New("authenticated ceremony changed during final package verification")
		}
		binding, err := m.NewFinalReleaseEvidenceV4(d.CeremonyID, head, verified.Candidate.CandidateID)
		if err != nil {
			return CommandResult{}, err
		}
		report := ReleaseInventoryReportV4{Schema: "proof-tool-mpc-release-inventory-report-v4", Release: binding, ManifestSHA256: verified.ManifestSHA256,
			PackagePrefix: inventory.PackagePrefix(), Artifacts: inventory.Artifacts(), Depth: "final-package", ArtifactsVerified: true, CoordinatorReplayClaimBound: true}
		if err := report.Validate(); err != nil {
			return CommandResult{}, err
		}
		data, err = m.MarshalCanonical(report)
		if err != nil {
			return CommandResult{}, err
		}
		result.ReleaseID, result.CandidateID, result.ReleaseManifestSHA256 = binding.ReleaseID, binding.CandidateID, verified.ManifestSHA256
		result.Outputs["inventory"] = o.OutPath
		result.Outputs["artifact_count"] = strconv.Itoa(len(report.Artifacts))
		result.Outputs["package_prefix"] = report.PackagePrefix
		result.Summary = "Verified checkpoint ancestry, the exact private package, required evidence and coordinator replay binding. The unsigned inventory is a local report, not download authority. No contribution replay, global freshness, production approval or publication occurred."
	default:
		return CommandResult{}, errors.New("unknown V4 evidence command")
	}
	if len(data) == 0 || len(data) > limit {
		return CommandResult{}, errors.New("V4 evidence output exceeds its format size bound")
	}
	if err := writeFreshOperationalFile(o.OutPath, data, 0600); err != nil {
		return CommandResult{}, err
	}
	result.Outputs["output_sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
	result.EvidenceInspectionV4.OutputDigest = m.NewDigest(data)
	return result, nil
}

func requireCanonicalBundlePathV4(root, file, name string) error {
	r, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	p, err := filepath.Abs(file)
	if err != nil || p != filepath.Join(r, filepath.FromSlash(name)) {
		return fmt.Errorf("bundle path must be artifact-root/%s", name)
	}
	return validateCheckpointPathComponents(r, filepath.Dir(p))
}

func validateEvidenceOutputV4(command Command, o EvidenceOptionsV4) error {
	parent, err := os.Lstat(filepath.Dir(o.OutPath))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("evidence output requires an existing real parent directory")
	}
	switch command {
	case CommandOpsPrepareBundleV4:
		if err := requireCanonicalBundlePathV4(o.ArtifactRoot, o.OutPath, m.OperationalEvidenceBundleFile); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(o.ArtifactRoot, m.OperationalEvidenceSignatureFile)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("bundle signature already exists or cannot be inspected; retain the existing pair for review")
		}
	case CommandOpsSignBundleV4:
		if err := requireCanonicalBundlePathV4(o.ArtifactRoot, o.OutPath, m.OperationalEvidenceSignatureFile); err != nil {
			return err
		}
	case CommandReleaseReviewV4, CommandCheckpointVerifyReleaseV4:
		for _, subtree := range []string{"final/candidate", "final/release"} {
			if err := validatePathOutsideTree(o.ArtifactRoot, subtree, o.OutPath); err != nil {
				return err
			}
		}
	default:
		return errors.New("unknown V4 evidence command")
	}
	if _, err := os.Lstat(o.OutPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence output already exists or cannot be inspected; retain it for review")
	}
	return nil
}
