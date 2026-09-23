package main

import (
	"errors"
	"fmt"

	"proof-tool/internal/mpcceremony"
)

func validateReleaseSignShapeV4(o ReleaseSignOptions) error {
	if o.ReviewCheckpointPath == "" || o.ReviewSignaturePath == "" {
		return errors.New("definition v4/v5 release signing requires --review-checkpoint and --review-checkpoint-signature")
	}
	if o.CandidateBundleDir != "" || len(o.AuditReportPaths) != 0 || len(o.AuditSignaturePaths) != 0 || o.Replay != (ReplayOptions{}) {
		return errors.New("V4 review signing must not supply legacy candidate, audit or replay flags; the authenticated review determines those inputs")
	}
	return nil
}

func executeReleaseSignV4(o ReleaseSignOptions, trust mpcceremony.TrustPaths, ceremonyID string) (CommandResult, error) {
	if err := validateReleaseSignShapeV4(o); err != nil {
		return CommandResult{}, err
	}
	at, err := parseUTCTime("--released-at", o.ReleasedAt)
	if err != nil {
		return CommandResult{}, err
	}
	// These are bounded metadata, not large contribution files. The helper
	// confines both paths to the root and refuses symlink traversal.
	_, _, review, err := checkpointSignedBytes(o.OperationalEvidenceRoot, o.ReviewCheckpointPath, o.ReviewSignaturePath)
	if err != nil {
		return CommandResult{}, fmt.Errorf("review checkpoint: %w", err)
	}
	_, _, bundle, err := checkpointSignedBytes(o.OperationalEvidenceRoot, o.OperationalBundlePath, o.OperationalSignaturePath)
	if err != nil {
		return CommandResult{}, fmt.Errorf("operational bundle: %w", err)
	}
	// Retain the dispatch identity across independently authenticated library reads.
	checked, err := mpcceremony.VerifyReleaseReviewV4(trust, o.OperationalEvidenceRoot, review, bundle, at)
	if err != nil {
		return CommandResult{}, err
	}
	if checked.CeremonyID != ceremonyID {
		return CommandResult{}, errors.New("authenticated ceremony changed during release review")
	}
	result, err := mpcceremony.SignReleaseV4(mpcceremony.SignReleaseV4Options{Trust: trust, ArtifactRoot: o.OperationalEvidenceRoot,
		ReviewCheckpoint: review, OperationalBundle: bundle, ReleaseDir: o.ReleaseDir, ReleaseSigningKey: o.ReleaseSigningKey,
		SignatureKeyID: o.SignatureKeyID, ReleasedAt: at})
	if err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: ceremonyID,
		Summary: "Created a local signed package after checking the coordinator replay binding, public proof and required evidence. No signer contribution replay, publication or production approval occurred.",
		Outputs: map[string]string{"release_dir": o.ReleaseDir, "manifest": result.ManifestPath, "manifest_signature": result.ManifestSignature,
			"manifest_public_key": result.ManifestPublicKey, "setup_transcript": result.FinalTranscript, "operational_evidence": result.OperationalEvidence, "checksums": result.ChecksumsPath}}, nil
}
