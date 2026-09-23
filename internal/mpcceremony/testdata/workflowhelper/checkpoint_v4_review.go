package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	m "proof-tool/internal/mpcceremony"
)

func runCheckpointV4Review(root string, trust m.TrustPaths, d m.CeremonyDefinition, head m.CheckpointV4, headRefs, bundle m.SignedArtifactRefs, expectedAudits []m.SignedArtifactRefs, coordinator ed25519.PrivateKey) error {
	at := mustUTC("2023-08-23T15:11:39Z")
	review, err := m.VerifyReleaseReviewV4(trust, root, headRefs, bundle, at)
	if err != nil {
		return fmt.Errorf("read-only final review: %w", err)
	}
	again, err := m.VerifyReleaseReviewV4(trust, root, headRefs, bundle, at)
	if err != nil {
		return err
	}
	rb, err := m.MarshalCanonical(review)
	if err != nil {
		return err
	}
	ab, err := m.MarshalCanonical(again)
	if err != nil {
		return err
	}
	if !bytes.Equal(rb, ab) {
		return fmt.Errorf("final review is not deterministic")
	}
	if review.ReviewCheckpoint != headRefs {
		return fmt.Errorf("final review is bound to a different checkpoint")
	}
	if len(review.Audits) != len(expectedAudits) || !slices.Equal(review.Audits, expectedAudits) {
		return fmt.Errorf("final review audit inventory differs from committed reports: got %d, want %d", len(review.Audits), len(expectedAudits))
	}
	if len(review.Audits) < int(d.AssurancePolicy.PassingCeremonyAudits) {
		return fmt.Errorf("final review has %d audits, below required minimum %d", len(review.Audits), d.AssurancePolicy.PassingCeremonyAudits)
	}
	// Copy only the declared review dependencies, not the ceremony workspace.
	// The real tiny fixture must still verify without its contribution payloads.
	snapshot, err := os.MkdirTemp(filepath.Dir(root), "review-dependencies-")
	if err != nil {
		return err
	}
	// Command integration tests may retain this public-only verified branch in
	// their own temporary workspace. Normal helper runs still remove it.
	if os.Getenv("MPC_WORKFLOW_RETAIN_REVIEW") != "1" {
		defer os.RemoveAll(snapshot)
	}
	for _, ref := range review.RequiredArtifacts {
		raw, err := os.ReadFile(filepath.Join(root, ref.Name))
		if err != nil {
			return err
		}
		if m.NewDigest(raw) != ref.Digest {
			return fmt.Errorf("review dependency has wrong bytes: %s", ref.Name)
		}
		destination := filepath.Join(snapshot, ref.Name)
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(destination, raw, 0600); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(filepath.Join(snapshot, d.Phase1Genesis.Name)); !os.IsNotExist(err) {
		return fmt.Errorf("review dependency snapshot unexpectedly contains genesis payload: %v", err)
	}
	snapshotTrust := trust
	snapshotTrust.DefinitionPath = filepath.Join(snapshot, head.Definition.Record.Name)
	snapshotTrust.DefinitionSignaturePath = filepath.Join(snapshot, head.Definition.Signature.Name)
	snapshotReview, err := m.VerifyReleaseReviewV4(snapshotTrust, snapshot, headRefs, bundle, at)
	if err != nil {
		return fmt.Errorf("exact dependency snapshot review: %w", err)
	}
	snapshotBytes, err := m.MarshalCanonical(snapshotReview)
	if err != nil {
		return err
	}
	if !bytes.Equal(rb, snapshotBytes) {
		return fmt.Errorf("dependency-only snapshot changed review")
	}
	var phase1 m.Chain
	chainBytes, err := os.ReadFile(filepath.Join(snapshot, head.Progress.Phase1.Chain.Record.Name))
	if err != nil {
		return err
	}
	if err := m.UnmarshalCanonical(chainBytes, &phase1); err != nil {
		return err
	}
	for _, record := range phase1.Records {
		if _, err := os.Lstat(filepath.Join(snapshot, record.OutputPayload.Name)); !os.IsNotExist(err) {
			return fmt.Errorf("snapshot unexpectedly contains historical contribution: %v", err)
		}
	}
	var bundleRecord m.OperationalEvidenceBundle
	bundleBytes, err := os.ReadFile(filepath.Join(snapshot, bundle.Record.Name))
	if err != nil {
		return err
	}
	if err := m.UnmarshalCanonical(bundleBytes, &bundleRecord); err != nil {
		return err
	}
	for _, ref := range []m.ArtifactRef{headRefs.Signature, head.Definition.Record, head.Definition.Signature, bundle.Signature, phase1.Records[0].Attestation, phase1.Records[0].Erasure, bundleRecord.Phase1.AcceptedHeads[0].AcceptedChainPrefix.Record, bundleRecord.Phase1.RawBeaconResponses[0]} {
		file := filepath.Join(snapshot, ref.Name)
		original, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if err := os.Remove(file); err != nil {
			return err
		}
		_, rejected := m.VerifyReleaseReviewV4(snapshotTrust, snapshot, headRefs, bundle, at)
		if err := os.WriteFile(file, original, 0600); err != nil {
			return err
		}
		if rejected == nil {
			return fmt.Errorf("missing dependency accepted in snapshot: %s", ref.Name)
		}
	}
	if err := runCheckpointV4Release(snapshot, snapshotTrust, d, review, filepath.Join(filepath.Dir(root), "identity-keys/release-signer.ed25519.private.hex"), filepath.Join(filepath.Dir(root), "release-v4")); err != nil {
		return err
	}
	if err := runFinalReleaseCheckpointV4(snapshot, filepath.Join(filepath.Dir(root), "release-v4"), snapshotTrust, d, head, headRefs, coordinator); err != nil {
		return err
	}
	renamedTrust := trust
	renamedTrust.DefinitionPath = filepath.Join(root, "renamed-trusted-definition.json")
	definitionBytes, err := os.ReadFile(trust.DefinitionPath)
	if err != nil {
		return err
	}
	if err = os.WriteFile(renamedTrust.DefinitionPath, definitionBytes, 0600); err != nil {
		return err
	}
	renamedReview, err := m.VerifyReleaseReviewV4(renamedTrust, root, headRefs, bundle, at)
	if err != nil {
		return fmt.Errorf("renamed trusted copy: %w", err)
	}
	renamedBytes, err := m.MarshalCanonical(renamedReview)
	if err != nil {
		return err
	}
	if !bytes.Equal(rb, renamedBytes) {
		return fmt.Errorf("trusted local filename changed logical review")
	}
	for _, badTime := range []time.Time{{}, mustUTC("2023-08-23T15:11:38Z"), at.In(time.FixedZone("other", 3600))} {
		bad, err := m.VerifyReleaseReviewV4(trust, root, headRefs, bundle, badTime)
		if err == nil || bad.CeremonyID != "" {
			return fmt.Errorf("invalid review time accepted: %v", err)
		}
	}
	wrongName := bundle
	wrongName.Record.Name = "another/bundle.json"
	if result, err := m.VerifyReleaseReviewV4(trust, root, headRefs, wrongName, at); err == nil || result.CeremonyID != "" {
		return fmt.Errorf("wrong bundle name accepted")
	}
	extra := filepath.Join(root, "final/candidate/unreviewed.txt")
	if err = os.WriteFile(extra, []byte("unreviewed"), 0600); err != nil {
		return err
	}
	bad, extraErr := m.VerifyReleaseReviewV4(trust, root, headRefs, bundle, at)
	if err = os.Remove(extra); err != nil {
		return err
	}
	if extraErr == nil || bad.CeremonyID != "" {
		return fmt.Errorf("extra final candidate file accepted")
	}
	for _, ref := range []m.ArtifactRef{bundle.Signature, review.CandidateArtifacts[0]} {
		p := filepath.Join(root, ref.Name)
		original, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		changed := bytes.Clone(original)
		changed[len(changed)-1] ^= 1
		if err = os.WriteFile(p, changed, 0600); err != nil {
			return err
		}
		bad, rejected := m.VerifyReleaseReviewV4(trust, root, headRefs, bundle, at)
		if err = os.WriteFile(p, original, 0600); err != nil {
			return err
		}
		if rejected == nil || bad.CeremonyID != "" {
			return fmt.Errorf("changed review input accepted: %s", ref.Name)
		}
	}
	write := func(name string, raw []byte) (m.ArtifactRef, error) {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return m.ArtifactRef{}, err
		}
		if err := os.WriteFile(p, raw, 0600); err != nil {
			return m.ArtifactRef{}, err
		}
		return m.ArtifactRef{Name: name, Digest: m.NewDigest(raw)}, nil
	}
	pair := func(name string, record any) (m.SignedArtifactRefs, error) {
		raw, sig, err := m.SignRecord(record, d.Coordinator.KeyID, coordinator)
		if err != nil {
			return m.SignedArtifactRefs{}, err
		}
		r, err := write(name+".json", raw)
		if err != nil {
			return m.SignedArtifactRefs{}, err
		}
		s, err := write(name+".sig", sig)
		return m.SignedArtifactRefs{Record: r, Signature: s}, err
	}
	statement, err := write("review-tests/statement.txt", []byte("Additional public fixture incident after bundle assembly.\n"))
	if err != nil {
		return err
	}
	// The factual statement predates assembly but is attached afterwards, so
	// chronology alone cannot reject the old bundle: exact bytes must differ.
	incident := m.GovernanceRecord{Schema: m.GovernanceRecordSchema, Kind: m.GovernanceIncident, CeremonyID: d.CeremonyID, Phase: m.Phase2, Index: head.Progress.Phase2.AcceptedCount, HeadID: head.Progress.Phase2.HeadRecordID, Evidence: []m.ArtifactRef{statement}, ReasonCode: "review-test", StatementSHA256: statement.Digest.SHA256, SignerID: d.Coordinator.ID, SignerKeyID: d.Coordinator.KeyID, RecordedAt: "2023-08-23T15:11:37.8Z"}
	ir, err := pair("review-tests/incident", incident)
	if err != nil {
		return err
	}
	updated := head
	updated.Sequence++
	updated.PreviousCheckpoint = &headRefs
	updated.Transition = m.CheckpointTransitionV4{Kind: m.CheckpointIncidentRecorded, Record: &ir, Evidence: []m.ArtifactRef{statement}}
	updated.AcceptedArtifacts = append(append([]m.ArtifactRef{}, head.AcceptedArtifacts...), ir.Record, ir.Signature, statement)
	sort.Slice(updated.AcceptedArtifacts, func(i, j int) bool { return updated.AcceptedArtifacts[i].Name < updated.AcceptedArtifacts[j].Name })
	newHead, err := pair("review-tests/checkpoint", updated)
	if err != nil {
		return err
	}
	if result, err := m.VerifyReleaseReviewV4(trust, root, newHead, bundle, at); err == nil || !strings.Contains(err.Error(), "cannot add an incident after freezing release review") || result.CeremonyID != "" {
		return fmt.Errorf("post-review incident accepted: %v", err)
	}
	fmt.Println("V4 final review passed: no contribution replay input, deterministic exact binding, changed files and post-review evidence rejected")
	return nil
}
