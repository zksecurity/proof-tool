package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	m "proof-tool/internal/mpcceremony"
)

func runCheckpointV4Review(root string, trust m.TrustPaths, d m.CeremonyDefinition, head m.CheckpointV4, headRefs, bundle m.SignedArtifactRefs, coordinator ed25519.PrivateKey) error {
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
	if !bytes.Equal(rb, ab) || review.ReviewCheckpoint != headRefs || len(review.Audits) != int(d.AssurancePolicy.PassingCeremonyAudits) {
		return fmt.Errorf("final review is not deterministic or exactly bound")
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
	if result, err := m.VerifyReleaseReviewV4(trust, root, newHead, bundle, at); err == nil || !strings.Contains(err.Error(), "signed bundle does not match the exact review checkpoint") || result.CeremonyID != "" {
		return fmt.Errorf("stale bundle review: %v", err)
	}
	fmt.Println("V4 final review passed: no contribution replay input, deterministic exact binding, stale bundle and changed files rejected")
	return nil
}
