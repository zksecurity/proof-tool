package mpcceremony

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareOperationalEvidenceVerifiesExistingRecords(t *testing.T) {
	f := newOperationalBundleFixture(t)
	p, err := PrepareOperationalEvidence(f.definition, f.root, f.bundle.AssembledAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Missing) > 0 {
		t.Fatal(p.Missing)
	}
	raw, err := MarshalCanonical(p.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	o := VerifyOperationalEvidenceOptions{Definition: f.definition, CoordinatorPublicKey: f.coordinatorKey.Public().(ed25519.PublicKey), EvidenceRoot: f.root, BundleBytes: raw, Phase1Close: f.phase1Close, Phase2Close: f.phase2Close}
	if err := VerifyOperationalEvidenceDraft(o); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOperationalEvidenceBundle(o); err == nil {
		t.Fatal("unsigned preparation passed signed release gate")
	}
	signature, err := SignExact(raw, f.definition.Coordinator.KeyID, f.coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}
	o.BundleSignatureBytes, err = MarshalCanonical(signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOperationalEvidenceBundle(o); err != nil {
		t.Fatal("signed prepared bundle rejected", err)
	}
	// Discovery does not substitute for validation of referenced public bytes.
	path := filepath.Join(f.root, f.bundle.Phase1.RawBeaconResponses[0].Name)
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationalEvidenceDraft(o); err == nil {
		t.Fatal("tampered raw beacon accepted")
	}
}

func TestPrepareOperationalEvidenceReportsMissingAndRejectsSymlinks(t *testing.T) {
	f := newOperationalBundleFixture(t)
	missing := f.bundle.Phase1.AcceptedHeads[0].ReturnReceipt.Signature.Name
	if err := os.Remove(filepath.Join(f.root, missing)); err != nil {
		t.Fatal(err)
	}
	p, err := PrepareOperationalEvidence(f.definition, f.root, f.bundle.AssembledAt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Missing, "\n"), "phase1 turn 1") || !strings.Contains(strings.Join(p.Missing, "\n"), "return receipt") {
		t.Fatal(p.Missing)
	}
	if err := os.Symlink("missing", filepath.Join(f.root, "unexpected.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareOperationalEvidence(f.definition, f.root, f.bundle.AssembledAt); err == nil {
		t.Fatal("symlink accepted")
	}
}
