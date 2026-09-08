package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestGuidedMirrorReceiptSigning(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinator := decisionSignFixture(t)
	trust := writeInspectionTrustFixture(t, root, definition, coordinator)
	enrollment, _, _, key := commandSignedExternalEnrollment(t, definition, mpcceremony.EnrollmentMirrorOperator, "mirror-owner", 0x92)
	record := mpcceremony.ImmutableMirrorReceipt{Schema: mpcceremony.ImmutableMirrorReceiptSchema, CeremonyID: definition.CeremonyID, Phase: mpcceremony.Phase1, Index: 1, AcceptedHeadID: "sha256:" + strings.Repeat("5a", 32), Files: []mpcceremony.ArtifactRef{commandArtifact("phase1/chain-0001.json", "test public chain")}, Mirror: enrollment.Identity, StorageLocationSHA256: "sha256:" + strings.Repeat("6b", 32), StoredAt: "2026-07-24T12:00:00Z"}
	raw, err := mpcceremony.MarshalCanonical(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "record.json")
	writeDecisionTestFile(t, path, raw, 0600)
	keyPath := filepath.Join(root, "mirror.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(key.Seed())), 0600)
	o, err := parseOpsSign(append(trust, "--record-type", "mirror-receipt", "--record", path, "--signing-key", keyPath, "--reviewed", "--out", filepath.Join(root, "record.sig")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeOpsSign(o); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(o.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := mpcceremony.ImportOperationalSignature(raw, enrollment.Identity.KeyID, key.Public().(ed25519.PublicKey), ed25519.Sign(key, raw))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := mpcceremony.MarshalCanonical(sig)
	if !bytes.Equal(actual, expected) {
		t.Fatal("mirror signature failed independent comparison")
	}
	// Signing authenticates the claim only; full receipt verification still
	// requires the retained transcript and signed enrollment.
	other := record
	other.CeremonyID = "sha256:" + strings.Repeat("77", 32)
	changed, _ := mpcceremony.MarshalCanonical(other)
	writeDecisionTestFile(t, path, changed, 0600)
	o.OutPath = filepath.Join(root, "other.sig")
	if _, err := executeOpsSign(o); err == nil {
		t.Fatal("signed another ceremony's receipt")
	}
}

func TestGuidedEnrollmentSigning(t *testing.T) {
	definition, _, coordinator := decisionSignFixture(t)
	for _, role := range []string{"coordinator", "release-signer", "auditor", "participant", "public-witness", "mirror-operator"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			trust := writeInspectionTrustFixture(t, root, definition, coordinator)
			id, key := definition.Coordinator, coordinator
			switch role {
			case "release-signer":
				id = definition.ReleaseSigner
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
			case "auditor":
				id = definition.Auditors[0]
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
			case "participant":
				id = definition.Roster[0].Identity
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
			case "public-witness", "mirror-operator":
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x60}, 32))
				var err error
				id, err = mpcceremony.NewIdentity("external-owner", "External owner", "external-key", key.Public().(ed25519.PublicKey))
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(id)
			writeDecisionTestFile(t, filepath.Join(root, "identity.json"), raw, 0600)
			writeDecisionTestFile(t, filepath.Join(root, "disclosure.txt"), []byte("Test operator shares this machine; not independent.\n"), 0600)
			writeDecisionTestFile(t, filepath.Join(root, "key.hex"), []byte(hex.EncodeToString(key.Seed())+"\n"), 0600)
			prepare, err := parseOpsPrepareEnrollment(append(append([]string{}, trust...), "--identity", filepath.Join(root, "identity.json"), "--role", role, "--role-index", "2", "--disclosure", filepath.Join(root, "disclosure.txt"), "--enrolled-at", "2026-07-24T12:00:00Z", "--out-dir", filepath.Join(root, "enrollment")))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = executeOpsPrepareEnrollment(prepare); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, trust...), "--record-type", "enrollment", "--record", filepath.Join(root, "enrollment/canonical.json"), "--signing-key", filepath.Join(root, "key.hex"), "--out", filepath.Join(root, "enrollment/enrollment.sig"))
			sign, err := parseOpsSign(args)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = executeOpsSign(sign); err == nil {
				t.Fatal("signed without review")
			}
			sign.Reviewed = true
			stale := sign
			stale.ReviewedSHA256 = "incorrect-reviewed-digest"
			if _, err = executeOpsSign(stale); err == nil {
				t.Fatal("signed bytes different from the review")
			}
			badTrust := sign
			badTrust.CeremonySignaturePath = filepath.Join(root, "bad-ceremony.sig")
			writeDecisionTestFile(t, badTrust.CeremonySignaturePath, []byte("{}"), 0600)
			if _, err = executeOpsSign(badTrust); err == nil {
				t.Fatal("signed without authentic ceremony signature")
			}
			disclosurePath := filepath.Join(root, "enrollment/enrollments", id.ID, "disclosure.txt")
			disclosureRaw, err := os.ReadFile(disclosurePath)
			if err != nil {
				t.Fatal(err)
			}
			writeDecisionTestFile(t, disclosurePath, []byte("changed disclosure"), 0600)
			if _, err = executeOpsSign(sign); err == nil {
				t.Fatal("signed changed disclosure")
			}
			writeDecisionTestFile(t, disclosurePath, disclosureRaw, 0600)
			wrong := sign
			wrong.SigningKey = filepath.Join(root, "wrong.hex")
			writeDecisionTestFile(t, wrong.SigningKey, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))), 0600)
			if _, err = executeOpsSign(wrong); err == nil {
				t.Fatal("accepted wrong owner")
			}
			unsupported := sign
			unsupported.RecordType = "decision"
			if _, err = executeOpsSign(unsupported); err == nil {
				t.Fatal("accepted unrelated record type")
			}
			if _, err = executeOpsSign(sign); err != nil {
				t.Fatal(err)
			}
			canonical, err := os.ReadFile(sign.RecordPath)
			if err != nil {
				t.Fatal(err)
			}
			sigRaw, err := os.ReadFile(sign.OutPath)
			if err != nil {
				t.Fatal(err)
			}
			var sig mpcceremony.DetachedSignature
			if err = json.Unmarshal(sigRaw, &sig); err != nil {
				t.Fatal(err)
			}
			// Compare against the canonical detached signature produced by the existing verifier/importer.
			expected, err := mpcceremony.ImportOperationalSignature(canonical, id.KeyID, key.Public().(ed25519.PublicKey), ed25519.Sign(key, canonical))
			if err != nil {
				t.Fatal(err)
			}
			expectedRaw, _ := mpcceremony.MarshalCanonical(expected)
			if !bytes.Equal(sigRaw, expectedRaw) {
				t.Fatal("unexpected detached signature")
			}
			if _, err = executeOpsSign(sign); err == nil {
				t.Fatal("overwrote signature")
			}
			tampered := sign
			tampered.OutPath = filepath.Join(root, "tampered.sig")
			writeDecisionTestFile(t, sign.RecordPath, append(canonical, '\n'), 0600)
			if _, err = executeOpsSign(tampered); err == nil {
				t.Fatal("accepted noncanonical bytes")
			}
		})
	}
}
