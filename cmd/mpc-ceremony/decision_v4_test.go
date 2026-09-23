package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestDecisionV4OutputOutsideClosedPackage(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"final/release/nested", "final/release-old", "decision"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "final/release"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		bad  bool
	}{
		{"final/release/decision.json", true}, {"final/release/nested/signature.json", true},
		{"alias/signature.json", true}, {"final/release-old/decision.json", false}, {"decision/record.json", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			err := validateDecisionOutputV4(root, filepath.Join(root, tc.path))
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v, want rejection %v", err, tc.bad)
			}
		})
	}
	if err := validateDecisionOutputV4("", filepath.Join(root, "decision.json")); err == nil {
		t.Fatal("missing evidence root accepted")
	}
}

func TestDecisionV4AuthenticatedDispatchRejectsLegacyBeforeKey(t *testing.T) {
	root := t.TempDir()
	d, legacy, key := decisionSignFixture(t)
	d.Schema = mpcceremony.DefinitionSchemaV5
	d.ReleaseVerification = "coordinator-full-replay-v1"
	var err error
	d, err = mpcceremony.FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	db, sig, err := mpcceremony.SignRecord(d, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, signature, publicKey := filepath.Join(root, "ceremony.json"), filepath.Join(root, "ceremony.sig"), filepath.Join(root, "coordinator.hex")
	writeDecisionTestFile(t, ceremony, db, 0o600)
	writeDecisionTestFile(t, signature, sig, 0o600)
	writeDecisionTestFile(t, publicKey, []byte(d.Coordinator.Ed25519PublicKeyHex), 0o600)
	decision := filepath.Join(root, "decision.json")
	writeDecisionTestFile(t, decision, legacy, 0o600)
	out := filepath.Join(root, "out.json")
	sign := DecisionSignOptions{CeremonyPath: ceremony, CeremonySignaturePath: signature, CoordinatorPublicKeyFile: publicKey,
		DecisionPath: decision, SigningKey: filepath.Join(root, "MISSING-PRIVATE-KEY"), OutPath: out,
		Role: "coordinator", SignerID: d.Coordinator.ID}
	if _, err := executeDecisionSign(sign); err == nil || !strings.Contains(err.Error(), "--evidence-root") {
		t.Fatalf("missing root: %v", err)
	}
	sign.EvidenceRoot = root
	if _, err := executeDecisionSign(sign); err == nil || strings.Contains(err.Error(), "MISSING-PRIVATE-KEY") {
		t.Fatalf("must reject legacy evidence before loading key: %v", err)
	}
	prepare := DecisionPrepareOptions{CeremonyPath: ceremony, CeremonySignaturePath: signature, CoordinatorPublicKeyFile: publicKey,
		DraftPath: decision, OutPath: out}
	if _, err := executeDecisionPrepare(prepare); err == nil || !strings.Contains(err.Error(), "--evidence-root") {
		t.Fatalf("prepare missing root: %v", err)
	}
	prepare.EvidenceRoot = root
	if _, err := executeDecisionPrepare(prepare); err == nil {
		t.Fatal("legacy draft accepted as v4")
	}
	verify := DecisionVerifyOptions{CeremonyPath: ceremony, CeremonySignaturePath: signature, CoordinatorPublicKeyFile: publicKey,
		DecisionPath: decision, EvidenceRoot: root}
	if _, err := executeDecisionVerify(verify); err == nil {
		t.Fatal("legacy decision verified as v4")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed commands produced output: %v", err)
	}
	// A valid signature is required to select any new behavior.
	writeDecisionTestFile(t, signature, []byte("{}"), 0o600)
	if _, err := executeDecisionSign(sign); err == nil || strings.Contains(err.Error(), "unverified decision evidence") {
		t.Fatalf("dispatch preceded authentication: %v", err)
	}
}

func TestDecisionPrepareEvidenceRootIsVersionSpecific(t *testing.T) {
	args := []string{"--ceremony", "ceremony.json", "--ceremony-signature", "ceremony.sig", "--coordinator-public-key-file", "key.hex", "--draft", "draft.json", "--out", "out.json"}
	if _, err := parseDecisionPrepare(args); err != nil {
		t.Fatal(err)
	}
	if o, err := parseDecisionPrepare(append(args, "--evidence-root", "evidence")); err != nil || o.EvidenceRoot != "evidence" {
		t.Fatalf("parse: %+v %v", o, err)
	}
	if _, err := parseDecisionPrepare(append(args, "--evidence-root", "https://example.invalid/evidence")); err == nil {
		t.Fatal("invalid evidence path accepted")
	}
	root := t.TempDir()
	d, data, key := decisionSignFixture(t)
	db, sig, err := mpcceremony.SignRecord(d, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, bytes := range map[string][]byte{"ceremony.json": db, "ceremony.sig": sig, "key.hex": []byte(d.Coordinator.Ed25519PublicKeyHex), "draft.json": data} {
		writeDecisionTestFile(t, filepath.Join(root, name), bytes, 0o600)
	}
	_, err = executeDecisionPrepare(DecisionPrepareOptions{CeremonyPath: filepath.Join(root, "ceremony.json"), CeremonySignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyFile: filepath.Join(root, "key.hex"), DraftPath: filepath.Join(root, "draft.json"), OutPath: filepath.Join(root, "out.json"), EvidenceRoot: root})
	if err == nil || !strings.Contains(err.Error(), "only supported for definition v4") {
		t.Fatalf("legacy flag silently ignored: %v", err)
	}
}

func TestDecisionV4ResultAndReloadBinding(t *testing.T) {
	d := mpcceremony.ProductionDecisionV3{CeremonyID: "expected"}
	if err := checkDecisionCeremonyV4(d, "changed"); err == nil {
		t.Fatal("changed ceremony accepted")
	}
	if err := checkDecisionCeremonyV4(d, "expected"); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(decisionCommandResultV4(d, "verified", nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, obsolete := range []string{"source_signed_tag", "source_tag_signer", "source_tag_object", "release_manifest_sha256"} {
		if strings.Contains(string(b), obsolete) {
			t.Fatalf("obsolete field emitted: %s", b)
		}
	}
}
