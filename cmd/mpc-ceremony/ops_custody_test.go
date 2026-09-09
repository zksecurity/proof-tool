package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"proof-tool/internal/mpcceremony"
	"strings"
	"testing"
	"time"
)

func TestCustodySigningAndReceiptRequireExactDeliveredBytes(t *testing.T) {
	root := t.TempDir()
	definition, _, key := decisionSignFixture(t)
	trust := writeInspectionTrustFixture(t, root, definition, key)
	payload := []byte("public ceremony payload")
	ref := mpcceremony.ArtifactRef{Name: "phase1/genesis.bin", Digest: mpcceremony.NewDigest(payload)}
	if err := os.MkdirAll(filepath.Join(root, "phase1"), 0700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, filepath.Join(root, ref.Name), payload, 0600)
	now := time.Now().UTC()
	handoff, err := mpcceremony.NewTransferHandoff(definition, mpcceremony.Phase1, 1, "sha256:"+strings.Repeat("a", 64), []mpcceremony.ArtifactRef{ref}, definition.Coordinator, definition.Roster[0].Identity, now.Add(-time.Second).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mpcceremony.MarshalCanonical(handoff)
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, "handoff.json")
	signature := filepath.Join(root, "handoff.sig")
	writeDecisionTestFile(t, record, raw, 0600)
	keyPath := filepath.Join(root, "private.hex")
	writeDecisionTestFile(t, keyPath, []byte(hex.EncodeToString(key.Seed())), 0600)
	sign, err := parseOpsSign(append(append([]string{}, trust...), "--record-type", "handoff", "--record", record, "--signing-key", keyPath, "--out", signature, "--reviewed", "--reviewed-sha256", fmt.Sprintf("%x", sha256.Sum256(raw))))
	if err != nil {
		t.Fatal(err)
	}
	bad := sign
	bad.ReviewedSHA256 = strings.Repeat("0", 64)
	if _, err := executeOpsSign(bad); err == nil {
		t.Fatal("signed changed reviewed bytes")
	}
	if _, err := os.Stat(signature); !os.IsNotExist(err) {
		t.Fatal("failed review wrote signature")
	}
	if _, err := executeOpsSign(sign); err != nil {
		t.Fatal(err)
	}
	if _, err := executeOpsSign(sign); err == nil {
		t.Fatal("overwrote signature")
	}
	receipt, err := parseCustody(append(append([]string{}, trust...), "--transcript-root", root, "--handoff", record, "--handoff-signature", signature, "--sender-public-key-file", filepath.Join(root, "coordinator-public-key.hex"), "--out-dir", filepath.Join(root, "receipt")), true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeCustody(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := os.ReadFile(result.Outputs["canonical"])
	if err != nil {
		t.Fatal(err)
	}
	var r mpcceremony.TransferReceipt
	if err := mpcceremony.UnmarshalCanonical(receiptBytes, &r); err != nil {
		t.Fatal(err)
	}
	if err := mpcceremony.VerifyTransferReceipt(raw, handoff, r); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, filepath.Join(root, ref.Name), []byte("changed"), 0600)
	receipt.OutDir = filepath.Join(root, "tampered-receipt")
	if _, err := executeCustody(receipt); err == nil {
		t.Fatal("receipt acknowledged different delivered bytes")
	}
	if _, err := os.Stat(receipt.OutDir); !os.IsNotExist(err) {
		t.Fatal("failed receipt left a signing packet")
	}
}
