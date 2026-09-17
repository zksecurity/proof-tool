package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Called after the real Linux fixture finishes, in its private test directory.
// This makes signatures/checksums internally consistent with a bad public
// proof, demonstrating that the new check is more than another file hash.
func testV4CoherentInvalidPublicProof(t *testing.T, root string) {
	t.Helper()
	var d CeremonyDefinition
	definitionRef, err := readCanonicalFile(filepath.Join(root, "ceremony.json"), &d)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "final/candidate")
	var candidate CandidateMetadata
	if _, err := readCanonicalFile(filepath.Join(dir, CandidateMetadataFile), &candidate); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidatePublicOutputsV4(d, candidate, dir); err != nil {
		t.Fatalf("original public proof: %v", err)
	}
	changedReport := candidate
	changedReport.VerificationReport.Digest = NewDigest([]byte("different report"))
	if err := verifyCandidatePublicOutputsV4(d, changedReport, dir); err == nil || !strings.Contains(err.Error(), "public report differs") {
		t.Fatalf("public output gate did not bind the report bytes it read: %v", err)
	}
	// Preserve a valid proof but make the report/candidate point to other bytes.
	// The verifier must bind the bytes it actually verified, not just the report.
	reportPath := filepath.Join(dir, candidate.VerificationReport.Name)
	originalReport, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var changedEvidenceReport VerificationReport
	if err := UnmarshalCanonical(originalReport, &changedEvidenceReport); err != nil {
		t.Fatal(err)
	}
	changedEvidence := candidate
	changedEvidence.PublicEvidence.Digest = NewDigest([]byte("different evidence"))
	changedEvidenceReport.PublicEvidence = changedEvidence.PublicEvidence
	changedReportBytes, err := MarshalCanonical(changedEvidenceReport)
	if err != nil {
		t.Fatal(err)
	}
	changedEvidence.VerificationReport = putCheckpointTestFileV4(t, dir, candidate.VerificationReport.Name, changedReportBytes)
	if err := verifyCandidatePublicOutputsV4(d, changedEvidence, dir); err == nil || !strings.Contains(err.Error(), "verified public evidence differs") {
		t.Fatalf("public output gate did not bind verified evidence bytes: %v", err)
	}
	putCheckpointTestFileV4(t, dir, candidate.VerificationReport.Name, originalReport)
	var evidence PublicFinalizationEvidence
	if _, err := readCanonicalFile(filepath.Join(dir, candidate.PublicEvidence.Name), &evidence); err != nil {
		t.Fatal(err)
	}
	proof, err := hex.DecodeString(evidence.CardanoProofHex)
	if err != nil {
		t.Fatal(err)
	}
	clear(proof)
	evidence.CardanoProofHex = hex.EncodeToString(proof)
	evidence.CardanoProofRawDigest = NewDigest(proof)
	raw, err := MarshalCanonical(evidence)
	if err != nil {
		t.Fatal(err)
	}
	candidate.PublicEvidence = putCheckpointTestFileV4(t, dir, candidate.PublicEvidence.Name, raw)
	var report VerificationReport
	if _, err := readCanonicalFile(filepath.Join(dir, candidate.VerificationReport.Name), &report); err != nil {
		t.Fatal(err)
	}
	report.PublicEvidence = candidate.PublicEvidence
	report.CardanoProofRawDigest = evidence.CardanoProofRawDigest
	raw, err = MarshalCanonical(report)
	if err != nil {
		t.Fatal(err)
	}
	candidate.VerificationReport = putCheckpointTestFileV4(t, dir, candidate.VerificationReport.Name, raw)
	candidate, err = NewCandidateMetadata(candidate)
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, err := SignRecord(candidate, d.Coordinator.KeyID, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x81}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	putCheckpointTestFileV4(t, dir, CandidateMetadataFile, raw)
	putCheckpointTestFileV4(t, dir, CandidateSignatureFile, sig)
	checksums := filepath.Join(dir, CandidateChecksumsFile)
	if err := os.Remove(checksums); err != nil {
		t.Fatal(err)
	}
	if err := writeChecksumsNoReplace(dir, checksums, candidateChecksumNames()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyCandidate(d, definitionRef, dir); err != nil {
		t.Fatalf("coherent fixture unexpectedly failed its metadata/hash gate: %v", err)
	}
	if err := verifyCandidatePublicOutputsV4(d, candidate, dir); err == nil || !strings.Contains(err.Error(), "V4 public proof verification") {
		t.Fatalf("coherent invalid public proof did not reach proof gate: %v", err)
	}
}
