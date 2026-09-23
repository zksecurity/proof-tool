package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proof-tool/internal/artifact"
	"proof-tool/internal/keybundle"
	m "proof-tool/internal/mpcceremony"
)

func runCheckpointV4Release(root string, trust m.TrustPaths, d m.CeremonyDefinition, review m.ReleaseReviewV4, key, out string) error {
	at, _ := time.Parse(time.RFC3339Nano, review.ReleasedAt)
	options := m.SignReleaseV4Options{Trust: trust, ArtifactRoot: root, ReviewCheckpoint: review.ReviewCheckpoint, OperationalBundle: review.OperationalBundle, ReleaseDir: out, ReleaseSigningKey: key, SignatureKeyID: d.ReleaseSigner.KeyID, ReleasedAt: at}
	wrong := options
	wrong.SignatureKeyID = d.Coordinator.KeyID
	if _, err := m.SignReleaseV4(wrong); err == nil {
		return fmt.Errorf("wrong release signer id accepted")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		return fmt.Errorf("failed release published output: %v", err)
	}
	if _, err := m.SignReleaseV4(options); err != nil {
		return fmt.Errorf("V4 release signing: %w", err)
	}
	verify := m.VerifyReleaseV4Options{Trust: trust, KeysDir: out, TrustedPublicKeyHex: d.ReleaseSigner.Ed25519PublicKeyHex, ExpectedSignatureKeyID: d.ReleaseSigner.KeyID}
	if _, err := m.VerifyReleaseV4(verify); err != nil {
		return fmt.Errorf("V4 release verification: %w", err)
	}
	if _, err := keybundle.VerifyCeremonyTest(keybundle.VerifyOptions{KeysDir: out, KeyVersion: d.Circuit.KeyVersion, PublicKeyHex: d.ReleaseSigner.Ed25519PublicKeyHex, ExpectedSignatureKeyID: d.ReleaseSigner.KeyID, RequireProvingKey: true}); err != nil {
		return fmt.Errorf("ordinary rehearsal key-bundle consumer: %w", err)
	}
	if _, err := m.VerifyRelease(m.VerifyReleaseOptions{DefinitionPath: trust.DefinitionPath, DefinitionSignaturePath: trust.DefinitionSignaturePath, CoordinatorPublicKeyHex: d.Coordinator.Ed25519PublicKeyHex, KeysDir: out, TrustedPublicKeyHex: d.ReleaseSigner.Ed25519PublicKeyHex, ExpectedSignatureKeyID: d.ReleaseSigner.KeyID, RequireProvingKey: true}); err == nil {
		return fmt.Errorf("legacy release verifier accepted definition v4")
	}
	if _, err := m.SignReleaseV4(options); err != nil {
		return fmt.Errorf("exact V4 signing retry: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(out, "final/candidate")); !os.IsNotExist(err) {
		return fmt.Errorf("V4 package duplicates candidate directory: %v", err)
	}
	for _, name := range []string{m.NativeVerifyingKeyFile, review.ReviewCheckpoint.Signature.Name, m.OperationalEvidenceSignatureFile} {
		p := filepath.Join(out, name)
		original, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		bad := bytes.Clone(original)
		bad[len(bad)-1] ^= 1
		if err := os.WriteFile(p, bad, 0600); err != nil {
			return err
		}
		_, rejected := m.VerifyReleaseV4(verify)
		if err := os.WriteFile(p, original, 0600); err != nil {
			return err
		}
		if rejected == nil {
			return fmt.Errorf("changed release file accepted: %s", name)
		}
	}
	extra := filepath.Join(out, "unreviewed.txt")
	if err := os.WriteFile(extra, []byte("not reviewed"), 0600); err != nil {
		return err
	}
	_, rejected := m.VerifyReleaseV4(verify)
	if err := os.Remove(extra); err != nil {
		return err
	}
	if rejected == nil {
		return fmt.Errorf("unlisted release file accepted")
	}
	link := filepath.Join(filepath.Dir(out), "linked-release-public-key.hex")
	if err := os.Link(filepath.Join(out, keybundle.ManifestPublicKeyFile), link); err != nil {
		return err
	}
	_, rejected = m.VerifyReleaseV4(verify)
	_, retryRejected := m.SignReleaseV4(options)
	if err := os.Remove(link); err != nil {
		return err
	}
	if rejected == nil || !strings.Contains(rejected.Error(), "hard link") {
		return fmt.Errorf("hardlinked package file accepted: %v", rejected)
	}
	if retryRejected == nil || !strings.Contains(retryRejected.Error(), "committed publication") || !strings.Contains(retryRejected.Error(), "hard link") {
		return fmt.Errorf("unsafe exact retry accepted: %v", retryRejected)
	}
	if _, err := os.Stat(out); err != nil {
		return fmt.Errorf("committed recovery output was not retained: %w", err)
	}
	// Give an incorrect embedded review a valid manifest signature. Rejection
	// must come from recomputing the review, not an incidental bad signature.
	transcriptPath := filepath.Join(out, m.FinalTranscriptFile)
	originalTranscript, err := os.ReadFile(transcriptPath)
	if err != nil {
		return err
	}
	var transcript m.FinalTranscript
	if err := m.UnmarshalCanonical(originalTranscript, &transcript); err != nil {
		return err
	}
	for i, ref := range transcript.ReleaseReview.RequiredArtifacts {
		if ref.Name == review.ReviewCheckpoint.Signature.Name {
			transcript.ReleaseReview.RequiredArtifacts[i].Digest = m.NewDigest([]byte("different committed dependency"))
		}
	}
	transcript, err = m.NewFinalTranscript(transcript)
	if err != nil {
		return err
	}
	raw, err := m.MarshalCanonical(transcript)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(out, keybundle.ManifestFile)
	originalManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest artifact.KeyManifest
	if err := json.Unmarshal(originalManifest, &manifest); err != nil {
		return err
	}
	manifest.SetupTranscriptHash = m.NewDigest(raw).Blake2b256
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	mb = append(mb, '\n')
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x82}, 32))
	sigPath := filepath.Join(out, keybundle.ManifestSignatureFile)
	originalSig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		p string
		b []byte
	}{{transcriptPath, raw}, {manifestPath, mb}, {sigPath, []byte(hex.EncodeToString(ed25519.Sign(private, mb)) + "\n")}} {
		if err := os.WriteFile(f.p, f.b, 0600); err != nil {
			return err
		}
	}
	_, rejected = m.VerifyReleaseV4(verify)
	for _, f := range []struct {
		p string
		b []byte
	}{{transcriptPath, originalTranscript}, {manifestPath, originalManifest}, {sigPath, originalSig}} {
		if err := os.WriteFile(f.p, f.b, 0600); err != nil {
			return err
		}
	}
	if rejected == nil || !strings.Contains(rejected.Error(), "signed release review differs") {
		return fmt.Errorf("coherently signed wrong review not rejected: %v", rejected)
	}
	if _, err := m.VerifyReleaseV4(verify); err != nil {
		return err
	}
	fmt.Println("V4 signed package passed: exact-only source, unchanged key-bundle consumer, signer required, exact retry, wrong files and signed review rejected")
	return nil
}
