package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"proof-tool/internal/artifact"
	"proof-tool/internal/keybundle"
)

type SignReleaseV4Options struct {
	Trust             TrustPaths
	ArtifactRoot      string
	ReviewCheckpoint  SignedArtifactRefs
	OperationalBundle SignedArtifactRefs
	ReleaseDir        string
	ReleaseSigningKey string
	SignatureKeyID    string
	ReleasedAt        time.Time
}

type VerifyReleaseV4Options struct {
	Trust                  TrustPaths
	KeysDir                string
	TrustedPublicKeyHex    string
	ExpectedSignatureKeyID string
}

// SignReleaseV4 signs a fresh local package after recomputing the exact review
// from its copied bytes. It does not append a checkpoint, authorize production
// use or publish to storage. The caller must keep it private until those gates.
func SignReleaseV4(o SignReleaseV4Options) (*SignReleaseResult, error) {
	if err := validateReleaseDestinationV4(o.ArtifactRoot, o.ReleaseDir); err != nil {
		return nil, err
	}
	review, err := VerifyReleaseReviewV4(o.Trust, o.ArtifactRoot, o.ReviewCheckpoint, o.OperationalBundle, o.ReleasedAt)
	if err != nil {
		return nil, err
	}
	trusted, err := loadOperationalCeremony(o.Trust)
	if err != nil {
		return nil, err
	}
	d := trusted.Definition
	if o.SignatureKeyID != d.ReleaseSigner.KeyID {
		return nil, errors.New("release signature key id differs from signed definition")
	}
	private, public, err := keybundle.LoadExistingPrivateKey(o.ReleaseSigningKey)
	if err != nil {
		return nil, err
	}
	if err := requireIdentityKey(d.ReleaseSigner, public); err != nil {
		return nil, fmt.Errorf("release signing key: %w", err)
	}
	names, err := releaseDependencyNamesV4(review.RequiredArtifacts)
	if err != nil {
		return nil, err
	}
	staging, err := createRecoveryStagingDir(o.ReleaseDir)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	for _, ref := range review.RequiredArtifacts {
		name, err := releasePhysicalNameV4(ref.Name)
		if err != nil {
			return nil, err
		}
		destination := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return nil, err
		}
		if err := copyRegularNoReplace(filepath.Join(o.ArtifactRoot, filepath.FromSlash(ref.Name)), destination); err != nil {
			return nil, err
		}
	}
	if err := verifyExactReleaseFiles(staging, names, true); err != nil {
		return nil, err
	}
	// Keep the independent coordinator-key anchor but authenticate the copied
	// definition/signature. Their exact logical names are in the signed head.
	head, err := readReleaseReviewHeadV4(o.Trust, o.ArtifactRoot, review.ReviewCheckpoint)
	if err != nil {
		return nil, err
	}
	stagedTrust := o.Trust
	stagedTrust.DefinitionPath = filepath.Join(staging, head.Definition.Record.Name)
	stagedTrust.DefinitionSignaturePath = filepath.Join(staging, head.Definition.Signature.Name)
	again, err := verifyReleaseReviewV4(stagedTrust, staging, review.ReviewCheckpoint, review.OperationalBundle, o.ReleasedAt, true)
	if err != nil {
		return nil, fmt.Errorf("copied release review: %w", err)
	}
	if !reflect.DeepEqual(review, again) {
		return nil, errors.New("copied release differs from approved review")
	}
	candidate, _, err := verifyCandidate(d, head.Definition.Record, staging)
	if err != nil {
		return nil, err
	}
	transcript, err := newFinalTranscriptV3(d, candidate, again)
	if err != nil {
		return nil, err
	}
	raw, err := MarshalCanonical(transcript)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFinalTranscriptV3Bytes {
		return nil, errors.New("V3 final transcript exceeds its bounded size")
	}
	if err := writeBytesNoReplace(filepath.Join(staging, FinalTranscriptFile), raw, 0600); err != nil {
		return nil, err
	}
	manifest := releaseManifestV4(d, candidate, raw, review.ReleasedAt)
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	mb = append(mb, '\n')
	for _, file := range []struct {
		name string
		data []byte
	}{
		{keybundle.ManifestFile, mb},
		{keybundle.ManifestSignatureFile, []byte(hex.EncodeToString(ed25519.Sign(private, mb)) + "\n")},
		{keybundle.ManifestPublicKeyFile, []byte(hex.EncodeToString(public) + "\n")},
	} {
		if err := writeBytesNoReplace(filepath.Join(staging, file.name), file.data, 0600); err != nil {
			return nil, err
		}
	}
	checksumNames := append(slices.Clone(names), FinalTranscriptFile, keybundle.ManifestFile, keybundle.ManifestSignatureFile, keybundle.ManifestPublicKeyFile)
	if err := writeChecksumsNoReplace(staging, filepath.Join(staging, ReleaseChecksumsFile), checksumNames); err != nil {
		return nil, err
	}
	if _, err := VerifyReleaseV4(VerifyReleaseV4Options{Trust: stagedTrust, KeysDir: staging, TrustedPublicKeyHex: hex.EncodeToString(public), ExpectedSignatureKeyID: o.SignatureKeyID}); err != nil {
		return nil, fmt.Errorf("V4 release self-verification: %w", err)
	}
	if err := syncDirectory(staging); err != nil {
		return nil, err
	}
	if err := publishReleaseDirectory(staging, o.ReleaseDir); err != nil {
		return nil, err
	}
	committed = true
	// Exact recovery may reuse an already-existing destination. Check its V4
	// invariants too; byte equality alone does not detect external hard links.
	finalTrust := o.Trust
	finalTrust.DefinitionPath = filepath.Join(o.ReleaseDir, head.Definition.Record.Name)
	finalTrust.DefinitionSignaturePath = filepath.Join(o.ReleaseDir, head.Definition.Signature.Name)
	if _, err := VerifyReleaseV4(VerifyReleaseV4Options{Trust: finalTrust, KeysDir: o.ReleaseDir, TrustedPublicKeyHex: hex.EncodeToString(public), ExpectedSignatureKeyID: o.SignatureKeyID}); err != nil {
		return nil, &publicationError{publicationCommitted, "verify V4 destination; retain for investigation", err}
	}
	return &SignReleaseResult{ManifestPath: filepath.Join(o.ReleaseDir, keybundle.ManifestFile), ManifestSignature: filepath.Join(o.ReleaseDir, keybundle.ManifestSignatureFile), ManifestPublicKey: filepath.Join(o.ReleaseDir, keybundle.ManifestPublicKeyFile), FinalTranscript: filepath.Join(o.ReleaseDir, FinalTranscriptFile), OperationalEvidence: filepath.Join(o.ReleaseDir, OperationalEvidenceBundleFile), ChecksumsPath: filepath.Join(o.ReleaseDir, ReleaseChecksumsFile)}, nil
}

func readReleaseReviewHeadV4(trust TrustPaths, root string, refs SignedArtifactRefs) (CheckpointV4, error) {
	t, err := loadOperationalCeremony(trust)
	if err != nil {
		return CheckpointV4{}, err
	}
	db, err := MarshalCanonical(t.Definition)
	if err != nil {
		return CheckpointV4{}, err
	}
	ds, err := readRegularBounded(trust.DefinitionSignaturePath, 4096)
	if err != nil {
		return CheckpointV4{}, err
	}
	r, err := openCheckpointReaderV4(root)
	if err != nil {
		return CheckpointV4{}, err
	}
	defer r.root.Close()
	rb, rs, err := r.pair(refs)
	if err != nil {
		return CheckpointV4{}, err
	}
	return VerifySignedCheckpointV4(t.Definition, db, ds, rb, rs)
}

func releaseManifestV4(d CeremonyDefinition, c CandidateMetadata, transcript []byte, at string) artifact.KeyManifest {
	return artifact.KeyManifest{
		Schema: artifact.ManifestSchema, KeyVersion: d.Circuit.KeyVersion, CircuitID: d.Circuit.CircuitID, Curve: d.Circuit.Curve, Backend: d.Circuit.Backend,
		VKHash: c.VerifyingKey.Digest.Blake2b256, ProvingKeySHA256: c.ProvingKey.Digest.SHA256, ProvingKeyBlake2b256: c.ProvingKey.Digest.Blake2b256, ProvingKeySize: c.ProvingKey.Digest.Size,
		VerifyingKeySHA256: c.VerifyingKey.Digest.SHA256, VerifyingKeySize: c.VerifyingKey.Digest.Size, ConstraintSystemHash: c.ConstraintSystem.Digest.Blake2b256,
		CircuitSourceCommit: d.Software.SourceCommit, ProofToolVersion: d.Software.ProofToolVersion, GnarkVersion: d.Software.GnarkVersion,
		SetupTranscriptHash: NewDigest(transcript).Blake2b256, PublishedAt: at, SignatureKeyID: d.ReleaseSigner.KeyID,
	}
}

// VerifyReleaseV4 authenticates the exact local package. It trusts the signed
// coordinator replay claim, not a caller flag, and does not claim publication
// or a production GO decision. Historical payload bytes are not in the package.
func VerifyReleaseV4(o VerifyReleaseV4Options) (*VerifyReleaseResult, error) {
	trusted, err := loadOperationalCeremony(o.Trust)
	if err != nil {
		return nil, err
	}
	d := trusted.Definition
	if d.Schema != DefinitionSchemaV4 {
		return nil, errors.New("V4 release verifier requires definition v4")
	}
	public, err := keybundle.DecodePublicKeyHex(o.TrustedPublicKeyHex)
	if err != nil {
		return nil, err
	}
	if err := requireIdentityKey(d.ReleaseSigner, public); err != nil {
		return nil, err
	}
	if o.ExpectedSignatureKeyID != d.ReleaseSigner.KeyID {
		return nil, errors.New("release signer id differs from signed definition")
	}
	verifyBundle := keybundle.Verify
	if d.Mode == ModeRehearsal && d.Circuit.KeyVersion == KeyVersionRehearsal {
		verifyBundle = keybundle.VerifyRehearsal
	}
	manifest, err := verifyBundle(keybundle.VerifyOptions{KeysDir: o.KeysDir, KeyVersion: d.Circuit.KeyVersion, PublicKeyHex: o.TrustedPublicKeyHex, ExpectedSignatureKeyID: o.ExpectedSignatureKeyID, RequireProvingKey: true})
	if err != nil {
		return nil, err
	}
	pk, err := readRegularFile(filepath.Join(o.KeysDir, keybundle.ManifestPublicKeyFile))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(pk)) != hex.EncodeToString(public) {
		return nil, errors.New("bundled release key differs from trusted key")
	}
	raw, err := readRegularBounded(filepath.Join(o.KeysDir, FinalTranscriptFile), maxFinalTranscriptV3Bytes)
	if err != nil {
		return nil, err
	}
	var transcript FinalTranscript
	if err := UnmarshalCanonical(raw, &transcript); err != nil {
		return nil, err
	}
	if transcript.Schema != FinalTranscriptSchemaV3 || transcript.ReleaseReview == nil {
		return nil, errors.New("V4 release requires final transcript v3")
	}
	at, _ := time.Parse(time.RFC3339Nano, transcript.FinalizedAt)
	review, err := verifyReleaseReviewV4(o.Trust, o.KeysDir, transcript.ReleaseReview.ReviewCheckpoint, transcript.ReleaseReview.OperationalBundle, at, true)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(review, *transcript.ReleaseReview) {
		return nil, errors.New("signed release review differs from verified package")
	}
	candidate, _, err := verifyCandidate(d, transcript.Definition, o.KeysDir)
	if err != nil {
		return nil, err
	}
	expected, err := newFinalTranscriptV3(d, candidate, review)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(transcript, expected) {
		return nil, errors.New("final transcript differs from exact verified review and candidate")
	}
	wantManifest := releaseManifestV4(d, candidate, raw, review.ReleasedAt)
	if !reflect.DeepEqual(*manifest, wantManifest) {
		return nil, errors.New("manifest differs from exact candidate and review transcript")
	}
	names, err := releaseDependencyNamesV4(review.RequiredArtifacts)
	if err != nil {
		return nil, err
	}
	names = append(names, FinalTranscriptFile, keybundle.ManifestFile, keybundle.ManifestSignatureFile, keybundle.ManifestPublicKeyFile)
	if err := verifyChecksumsExact(o.KeysDir, filepath.Join(o.KeysDir, ReleaseChecksumsFile), names); err != nil {
		return nil, err
	}
	if err := verifyExactReleaseFiles(o.KeysDir, append(names, ReleaseChecksumsFile), true); err != nil {
		return nil, err
	}
	ref, err := artifactRefForFile(keybundle.ManifestFile, filepath.Join(o.KeysDir, keybundle.ManifestFile))
	if err != nil {
		return nil, err
	}
	return &VerifyReleaseResult{Manifest: manifest, ManifestSHA256: ref.Digest.SHA256, Transcript: transcript, Candidate: candidate}, nil
}
