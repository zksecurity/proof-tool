package keybundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proof-tool/internal/artifact"
	"proof-tool/internal/circuit/rehearsal"
	"proof-tool/internal/prover"
)

func TestLoadExistingPrivateKeyDoesNotGenerate(t *testing.T) {
	dir := t.TempDir()
	missingPath := filepath.Join(dir, "missing.private.hex")
	if _, _, err := LoadExistingPrivateKey(missingPath); err == nil {
		t.Fatal("missing private key unexpectedly loaded")
	}
	if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
		t.Fatalf("missing key was created: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	keyPath := filepath.Join(dir, "existing.private.hex")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey, err := LoadExistingPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("key sizes = %d/%d", len(privateKey), len(publicKey))
	}
}

func TestLoadExistingPrivateKeyRejectsSymlinkAndLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	target := filepath.Join(dir, "target.private.hex")
	if err := os.WriteFile(target, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.private.hex")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadExistingPrivateKey(link); err == nil {
		t.Fatal("symlinked private key was accepted")
	}

	if runtime.GOOS != "windows" {
		loose := filepath.Join(dir, "loose.private.hex")
		if err := os.WriteFile(loose, []byte(hex.EncodeToString(seed)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadExistingPrivateKey(loose); err == nil || !strings.Contains(err.Error(), "permission") {
			t.Fatalf("loosely permissioned private key error = %v", err)
		}
	}
}

func TestLoadExistingPrivateKeyRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.private.hex")
	if err := os.WriteFile(path, []byte(strings.Repeat("0", maxPrivateKeyHexBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadExistingPrivateKey(path); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("oversized private key error = %v", err)
	}
}

func TestDecodePrivateKeyHexRejectsInconsistentPublicHalf(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	privateKey[ed25519.SeedSize] ^= 1
	if _, err := DecodePrivateKeyHex(hex.EncodeToString(privateKey)); err == nil ||
		!strings.Contains(err.Error(), "public half") {
		t.Fatalf("inconsistent private key error = %v", err)
	}
}

func TestVerifyManifestSignatureRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, ManifestFile)
	signaturePath := filepath.Join(dir, ManifestSignatureFile)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("{\"schema\":\"test\"}\n")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	signature := hex.EncodeToString(ed25519.Sign(privateKey, manifest)) + "\n"
	if err := os.WriteFile(signaturePath, []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifestSignature(manifestPath, signaturePath, hex.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{\"schema\":\"tampered\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyManifestSignature(manifestPath, signaturePath, hex.EncodeToString(publicKey))
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("tampered manifest err = %v", err)
	}
}

func TestRequireManifestMatchRejectsInspectedManifestMismatch(t *testing.T) {
	signed := &artifact.KeyManifest{
		Schema:     artifact.ManifestSchema,
		KeyVersion: "signed-version",
		CircuitID:  "signed-circuit",
	}
	inspected := *signed
	inspected.CircuitID = "swapped-circuit"
	if err := requireManifestMatch(signed, &inspected); err == nil ||
		!strings.Contains(err.Error(), "changed after signature verification") {
		t.Fatalf("manifest mismatch error = %v", err)
	}
}

// These fixtures exercise signature/profile/file-pin verification, not Groth16
// deserialization. The ceremony lifecycle test supplies real generated keys.
func rehearsalBundleFixture(t *testing.T) (VerifyOptions, func(func(*artifact.KeyManifest))) {
	t.Helper()
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ownership.pk", "ownership.vk"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test file pins: "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pk, err := prover.DigestFile(filepath.Join(dir, "ownership.pk"))
	if err != nil {
		t.Fatal(err)
	}
	vk, err := prover.DigestFile(filepath.Join(dir, "ownership.vk"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifact.KeyManifest{
		Schema: artifact.ManifestSchema, KeyVersion: rehearsal.KeyVersion,
		CircuitID: rehearsal.CircuitID, Curve: "BLS12-381", Backend: "groth16",
		ProvingKeySHA256: pk.SHA256, ProvingKeyBlake2b256: pk.Blake2b256, ProvingKeySize: pk.Size,
		VKHash: vk.Blake2b256, VerifyingKeySHA256: vk.SHA256, VerifyingKeySize: vk.Size,
		SignatureKeyID: "test-rehearsal-signer",
	}
	writeSigned := func(change func(*artifact.KeyManifest)) {
		t.Helper()
		updated := manifest
		if change != nil {
			change(&updated)
		}
		raw, err := json.Marshal(updated)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ManifestFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		sig := hex.EncodeToString(ed25519.Sign(privateKey, raw))
		if err := os.WriteFile(filepath.Join(dir, ManifestSignatureFile), []byte(sig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSigned(nil)
	return VerifyOptions{
		KeysDir: dir, KeyVersion: rehearsal.KeyVersion, PublicKeyHex: hex.EncodeToString(publicKey),
		ExpectedSignatureKeyID: manifest.SignatureKeyID, RequireProvingKey: true,
	}, writeSigned
}

func TestVerifyRehearsalDoesNotBroadenProductionProfiles(t *testing.T) {
	opts, _ := rehearsalBundleFixture(t)
	if _, err := VerifyRehearsal(opts); err != nil {
		t.Fatalf("explicit rehearsal verification: %v", err)
	}
	if _, err := Verify(opts); err == nil || !strings.Contains(err.Error(), "unsupported key version") {
		t.Fatalf("production verifier accepted rehearsal profile: %v", err)
	}
	opts.KeyVersion = ""
	if _, err := Verify(opts); err == nil {
		t.Fatal("production verifier inferred and accepted rehearsal profile")
	}
	if _, err := VerifyRehearsal(opts); err == nil {
		t.Fatal("rehearsal verifier accepted an implicit profile")
	}
	opts.KeyVersion = "ownership-destination-v2"
	if _, err := VerifyRehearsal(opts); err == nil {
		t.Fatal("rehearsal verifier accepted a production profile")
	}
}

func TestVerifyRehearsalRetainsSignatureAndFilePinChecks(t *testing.T) {
	for _, name := range []string{"ownership.pk", "ownership.vk", ManifestSignatureFile} {
		t.Run(name, func(t *testing.T) {
			opts, _ := rehearsalBundleFixture(t)
			if err := os.WriteFile(filepath.Join(opts.KeysDir, name), []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRehearsal(opts); err == nil {
				t.Fatal("changed file was accepted")
			}
		})
	}
	for name, change := range map[string]func(*artifact.KeyManifest){
		"key version": func(m *artifact.KeyManifest) { m.KeyVersion = "ownership-destination-v2" },
		"circuit":     func(m *artifact.KeyManifest) { m.CircuitID = "wrong-circuit" },
		"curve":       func(m *artifact.KeyManifest) { m.Curve = "wrong-curve" },
		"backend":     func(m *artifact.KeyManifest) { m.Backend = "wrong-backend" },
		"signer ID":   func(m *artifact.KeyManifest) { m.SignatureKeyID = "wrong-signer" },
	} {
		t.Run(name, func(t *testing.T) {
			opts, writeSigned := rehearsalBundleFixture(t)
			writeSigned(change)
			if _, err := VerifyRehearsal(opts); err == nil {
				t.Fatal("incorrect signed profile was accepted")
			}
		})
	}
	t.Run("trust anchor", func(t *testing.T) {
		opts, _ := rehearsalBundleFixture(t)
		opts.PublicKeyHex = ""
		if _, err := VerifyRehearsal(opts); err == nil {
			t.Fatal("missing trust anchor was accepted")
		}
	})
}
