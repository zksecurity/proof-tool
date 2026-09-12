// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

func TestIdentityGenerateCreatesCompatibleProtectedKeyAndCanonicalPublicIdentity(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "participant-03.private.hex")
	publicPath := filepath.Join(root, "participant-03.identity.json")
	args := []string{
		"identity", "generate",
		"--identity-id", "participant-03",
		"--display-name", "Participant Three",
		"--private-key-out", privatePath,
		"--public-identity-out", publicPath,
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code != 0 {
		t.Fatalf("identity generate exit = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}

	privateInfo, err := os.Lstat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !privateInfo.Mode().IsRegular() {
		t.Fatalf("private output mode = %s, want regular file", privateInfo.Mode())
	}
	if runtime.GOOS != "windows" && privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private output permissions = %o, want 600", privateInfo.Mode().Perm())
	}

	publicIdentityBytes, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var identity mpcceremony.Identity
	if err := mpcceremony.UnmarshalCanonical(publicIdentityBytes, &identity); err != nil {
		t.Fatalf("public identity is not canonical: %v", err)
	}
	if identity.ID != "participant-03" || identity.DisplayName != "Participant Three" {
		t.Fatalf("identity = %+v", identity)
	}
	wantKeyID := generatedIdentityKeyIDPrefix + strings.TrimPrefix(identity.PublicKeyFingerprint, "sha256:")
	if identity.KeyID != wantKeyID {
		t.Fatalf("key id = %q, want %q", identity.KeyID, wantKeyID)
	}

	privateKey, publicKey, err := keybundle.LoadExistingPrivateKey(privatePath)
	if err != nil {
		t.Fatalf("generated key is not proof-tool-compatible: %v", err)
	}
	defer zeroBytes(privateKey)
	if got := hex.EncodeToString(publicKey); got != identity.Ed25519PublicKeyHex {
		t.Fatalf("derived public key = %q, identity has %q", got, identity.Ed25519PublicKeyHex)
	}
	seedHexBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	seedHex := strings.TrimSpace(string(seedHexBytes))
	zeroBytes(seedHexBytes)
	if strings.Contains(stdout.String(), seedHex) {
		t.Fatal("human command output disclosed the private seed")
	}
	for _, want := range []string{
		"key_id: " + identity.KeyID,
		"public_key_fingerprint: " + identity.PublicKeyFingerprint,
		"private_key_SECRET: " + privatePath,
		"public_identity: " + publicPath,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout %q does not contain %q", stdout.String(), want)
		}
	}
}

func TestIdentityGenerateJSONOutputContainsPublicMetadataButNotPrivateKey(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "auditor-01.private.hex")
	publicPath := filepath.Join(root, "auditor-01.identity.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCLI(context.Background(), []string{
		"--format", "json",
		"identity", "generate",
		"--identity-id", "auditor-01",
		"--display-name", "Independent Auditor One",
		"--private-key-out", privatePath,
		"--public-identity-out", publicPath,
	}, &stdout, &stderr, workflowExecutor{}); code != 0 {
		t.Fatalf("identity generate exit = %d, stderr = %q", code, stderr.String())
	}

	var result CommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON result: %v", err)
	}
	if !result.OK || result.Command != CommandIdentityGenerate || result.Identity == nil {
		t.Fatalf("result = %+v", result)
	}
	if result.Identity.ID != "auditor-01" || result.Identity.KeyID == "" {
		t.Fatalf("public identity result = %+v", result.Identity)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateHex := strings.TrimSpace(string(privateBytes))
	zeroBytes(privateBytes)
	if strings.Contains(stdout.String(), privateHex) {
		t.Fatal("JSON command output disclosed the private seed")
	}
}

func TestIdentityGenerateDoesNotOverwriteOrCreatePartialSecretOutput(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "identity.private.hex")
	publicPath := filepath.Join(root, "identity.json")
	existing := []byte("already enrolled")
	if err := os.WriteFile(publicPath, existing, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI(context.Background(), []string{
		"identity", "generate",
		"--identity-id", "participant-03",
		"--display-name", "Participant Three",
		"--private-key-out", privatePath,
		"--public-identity-out", publicPath,
	}, &stdout, &stderr, workflowExecutor{})
	if code == 0 {
		t.Fatal("identity generate overwrote an existing output")
	}
	got, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatalf("existing public output changed to %q", got)
	}
	if _, err := os.Lstat(privatePath); !os.IsNotExist(err) {
		t.Fatalf("private output exists after preflight failure: %v", err)
	}
}

func TestIdentityGenerateContinuesFromRetainedPrivateKey(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "identity.private.hex")
	publicPath := filepath.Join(root, "identity.json")
	options := IdentityGenerateOptions{
		IdentityID:        "participant-03",
		DisplayName:       "Participant Three",
		PrivateKeyOut:     privatePath,
		PublicIdentityOut: publicPath,
	}
	first, err := executeIdentityGenerate(options)
	if err != nil {
		t.Fatal(err)
	}
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicBefore, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := executeIdentityGenerate(options)
	if err != nil {
		t.Fatal("exact completed identity retry was not adopted:", err)
	}
	if exact.Identity == nil || first.Identity == nil || *exact.Identity != *first.Identity {
		t.Fatal("exact completed identity retry changed metadata")
	}
	if err := os.Remove(publicPath); err != nil {
		t.Fatal(err)
	}
	second, err := executeIdentityGenerate(options)
	if err != nil {
		t.Fatal(err)
	}
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicAfter, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) || !bytes.Equal(publicBefore, publicAfter) {
		t.Fatal("continuation replaced the keypair instead of deriving the same public identity")
	}
	if first.Identity == nil || second.Identity == nil || *first.Identity != *second.Identity {
		t.Fatal("continued identity metadata changed")
	}
	changed := options
	changed.DisplayName = "Different Person"
	if err := os.Remove(publicPath); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIdentityGenerate(changed); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed recovery inputs error = %v", err)
	}
}

func TestIdentityGenerateRejectsChangedCompletedPublicIdentity(t *testing.T) {
	root := t.TempDir()
	options := IdentityGenerateOptions{
		IdentityID: "participant-03", DisplayName: "Participant Three",
		PrivateKeyOut:     filepath.Join(root, "identity.private.hex"),
		PublicIdentityOut: filepath.Join(root, "identity.json"),
	}
	if _, err := executeIdentityGenerate(options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.PublicIdentityOut, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIdentityGenerate(options); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed completed public identity error = %v", err)
	}
}

func TestIdentityGenerateDoesNotGuessLegacyPrivateKeyInputs(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "identity.private.hex")
	if err := os.WriteFile(privatePath, []byte(strings.Repeat("01", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeIdentityGenerate(IdentityGenerateOptions{
		IdentityID: "participant-03", DisplayName: "Participant Three",
		PrivateKeyOut: privatePath, PublicIdentityOut: filepath.Join(root, "identity.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "no identity recovery record") {
		t.Fatalf("legacy private key error = %v", err)
	}
}

func TestIdentityGenerateRejectsSameResolvedOutput(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}

	_, err := executeIdentityGenerate(IdentityGenerateOptions{
		IdentityID:        "participant-03",
		DisplayName:       "Participant Three",
		PrivateKeyOut:     filepath.Join(realDir, "same"),
		PublicIdentityOut: filepath.Join(aliasDir, "same"),
	})
	if err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("same resolved output error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(realDir, "same")); !os.IsNotExist(err) {
		t.Fatalf("same output exists after rejection: %v", err)
	}
}

func TestIdentityGenerateValidatesIdentityBeforeWriting(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "identity.private.hex")
	publicPath := filepath.Join(root, "identity.json")
	_, err := executeIdentityGenerate(IdentityGenerateOptions{
		IdentityID:        "Participant-03",
		DisplayName:       "Participant Three",
		PrivateKeyOut:     privatePath,
		PublicIdentityOut: publicPath,
	})
	if err == nil {
		t.Fatal("invalid identity id was accepted")
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("output %s exists after validation failure: %v", path, statErr)
		}
	}
}
