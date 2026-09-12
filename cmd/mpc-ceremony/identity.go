// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

const generatedIdentityKeyIDPrefix = "ed25519:"

const identityRecoverySchema = "proof-tool-identity-recovery-v1"

type identityRecoveryIntent struct {
	Schema            string `json:"schema"`
	IdentityID        string `json:"identity_id"`
	DisplayName       string `json:"display_name"`
	PrivateKeyOut     string `json:"private_key_out"`
	PublicIdentityOut string `json:"public_identity_out"`
}

func executeIdentityGenerate(options IdentityGenerateOptions) (CommandResult, error) {
	privateTarget, err := resolvedFreshTarget(options.PrivateKeyOut)
	if err != nil {
		return CommandResult{}, fmt.Errorf("private key output: %w", err)
	}
	publicTarget, err := resolvedFreshTarget(options.PublicIdentityOut)
	if err != nil {
		return CommandResult{}, fmt.Errorf("public identity output: %w", err)
	}
	if privateTarget == publicTarget {
		return CommandResult{}, errors.New("private and public output paths must be distinct")
	}
	intentPath := privateTarget + ".identity-recovery.json"
	if intentPath == publicTarget {
		return CommandResult{}, errors.New("public identity output conflicts with the private-key recovery record")
	}
	privateExists, err := targetExists(options.PrivateKeyOut)
	if err != nil {
		return CommandResult{}, fmt.Errorf("private key output: %w", err)
	}
	publicExists, err := targetExists(options.PublicIdentityOut)
	if err != nil {
		return CommandResult{}, fmt.Errorf("public identity output: %w", err)
	}
	if publicExists && !privateExists {
		return CommandResult{}, errors.New("public identity output already exists without its private key")
	}
	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey
	if privateExists {
		privateKey, publicKey, err = keybundle.LoadExistingPrivateKey(options.PrivateKeyOut)
		if err != nil {
			return CommandResult{}, fmt.Errorf("continue identity from retained private key: %w", err)
		}
	} else {
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return CommandResult{}, fmt.Errorf("generate Ed25519 key from operating-system CSPRNG: %w", err)
		}
	}
	defer zeroBytes(privateKey)

	publicKeyDigest := sha256.Sum256(publicKey)
	identity, err := mpcceremony.NewIdentity(
		options.IdentityID,
		options.DisplayName,
		generatedIdentityKeyIDPrefix+hex.EncodeToString(publicKeyDigest[:]),
		publicKey,
	)
	if err != nil {
		return CommandResult{}, fmt.Errorf("create public ceremony identity: %w", err)
	}
	publicIdentity, err := mpcceremony.MarshalCanonical(identity)
	if err != nil {
		return CommandResult{}, fmt.Errorf("encode public ceremony identity: %w", err)
	}
	intent := identityRecoveryIntent{
		Schema: identityRecoverySchema, IdentityID: options.IdentityID,
		DisplayName: options.DisplayName, PrivateKeyOut: privateTarget,
		PublicIdentityOut: publicTarget,
	}
	if err := ensureIdentityRecoveryIntent(intentPath, intent, privateExists); err != nil {
		return CommandResult{}, err
	}
	if publicExists {
		if err := verifyExistingPublicIdentity(options.PublicIdentityOut, publicIdentity); err != nil {
			return CommandResult{}, err
		}
		return identityGenerateResult(identity, options), nil
	}

	seed := privateKey.Seed()
	defer zeroBytes(seed)
	privateSeedHex := make([]byte, hex.EncodedLen(len(seed))+1)
	hex.Encode(privateSeedHex, seed)
	privateSeedHex[len(privateSeedHex)-1] = '\n'
	defer zeroBytes(privateSeedHex)

	// Persist the secret first. If public-file creation is interrupted, the
	// exact public identity can be derived from this retained key on the next
	// invocation; a second private key is never generated automatically.
	if !privateExists {
		if err := writeFreshOperationalFile(options.PrivateKeyOut, privateSeedHex, 0o600); err != nil {
			return CommandResult{}, fmt.Errorf("write private key: %w", err)
		}
		if err := syncDirectory(filepath.Dir(options.PrivateKeyOut)); err != nil {
			return CommandResult{}, fmt.Errorf("sync private key directory: %w", err)
		}
	}
	if err := writeFreshOperationalFile(options.PublicIdentityOut, publicIdentity, 0o644); err != nil {
		return CommandResult{}, fmt.Errorf("write public identity (private key retained for exact continuation): %w", err)
	}
	if err := syncDirectory(filepath.Dir(options.PublicIdentityOut)); err != nil {
		return CommandResult{}, fmt.Errorf("sync public identity directory: %w", err)
	}

	return identityGenerateResult(identity, options), nil
}

func identityGenerateResult(identity mpcceremony.Identity, options IdentityGenerateOptions) CommandResult {
	return CommandResult{
		Identity: &identity,
		Outputs: map[string]string{
			"private_key_SECRET": options.PrivateKeyOut,
			"public_identity":    options.PublicIdentityOut,
		},
		Summary: "generated Ed25519 ceremony identity; keep private_key_SECRET local and share only public_identity",
	}
}

func verifyExistingPublicIdentity(path string, expected []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect existing public identity: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return errors.New("existing public identity is not a safe regular file")
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read existing public identity: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("existing public identity does not match the retained private key and recovery record")
	}
	return nil
}

func ensureIdentityRecoveryIntent(path string, expected identityRecoveryIntent, privateExists bool) error {
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 1<<20 {
			return errors.New("identity recovery record must be a protected regular file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect identity recovery record: %w", statErr)
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if privateExists {
			return errors.New("retained private key has no identity recovery record; refusing to guess its original public identity")
		}
		encoded, marshalErr := json.Marshal(expected)
		if marshalErr != nil {
			return marshalErr
		}
		encoded = append(encoded, '\n')
		if writeErr := writeFreshOperationalFile(path, encoded, 0o600); writeErr != nil {
			return fmt.Errorf("write identity recovery record: %w", writeErr)
		}
		if syncErr := syncDirectory(filepath.Dir(path)); syncErr != nil {
			return fmt.Errorf("sync identity recovery directory: %w", syncErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read identity recovery record: %w", err)
	}
	var actual identityRecoveryIntent
	if json.Unmarshal(raw, &actual) != nil || actual != expected {
		return errors.New("identity recovery record does not match the requested identity and output paths")
	}
	return nil
}

func resolvedFreshTarget(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve parent directory: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect parent directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("parent is not a directory")
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func targetExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
