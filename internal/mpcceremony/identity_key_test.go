package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// smallOrderEd25519Keys are the canonical encodings of the eight points of
// order dividing 8 on edwards25519, plus the two non-canonical encodings of the
// small-order points that decode successfully. Any of them, enrolled as an
// identity, makes signatures under that identity forgeable without a private
// key.
var smallOrderEd25519Keys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
}

func TestIdentityRejectsSmallOrderPublicKeys(t *testing.T) {
	for _, keyHex := range smallOrderEd25519Keys {
		raw, err := hex.DecodeString(keyHex)
		if err != nil {
			t.Fatalf("decode %s: %v", keyHex, err)
		}
		if _, err := NewIdentity("participant-01", "Participant One", "participant-key", raw); err == nil {
			t.Fatalf("NewIdentity accepted small-order public key %s", keyHex)
		}
	}
}

// TestSmallOrderPublicKeyAcceptsForgedSignature documents why the check above
// exists. Without it, this signature verifies against the identity point for
// any message at all.
func TestSmallOrderPublicKeyAcceptsForgedSignature(t *testing.T) {
	identityPoint := make([]byte, ed25519.PublicKeySize)
	identityPoint[0] = 0x01

	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 0x01 // R = identity encoding, S = 0

	for _, message := range []string{"one message", "an entirely different message"} {
		if !ed25519.Verify(identityPoint, []byte(message), forged) {
			t.Fatalf("expected the forged signature to verify for %q; the premise of the guard no longer holds", message)
		}
	}

	if err := validateEd25519PublicKey(identityPoint); err == nil {
		t.Fatal("validateEd25519PublicKey accepted the identity point")
	}
}

func TestIdentityRejectsOffCurvePublicKey(t *testing.T) {
	// High bit of the final byte is the sign of x; the remaining field element
	// is not a valid y coordinate for any curve point.
	raw, err := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	err = validateEd25519PublicKey(raw)
	if err == nil {
		t.Fatal("validateEd25519PublicKey accepted an off-curve encoding")
	}
	if !strings.Contains(err.Error(), "curve point") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestIdentityAcceptsGeneratedKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := validateEd25519PublicKey(public); err != nil {
		t.Fatalf("validateEd25519PublicKey rejected a freshly generated key: %v", err)
	}
	if _, err := NewIdentity("participant-01", "Participant One", "participant-key", public); err != nil {
		t.Fatalf("NewIdentity rejected a freshly generated key: %v", err)
	}
}
