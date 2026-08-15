package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// Built with string(rune(...)) rather than written literally: these characters
// are invisible, and two of them would reorder this source file in an editor.
var (
	rlo  = string(rune(0x202E)) // right-to-left override
	lro  = string(rune(0x202D)) // left-to-right override
	rli  = string(rune(0x2067)) // right-to-left isolate
	pdi  = string(rune(0x2069)) // pop directional isolate
	lrm  = string(rune(0x200E)) // left-to-right mark
	zwsp = string(rune(0x200B)) // zero-width space
	zwnj = string(rune(0x200C)) // zero-width non-joiner, legitimate
	zwj  = string(rune(0x200D)) // zero-width joiner, legitimate
	esc  = string(rune(0x001B)) // ANSI escape introducer
	bel  = string(rune(0x0007)) // bell
)

// identityWithDisplayName builds an otherwise valid identity so the only thing
// under test is the display name.
func identityWithDisplayName(t *testing.T, displayName string) Identity {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{
		ID:                   "participant-01",
		DisplayName:          displayName,
		KeyID:                "participant-01-key",
		Ed25519PublicKeyHex:  hex.EncodeToString(public),
		PublicKeyFingerprint: taggedSHA256(public),
	}
}

// TestDisplayNameRejectsDeceptiveRunes covers the characters that make a signed
// value render as something other than its bytes. None of these forge anything:
// the target is the human reading a transcript, and the audit and release steps
// depend on that reading being accurate.
func TestDisplayNameRejectsDeceptiveRunes(t *testing.T) {
	cases := []struct {
		name        string
		displayName string
		wantErr     string
	}{
		// Stored bytes read "ecilA"; a terminal renders "Alice".
		{"right-to-left override", rlo + "ecilA", "bidirectional formatting"},
		{"left-to-right override", "Alice" + lro, "bidirectional formatting"},
		{"right-to-left isolate", "Alice" + rli + "Chen", "bidirectional formatting"},
		{"pop directional isolate", "Alice" + pdi, "bidirectional formatting"},
		{"left-to-right mark", "Alice" + lrm + "Chen", "bidirectional formatting"},
		// Renders identically to a plain "Alice", so two roster entries become
		// indistinguishable on screen.
		{"zero width space", "Ali" + zwsp + "ce", "zero-width"},
		{"ansi escape", "Alice" + esc + "[2K", "control character"},
		{"bell", "Alice" + bel, "control character"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := identityWithDisplayName(t, testCase.displayName).Validate()
			if err == nil {
				t.Fatalf("display name %q was accepted", testCase.displayName)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error %q does not mention %q", err, testCase.wantErr)
			}
		})
	}
}

// TestDisplayNameAcceptsLegitimateText guards against over-blocking. ZWNJ and
// ZWJ are category Cf like the rejected characters, but they carry meaning:
// U+200C separates Persian and Indic letterforms and U+200D joins emoji
// sequences. Rejecting all of category Cf would make these names unwritable.
func TestDisplayNameAcceptsLegitimateText(t *testing.T) {
	for _, displayName := range []string{
		"Alice Chen",
		"Alice Chen, ZK Security",
		"Zoe Muller",
		"田中太郎",
		"مريم",
		"می" + zwnj + "خواهم",
		"\U0001F469" + zwj + "\U0001F4BB",
		strings.Repeat("a", maxDisplayNameBytes),
	} {
		if err := identityWithDisplayName(t, displayName).Validate(); err != nil {
			t.Fatalf("legitimate display name %q was rejected: %v", displayName, err)
		}
	}
}

func TestDisplayNameBounds(t *testing.T) {
	cases := []struct {
		name        string
		displayName string
		wantErr     string
	}{
		{"empty", "", "1 to 256 bytes"},
		{"too long", strings.Repeat("a", maxDisplayNameBytes+1), "1 to 256 bytes"},
		{"blank", "   ", "must be trimmed"},
		{"untrimmed", " Alice ", "must be trimmed"},
		{"invalid utf8", "Alice\xff", "valid UTF-8"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := identityWithDisplayName(t, testCase.displayName).Validate()
			if err == nil {
				t.Fatalf("display name %q was accepted", testCase.displayName)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error %q does not mention %q", err, testCase.wantErr)
			}
		})
	}
}

// TestArtifactNameRejectsDeceptiveRunes covers the other half of the same gap.
// Artifact names were already screened with unicode.IsControl, which reports
// category Cc only, so every bidi and zero-width character (category Cf) passed
// until rejectDeceptiveRunes was shared between the two validators.
func TestArtifactNameRejectsDeceptiveRunes(t *testing.T) {
	for _, name := range []string{
		"phase1/" + rlo + "gnp.nib",
		"phase1/chain" + zwsp + "-0001.json",
		"phase1/" + rli + "chain.json",
	} {
		if err := validateArtifactName(name); err == nil {
			t.Fatalf("artifact name %q was accepted", name)
		}
	}
	for _, name := range []string{
		"phase1/chain-0001.json",
		"phase1/beacon/record.json",
		"ownership-destination.ccs",
	} {
		if err := validateArtifactName(name); err != nil {
			t.Fatalf("legitimate artifact name %q was rejected: %v", name, err)
		}
	}
}
