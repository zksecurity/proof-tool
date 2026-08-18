// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactShortValuesOnlyAsWholeTokens(t *testing.T) {
	t.Parallel()

	// A short argument value must not blank matching characters inside
	// unrelated numbers and words.
	args := []string{"phase1", "verify", "--candidate-dir", "3"}
	message := "chain has 3 records at index 13 under /tmp/3/state"
	redacted := redactCLIError(message, args)
	if strings.Contains(redacted, "index 1"+redactedCLIValue) {
		t.Fatalf("digit inside a larger number was blanked: %q", redacted)
	}
	if !strings.Contains(redacted, "index 13") {
		t.Fatalf("unrelated number damaged: %q", redacted)
	}
	if !strings.Contains(redacted, "has "+redactedCLIValue+" records") {
		t.Fatalf("standalone short value survived: %q", redacted)
	}
	if !strings.Contains(redacted, "/tmp/"+redactedCLIValue+"/state") {
		t.Fatalf("short path segment survived: %q", redacted)
	}
}

func TestRedactShortKeyIDStillRedactedAsToken(t *testing.T) {
	t.Parallel()

	// validateID permits identifiers as short as one character. A short key
	// id echoed verbatim appears as its own token and must still be redacted;
	// this is the leak that forced reverting the plain length-floor approach.
	args := []string{"phase1", "verify", "--participant", "p3"}
	redacted := redactCLIError(`participant "p3" is not in the signed roster`, args)
	if strings.Contains(redacted, "p3") {
		t.Fatalf("short identifier leaked: %q", redacted)
	}
	// The same short value inside a longer token is a different token and
	// stays readable.
	other := redactCLIError("participant p30 is not scheduled", args)
	if !strings.Contains(other, "p30") {
		t.Fatalf("longer identifier containing the short value was damaged: %q", other)
	}
}

func TestRedactLongValuesAnywhere(t *testing.T) {
	t.Parallel()

	args := []string{"phase1", "verify", "--key", "SENSITIVE-VALUE"}
	redacted := redactCLIError("open /keys/SENSITIVE-VALUE.hex failed", args)
	if strings.Contains(redacted, "SENSITIVE-VALUE") {
		t.Fatalf("long value leaked as substring: %q", redacted)
	}
}

func TestWriteDiagnosticRedactsByConstruction(t *testing.T) {
	t.Parallel()

	// A diagnostic call site that never called redactCLIError must still not
	// echo a caller-supplied value.
	args := []string{"phase1", "verify", "--key", "SENSITIVE-SENTINEL"}
	var out bytes.Buffer
	writeDiagnostic(&out, args, "error: open %s: no such file\n", "SENSITIVE-SENTINEL")
	if strings.Contains(out.String(), "SENSITIVE-SENTINEL") {
		t.Fatalf("writeDiagnostic leaked an argument value: %q", out.String())
	}
	if !strings.Contains(out.String(), redactedCLIValue) {
		t.Fatalf("writeDiagnostic did not mark the redaction: %q", out.String())
	}
}
