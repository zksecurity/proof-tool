// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestParseRehearsalInitIsNarrowAndExplicit(t *testing.T) {
	t.Parallel()

	invocation, err := parseInvocation([]string{
		"rehearsal", "init",
		"--created-at", "2026-08-20T06:00:00Z",
		"--out-dir", "/secure/rehearsal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Command != CommandRehearsalInit {
		t.Fatalf("command = %q", invocation.Command)
	}
	options := invocation.Options.(RehearsalInitOptions)
	if options.CreatedAt != "2026-08-20T06:00:00Z" || options.OutDir != "/secure/rehearsal" {
		t.Fatalf("options = %+v", options)
	}

	for name, args := range map[string][]string{
		"missing creation time": {"rehearsal", "init", "--out-dir", "/secure/rehearsal"},
		"missing output":        {"rehearsal", "init", "--created-at", "2026-08-20T06:00:00Z"},
		"production mode": {
			"rehearsal", "init", "--created-at", "2026-08-20T06:00:00Z",
			"--out-dir", "/secure/rehearsal", "--mode", "production",
		},
		"production circuit": {
			"rehearsal", "init", "--created-at", "2026-08-20T06:00:00Z",
			"--out-dir", "/secure/rehearsal", "--key-version", supportedKeyVersion,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseInvocation(args); err == nil {
				t.Fatal("unsafe rehearsal initializer invocation was accepted")
			}
		})
	}
}

func TestRehearsalInitHelpLabelsOutputAsNonProduction(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	if err := writeUsage(&output, []string{"rehearsal", "init"}); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(output.String())
	if !strings.Contains(lower, "rehearsal-tiny-v1") || !strings.Contains(lower, "not production") {
		t.Fatalf("help does not state the rehearsal boundary: %q", output.String())
	}
}
