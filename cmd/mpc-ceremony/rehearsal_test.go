// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
	"proof-tool/internal/mpcrehearsal"
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
	if options.CreatedAt != "2026-08-20T06:00:00Z" || options.OutDir != "/secure/rehearsal" || options.BeaconLeadSeconds != rehearsalBeaconLeadSeconds {
		t.Fatalf("options = %+v", options)
	}

	custom, err := parseInvocation([]string{
		"rehearsal", "init",
		"--created-at", "2026-08-20T06:00:00Z",
		"--out-dir", "/secure/rehearsal",
		"--beacon-lead-seconds", "12",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := custom.Options.(RehearsalInitOptions).BeaconLeadSeconds; got != 12 {
		t.Fatalf("custom beacon lead = %d, want 12", got)
	}

	for name, args := range map[string][]string{
		"missing creation time": {"rehearsal", "init", "--out-dir", "/secure/rehearsal"},
		"missing output":        {"rehearsal", "init", "--created-at", "2026-08-20T06:00:00Z"},
		"short beacon lead": {
			"rehearsal", "init", "--created-at", "2026-08-20T06:00:00Z",
			"--out-dir", "/secure/rehearsal", "--beacon-lead-seconds", "11",
		},
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

func TestInitExactRetryAcceptsAtomicallyPublishedTree(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "fixture")
	if err := mpcrehearsal.Generate(root, rehearsalParticipantCount, rehearsalBeaconLeadSeconds); err != nil {
		t.Fatal(err)
	}
	participantsPath := filepath.Join(root, "config", "participants.json")
	participants, err := mpcceremony.LoadInitParticipants(participantsPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mpcceremony.LoadInitPolicy(filepath.Join(root, "config", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := mpcceremony.CompileForKeyVersion(rehearsalKeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	options := mpcceremony.InitFilesOptions{
		RootDir: filepath.Join(root, "public"), Circuit: circuit,
		CoordinatorPrivateKeyPath: filepath.Join(root, "keys", "coordinator.ed25519.private.hex"),
		Definition: mpcceremony.DefinitionOptions{
			Mode: mpcceremony.ModeRehearsal, CreatedAt: "2026-09-12T00:00:00Z", SessionNonceHex: strings.Repeat("5a", 32),
			Software: mpcceremony.SoftwareBinding{
				ProofToolVersion: "test", GnarkVersion: mpcceremony.GnarkVersion, GnarkCryptoVersion: mpcceremony.GnarkCryptoVersion,
				DrandVersion: mpcceremony.DrandVersion, GoVersion: "go-test", GoOS: "linux", GoArch: "amd64", GoAMD64: "v1",
				Compiler: "gc", BuildMode: "exe", TrimPath: true, SourceCommit: strings.Repeat("6b", 20),
				ToolBinary: mpcceremony.NewDigest([]byte("test mpc-ceremony binary")),
			},
			Coordinator: participants.Coordinator, ReleaseSigner: participants.ReleaseSigner, Auditors: participants.Auditors, Roster: participants.Roster,
			Phase1Policy: policy.Phase1Policy, Phase2Policy: policy.Phase2Policy, BeaconPolicy: policy.BeaconPolicy,
		},
	}
	first, err := mpcceremony.InitializeCeremonyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mpcceremony.InitializeCeremonyFiles(options)
	if err != nil {
		t.Fatal("exact initialization retry rejected the committed tree:", err)
	}
	if first.Definition.CeremonyID != second.Definition.CeremonyID {
		t.Fatal("exact initialization retry changed the ceremony")
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
