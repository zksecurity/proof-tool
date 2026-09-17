package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	m "proof-tool/internal/mpcceremony"
)

func TestContributionInventoryV4CommandSurface(t *testing.T) {
	args := []string{"--ceremony", "ceremony.json", "--ceremony-signature", "ceremony.sig", "--coordinator-public-key-file", "coordinator.hex", "--transcript-root", "transcript", "--chain", "transcript/phase1/chain-0000.json", "--chain-signature", "transcript/phase1/chain-0000.sig", "--scope", "scope.json", "--candidate-dir", "candidate"}
	o, err := parseContributionInventoryV4(args)
	if err != nil || o.ScopePath != "scope.json" || o.CandidateDir != "candidate" {
		t.Fatal(o, err)
	}
	for n := 0; n < len(args); n += 2 {
		missing := append(append([]string{}, args[:n]...), args[n+2:]...)
		if _, err := parseContributionInventoryV4(missing); err == nil {
			t.Fatalf("accepted missing %s", args[n])
		}
	}
	for _, secret := range []string{"--participant-signing-key", "--coordinator-signing-key", "--signing-key"} {
		if _, err := parseContributionInventoryV4(append(append([]string{}, args...), secret, "private.hex")); err == nil {
			t.Fatal("read-only inspection accepted secret input", secret)
		}
	}
	invocation, err := parseInvocation(append([]string{"--format", "json", "inspect", "contribution-inventory-v4"}, args...))
	if err != nil || invocation.Command != CommandInspectContributionInventoryV4 || !reflect.DeepEqual(invocation.Options, o) {
		t.Fatal(invocation, err)
	}
	if !strings.Contains(commandHelp["inspect contribution-inventory-v4"], "Does not verify mathematics") {
		t.Fatal("missing narrow inspection claim")
	}
}

// Called by the Linux approved-executable test after real tiny initialization.
func checkContributionInventoryExecutableV4(t *testing.T, executable, root string, d m.CeremonyDefinition, chain m.Chain) {
	t.Helper()
	dir := filepath.Join(root, "inspection-candidate")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) { t.Helper(); writeDecisionTestFile(t, filepath.Join(dir, name), b, 0600) }
	sign := func(name string, v any, keyID string, key ed25519.PrivateKey) {
		t.Helper()
		b, s, err := m.SignRecord(v, keyID, key)
		if err != nil {
			t.Fatal(err)
		}
		write(name+".json", b)
		write(name+".sig", s)
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		t.Fatal(err)
	}
	previous, err := chain.HeadPayload()
	if err != nil {
		t.Fatal(err)
	}
	p := d.Roster[0].Identity
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	payload := []byte("signature-and-digest inspection deliberately does not prove contribution mathematics")
	a, err := m.NewContributionAttestation(m.ContributionAttestation{CeremonyID: d.CeremonyID, Phase: m.Phase1, PhaseID: chain.PhaseID, Index: 1, ParticipantID: p.ID, ParticipantKeyID: p.KeyID, PreviousPayload: previous, PreviousAcceptanceID: head, OutputPayload: m.ArtifactRef{Name: "phase1/contributions/0001/contribution.bin", Digest: m.NewDigest(payload)}, ToolBinary: d.Software.ToolBinary, SourceCommit: d.Software.SourceCommit, GnarkVersion: d.Software.GnarkVersion, GnarkCryptoVersion: d.Software.GnarkCryptoVersion, DrandVersion: d.Software.DrandVersion, Environment: m.ContributionEnvironment{OS: "linux", Architecture: "arm64", EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}, ContributedAt: "2026-09-16T00:01:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := m.NewErasureAttestation(m.ErasureAttestation{CeremonyID: a.CeremonyID, Phase: a.Phase, PhaseID: a.PhaseID, Index: a.Index, ParticipantID: p.ID, ParticipantKeyID: p.KeyID, ContributionAttestationID: a.AttestationID, OutputPayload: a.OutputPayload, DestroyedAt: "2026-09-16T00:02:00Z", ProcessTerminated: true, EphemeralEnvironmentRemoved: true, NoDeliberateCopiesConfirmed: true, HostRemnantsNotExcluded: true})
	if err != nil {
		t.Fatal(err)
	}
	write("contribution.bin", payload)
	sign("attestation", a, p.KeyID, key)
	scope := m.ContributionScope{CeremonyID: d.CeremonyID, Phase: m.Phase1, Index: 1, ParticipantID: p.ID, ParentHeadID: head}
	b, err := m.MarshalCanonical(scope)
	if err != nil {
		t.Fatal(err)
	}
	write("scope.json", b)
	args := []string{"--format", "json", "inspect", "contribution-inventory-v4", "--ceremony", filepath.Join(root, "ceremony.json"), "--ceremony-signature", filepath.Join(root, "ceremony.sig"), "--coordinator-public-key-file", filepath.Join(root, "coordinator-public-key.hex"), "--transcript-root", root, "--chain", filepath.Join(root, "phase1/chain-0000.json"), "--chain-signature", filepath.Join(root, "phase1/chain-0000.sig"), "--scope", filepath.Join(dir, "scope.json"), "--candidate-dir", dir}
	generatedArgs := append([]string{}, args...)
	generatedArgs[3] = "computation-output-v4"
	generated := runCheckpointCommandExecutable(t, executable, generatedArgs).ComputationOutputV4
	if generated == nil || len(generated.Output.Files) != 3 || generated.CleanupVerified || generated.MathematicsReplayed || generated.PhysicalErasureVerified || generated.GlobalFreshnessVerified || !generated.SignaturesVerified || !generated.PayloadDigestVerified {
		t.Fatalf("wrong preliminary CLI result %+v", generated)
	}
	sign("erasure", e, p.KeyID, key)
	five := runCheckpointCommandExecutable(t, executable, args).ContributionInventoryV4
	if five == nil || five.Inventory.Complete == nil || five.Inventory.ComputedCandidateID == "" || five.Inventory.CandidateResultID != five.Inventory.ComputedCandidateID || five.MathematicsReplayed || five.GlobalFreshnessVerified || five.PhysicalErasureVerified || !five.SignaturesVerified || !five.PayloadDigestVerified {
		t.Fatalf("wrong CLI boundary %+v", five)
	}
	bad := d
	bad.Software.ToolBinary = m.NewDigest([]byte("unapproved executable"))
	bad.Software.Binaries = append([]m.SoftwareBinary{}, d.Software.Binaries...)
	for i := range bad.Software.Binaries {
		bad.Software.Binaries[i].ToolBinary = bad.Software.ToolBinary
	}
	bad, err = m.FinalizeCeremonyDefinition(bad)
	if err != nil {
		t.Fatal(err)
	}
	sign("unapproved", bad, d.Coordinator.KeyID, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	badArgs := append([]string{}, args...)
	for i := range badArgs {
		if badArgs[i] == "--ceremony" {
			badArgs[i+1] = filepath.Join(dir, "unapproved.json")
		}
		if badArgs[i] == "--ceremony-signature" {
			badArgs[i+1] = filepath.Join(dir, "unapproved.sig")
		}
	}
	assertCheckpointExecutableFails(t, executable, badArgs, "binary")
	badArgs[3] = "computation-output-v4"
	assertCheckpointExecutableFails(t, executable, badArgs, "binary")
}
