// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"proof-tool/internal/mpcceremony"
)

func TestInspectCommandsAuthenticateSignedDefinitionAndChain(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinatorKey := decisionSignFixture(t)
	definitionBytes, definitionSignature, err := mpcceremony.SignRecord(
		definition,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	phaseID, err := mpcceremony.ComputePhaseID(
		definition.CeremonyID,
		mpcceremony.Phase1,
		definition.Phase1Genesis,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := mpcceremony.NewChain(
		definition.CeremonyID,
		mpcceremony.Phase1,
		phaseID,
		definition.Phase1Genesis,
	)
	if err != nil {
		t.Fatal(err)
	}
	chainBytes, chainSignature, err := mpcceremony.SignRecord(
		chain,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	ceremonyPath := filepath.Join(root, "ceremony.json")
	ceremonySignaturePath := filepath.Join(root, "ceremony.sig")
	coordinatorPublicKeyPath := filepath.Join(root, "coordinator-public-key.hex")
	chainPath := filepath.Join(root, "phase1", "chain-0000.json")
	chainSignaturePath := filepath.Join(root, "phase1", "chain-0000.sig")
	if err := os.MkdirAll(filepath.Dir(chainPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, ceremonyPath, definitionBytes, 0o600)
	writeDecisionTestFile(t, ceremonySignaturePath, definitionSignature, 0o600)
	writeDecisionTestFile(t, coordinatorPublicKeyPath, []byte(definition.Coordinator.Ed25519PublicKeyHex+"\n"), 0o600)
	writeDecisionTestFile(t, chainPath, chainBytes, 0o600)
	writeDecisionTestFile(t, chainSignaturePath, chainSignature, 0o600)

	trustArgs := []string{
		"--ceremony", ceremonyPath,
		"--ceremony-signature", ceremonySignaturePath,
		"--coordinator-public-key-file", coordinatorPublicKeyPath,
	}
	tests := []struct {
		name    string
		args    []string
		command Command
		check   func(CommandResult) bool
	}{
		{
			name:    "definition",
			args:    append([]string{"--format", "json", "inspect", "definition"}, trustArgs...),
			command: CommandInspectDefinition,
			check: func(result CommandResult) bool {
				return result.DefinitionInspection != nil &&
					result.DefinitionInspection.CeremonyID == definition.CeremonyID &&
					reflect.DeepEqual(result.DefinitionInspection.Phase1Participants, definition.Phase1Policy.Participants)
			},
		},
		{
			name: "chain",
			args: append(
				append([]string{"--format", "json", "inspect", "chain"}, trustArgs...),
				"--transcript-root", root,
				"--chain", chainPath,
				"--chain-signature", chainSignaturePath,
			),
			command: CommandInspectChain,
			check: func(result CommandResult) bool {
				return result.ChainInspection != nil &&
					result.ChainInspection.CeremonyID == definition.CeremonyID &&
					result.ChainInspection.AcceptedCount == 0 &&
					len(result.ChainInspection.Artifacts) == 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runCLI(context.Background(), test.args, &stdout, &stderr, workflowExecutor{}); code != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			var result CommandResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !result.OK || result.Command != test.command || !test.check(result) {
				t.Fatalf("result = %#v", result)
			}
		})
	}

	writeDecisionTestFile(t, chainPath, append(chainBytes, '\n'), 0o600)
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), tests[1].args, &stdout, &stderr, workflowExecutor{}); code == 0 {
		t.Fatalf("tampered chain was accepted: stdout = %q", stdout.String())
	}
}

func TestInspectParticipantMatchesRosterPositionsWithoutExposingPrivateKey(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinatorKey := decisionSignFixture(t)
	definition.Mode = mpcceremony.ModeRehearsal
	definition.Phase2Policy.Participants = []string{"participant-01", "participant-03"}
	definition.Phase2Policy.Minimum = 2
	var err error
	definition, err = mpcceremony.FinalizeCeremonyDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	trustArgs := writeInspectionTrustFixture(t, root, definition, coordinatorKey)
	participantKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize))
	seedHex := hex.EncodeToString(participantKey.Seed())
	keyPath := filepath.Join(root, "participant-02.private.hex")
	writeDecisionTestFile(t, keyPath, []byte(seedHex+"\n"), 0o600)

	args := append(
		append([]string{"--format", "json", "inspect", "participant"}, trustArgs...),
		"--participant-signing-key", keyPath,
	)
	var stdout, stderr bytes.Buffer
	if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), seedHex) || strings.Contains(stdout.String(), keyPath) {
		t.Fatal("participant inspection output exposed private key material or its path")
	}
	if !strings.Contains(stdout.String(), `"phase2_position":null`) {
		t.Fatalf("absent phase position was not explicit null: %s", stdout.String())
	}
	var result CommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	inspection := result.ParticipantInspection
	if inspection == nil || inspection.Schema != participantInspectionSchema ||
		inspection.ParticipantID != "participant-02" ||
		inspection.KeyID != definition.Roster[1].Identity.KeyID ||
		inspection.PublicKeyFingerprint != definition.Roster[1].Identity.PublicKeyFingerprint ||
		inspection.Phase1Position == nil || *inspection.Phase1Position != 2 ||
		inspection.Phase2Position != nil {
		t.Fatalf("participant inspection = %#v", inspection)
	}
}

func TestInspectEnrollmentAuthenticatesWitnessAndMirrorProofs(t *testing.T) {
	for _, test := range []struct {
		role mpcceremony.EnrollmentRole
		id   string
		fill byte
	}{
		{role: mpcceremony.EnrollmentPublicWitness, id: "public-witness-01", fill: 0x91},
		{role: mpcceremony.EnrollmentMirrorOperator, id: "mirror-operator-01", fill: 0xa1},
	} {
		t.Run(string(test.role), func(t *testing.T) {
			root := t.TempDir()
			definition, _, coordinatorKey := decisionSignFixture(t)
			trustArgs := writeInspectionTrustFixture(t, root, definition, coordinatorKey)
			record, recordBytes, signatureBytes, _ := commandSignedExternalEnrollment(
				t, definition, test.role, test.id, test.fill,
			)
			recordPath := filepath.Join(root, test.id+".json")
			signaturePath := filepath.Join(root, test.id+".sig")
			writeDecisionTestFile(t, recordPath, recordBytes, 0o600)
			writeDecisionTestFile(t, signaturePath, signatureBytes, 0o600)
			args := append(
				append([]string{"--format", "json", "inspect", "enrollment"}, trustArgs...),
				"--enrollment", recordPath,
				"--enrollment-signature", signaturePath,
			)
			var stdout, stderr bytes.Buffer
			if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			var result CommandResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			inspection := result.EnrollmentInspection
			if inspection == nil || inspection.Schema != enrollmentInspectionSchema ||
				inspection.CeremonyID != definition.CeremonyID || inspection.Identity != record.Identity ||
				inspection.Role != test.role || inspection.RoleIndex != 1 ||
				inspection.IndependenceDisclosure != record.IndependenceDisclosure {
				t.Fatalf("enrollment inspection = %#v", inspection)
			}

			writeDecisionTestFile(t, recordPath, append(recordBytes, '\n'), 0o600)
			stdout.Reset()
			stderr.Reset()
			if code := runCLI(context.Background(), args, &stdout, &stderr, workflowExecutor{}); code == 0 {
				t.Fatal("altered enrollment unexpectedly accepted")
			}
		})
	}
}

func writeInspectionTrustFixture(
	t *testing.T,
	root string,
	definition mpcceremony.CeremonyDefinition,
	coordinatorKey ed25519.PrivateKey,
) []string {
	t.Helper()
	definitionBytes, signatureBytes, err := mpcceremony.SignRecord(
		definition,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	ceremonyPath := filepath.Join(root, "ceremony.json")
	signaturePath := filepath.Join(root, "ceremony.sig")
	publicKeyPath := filepath.Join(root, "coordinator-public-key.hex")
	writeDecisionTestFile(t, ceremonyPath, definitionBytes, 0o600)
	writeDecisionTestFile(t, signaturePath, signatureBytes, 0o600)
	writeDecisionTestFile(t, publicKeyPath, []byte(definition.Coordinator.Ed25519PublicKeyHex+"\n"), 0o600)
	return []string{
		"--ceremony", ceremonyPath,
		"--ceremony-signature", signaturePath,
		"--coordinator-public-key-file", publicKeyPath,
	}
}

func commandSignedExternalEnrollment(
	t *testing.T,
	definition mpcceremony.CeremonyDefinition,
	role mpcceremony.EnrollmentRole,
	id string,
	fill byte,
) (mpcceremony.EnrollmentRecord, []byte, []byte, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	identity, err := mpcceremony.NewIdentity(
		id,
		"Test "+id,
		id+"-key",
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	definitionBytes, err := mpcceremony.MarshalCanonical(definition)
	if err != nil {
		t.Fatal(err)
	}
	record, err := mpcceremony.NewEnrollmentRecord(
		definition,
		definitionBytes,
		identity,
		role,
		1,
		mpcceremony.ArtifactRef{
			Name:   "disclosures/" + id + ".json",
			Digest: mpcceremony.NewDigest([]byte("independent " + id)),
		},
		"2026-07-23T12:00:01Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, signatureBytes, err := mpcceremony.SignRecord(record, identity.KeyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return record, recordBytes, signatureBytes, privateKey
}

func TestInspectDefinitionProjectsRelayView(t *testing.T) {
	definition := mpcceremony.CeremonyDefinition{
		CeremonyID: "ceremony-id",
		Mode:       mpcceremony.ModeProduction,
		Phase1Policy: mpcceremony.PhasePolicy{
			Participants: []string{"p1", "p2"},
		},
		Phase2Policy: mpcceremony.PhasePolicy{
			Participants: []string{"p2"},
		},
		Circuit: mpcceremony.CircuitBinding{
			R1CS: mpcceremony.ArtifactRef{Name: "ownership-destination.ccs"},
		},
	}

	got := inspectDefinition(definition)
	if got.Schema != definitionInspectionSchema || got.CeremonyID != definition.CeremonyID || got.Mode != definition.Mode {
		t.Fatalf("inspection identity = %#v", got)
	}
	if !reflect.DeepEqual(got.Phase1Participants, []string{"p1", "p2"}) ||
		!reflect.DeepEqual(got.Phase2Participants, []string{"p2"}) {
		t.Fatalf("inspection schedules = %#v / %#v", got.Phase1Participants, got.Phase2Participants)
	}
	if got.R1CS != definition.Circuit.R1CS {
		t.Fatalf("inspection r1cs = %#v", got.R1CS)
	}

	definition.Phase1Policy.Participants[0] = "changed"
	if got.Phase1Participants[0] != "p1" {
		t.Fatal("inspection retained mutable definition schedule storage")
	}
}

func TestInspectChainProjectsStableArtifactOrder(t *testing.T) {
	ref := func(name string) mpcceremony.ArtifactRef { return mpcceremony.ArtifactRef{Name: name} }
	chain := mpcceremony.Chain{
		CeremonyID: "ceremony-id",
		Phase:      mpcceremony.Phase1,
		Genesis:    ref("genesis"),
		Records: []mpcceremony.ChainRecord{{
			Index:                1,
			RecordID:             "record-id",
			ParticipantID:        "p1",
			OutputPayload:        ref("output"),
			Attestation:          ref("attestation"),
			AttestationSignature: ref("attestation.sig"),
			Erasure:              ref("erasure"),
			ErasureSignature:     ref("erasure.sig"),
			Verification:         ref("verification"),
		}},
	}

	got := inspectChain(chain)
	if got.Schema != chainInspectionSchema || got.AcceptedCount != 1 || len(got.Records) != 1 {
		t.Fatalf("inspection = %#v", got)
	}
	wantNames := []string{"genesis", "output", "attestation", "attestation.sig", "erasure", "erasure.sig", "verification"}
	for index, want := range wantNames {
		if got.Artifacts[index].Name != want {
			t.Fatalf("artifact %d = %q, want %q", index, got.Artifacts[index].Name, want)
		}
	}
	if !reflect.DeepEqual(got.Records[0].Artifacts, got.Artifacts[1:]) {
		t.Fatalf("record artifacts = %#v, want %#v", got.Records[0].Artifacts, got.Artifacts[1:])
	}
}
