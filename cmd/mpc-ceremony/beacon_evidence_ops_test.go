package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proof-tool/internal/mpcceremony"
)

const commandQuicknetRound = `{"round":31000000,"randomness":"b83329945edcd19e76cdc0f8c44afcac406df603247ef357b93924673da8f9a5","signature":"a43f1eab1da28f3f95220709d12a61cc0f1fed4a9ffe7cb4948e3bc3777de670e837501cdc70c903a6189c0639871985"}`

func TestPrepareBeaconEvidenceVerifiesDistinctOperatorsAndRawResponses(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	definition, _, coordinatorKey := decisionSignFixture(t)
	trust := trustOptionsFromArgs(t, writeInspectionTrustFixture(t, root, definition, coordinatorKey))
	roundTime, err := mpcceremony.QuicknetRoundTime(31_000_000)
	if err != nil {
		t.Fatal(err)
	}
	closeRecord, err := mpcceremony.NewCloseRecord(mpcceremony.CloseRecord{
		CeremonyID: definition.CeremonyID, Phase: mpcceremony.Phase1,
		PhaseID: "sha256:" + strings.Repeat("44", 32), FinalIndex: 1,
		FinalPayload: commandArtifact("phase1/final.bin", "final"), ChainHeadID: "sha256:" + strings.Repeat("55", 32),
		AcceptedParticipants: []string{definition.Roster[0].Identity.ID}, BeaconProvider: definition.BeaconPolicy.Provider,
		BeaconNetwork: definition.BeaconPolicy.Network, BeaconRound: 31_000_000, BeaconNotBefore: roundTime.Format(time.RFC3339),
		ClosedAt: roundTime.Add(-25 * time.Hour).Format(time.RFC3339), CoordinatorID: definition.Coordinator.ID,
		CoordinatorKeyID: definition.Coordinator.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeBytes, closeSignature, err := mpcceremony.SignRecord(closeRecord, definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}
	closure := filepath.Join(root, "phase1", "closure", "record.json")
	closureSignature := filepath.Join(root, "phase1", "closure", "record.sig")
	if err := os.MkdirAll(filepath.Dir(closure), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, closure, closeBytes, 0o600)
	writeDecisionTestFile(t, closureSignature, closeSignature, 0o600)
	if err := os.MkdirAll(filepath.Join(root, "phase1", "beacon", "raw"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"protocol-labs.json", "cloudflare.json"} {
		writeDecisionTestFile(t, filepath.Join(root, "phase1", "beacon", "raw", name), []byte(commandQuicknetRound), 0o600)
	}
	inputs := beaconObservationInputSet{Schema: beaconObservationInputSchema, Observations: []beaconObservationInput{
		{RelayID: "cloudflare-relay", OperatorID: "cloudflare", Endpoint: "https://drand.cloudflare.com", RawResponseName: "phase1/beacon/raw/cloudflare.json", RetrievedAt: roundTime.Add(time.Minute).Format(time.RFC3339)},
		{RelayID: "protocol-labs-relay", OperatorID: "protocol-labs", Endpoint: "https://api.drand.sh", RawResponseName: "phase1/beacon/raw/protocol-labs.json", RetrievedAt: roundTime.Add(time.Minute).Format(time.RFC3339)},
	}}
	inputBytes, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "observations.json")
	writeDecisionTestFile(t, inputPath, inputBytes, 0o600)
	options := OpsPrepareBeaconEvidenceOptions{CeremonyPath: trust.CeremonyPath, CeremonySignaturePath: trust.CeremonySignaturePath, CoordinatorPublicKeyFile: trust.CoordinatorPublicKeyFile, TranscriptRoot: root, ClosurePath: closure, ClosureSignaturePath: closureSignature, ObservationsPath: inputPath, RecordedAt: roundTime.Add(2 * time.Minute).Format(time.RFC3339), OutDir: filepath.Join(root, "prepared")}
	result, err := executeOpsPrepareBeaconEvidence(options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.Outputs["canonical"])
	if err != nil {
		t.Fatal(err)
	}
	var evidence mpcceremony.MultiRelayBeaconEvidence
	if err := mpcceremony.UnmarshalCanonical(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Observations) != 2 || evidence.Observations[0].RelayID != "cloudflare-relay" || evidence.Observations[1].RelayID != "protocol-labs-relay" {
		t.Fatalf("unexpected canonical observations: %#v", evidence.Observations)
	}

	inputs.Observations[1].OperatorID = inputs.Observations[0].OperatorID
	inputBytes, _ = json.Marshal(inputs)
	writeDecisionTestFile(t, inputPath, inputBytes, 0o600)
	options.OutDir = filepath.Join(root, "rejected")
	if _, err := executeOpsPrepareBeaconEvidence(options); err == nil {
		t.Fatal("same-operator relay observations unexpectedly accepted")
	}
}
