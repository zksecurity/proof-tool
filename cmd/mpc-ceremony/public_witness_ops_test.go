package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proof-tool/internal/mpcceremony"
)

func TestPreparePublicWitnessReceiptAuthenticatesClosureEnrollmentAndOutput(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinatorKey := decisionSignFixture(t)
	trustArgs := writeInspectionTrustFixture(t, root, definition, coordinatorKey)
	trust := trustOptionsFromArgs(t, trustArgs)

	round := uint64(40_000_000)
	roundTime, err := mpcceremony.QuicknetRoundTime(round)
	if err != nil {
		t.Fatal(err)
	}
	closeRecord, err := mpcceremony.NewCloseRecord(mpcceremony.CloseRecord{
		CeremonyID:           definition.CeremonyID,
		Phase:                mpcceremony.Phase1,
		PhaseID:              "sha256:" + strings.Repeat("44", 32),
		FinalIndex:           1,
		FinalPayload:         commandArtifact("phase1/final.bin", "final"),
		ChainHeadID:          "sha256:" + strings.Repeat("55", 32),
		AcceptedParticipants: []string{definition.Roster[0].Identity.ID},
		BeaconProvider:       definition.BeaconPolicy.Provider,
		BeaconNetwork:        definition.BeaconPolicy.Network,
		BeaconRound:          round,
		BeaconNotBefore:      roundTime.Format(time.RFC3339),
		ClosedAt:             roundTime.Add(-25 * time.Hour).Format(time.RFC3339),
		CoordinatorID:        definition.Coordinator.ID,
		CoordinatorKeyID:     definition.Coordinator.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeBytes, closeSignature, err := mpcceremony.SignRecord(
		closeRecord,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	closurePath := filepath.Join(root, "phase1", "closure", "record.json")
	closureSignaturePath := filepath.Join(root, "phase1", "closure", "record.sig")
	if err := os.MkdirAll(filepath.Dir(closurePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, closurePath, closeBytes, 0o600)
	writeDecisionTestFile(t, closureSignaturePath, closeSignature, 0o600)

	witness, witnessBytes, witnessSignature, _ := commandSignedExternalEnrollment(
		t,
		definition,
		mpcceremony.EnrollmentPublicWitness,
		"public-witness-01",
		0x91,
	)
	witnessPath := filepath.Join(root, "operational", "enrollments", "public-witness-01.json")
	witnessSignaturePath := filepath.Join(root, "operational", "enrollments", "public-witness-01.sig")
	if err := os.MkdirAll(filepath.Dir(witnessPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, witnessPath, witnessBytes, 0o600)
	writeDecisionTestFile(t, witnessSignaturePath, witnessSignature, 0o600)

	location := "https://independent.example/phase1/closure.json"
	options := OpsPreparePublicWitnessReceiptOptions{
		CeremonyPath:                   trust.CeremonyPath,
		CeremonySignaturePath:          trust.CeremonySignaturePath,
		CoordinatorPublicKeyFile:       trust.CoordinatorPublicKeyFile,
		TranscriptRoot:                 root,
		ClosurePath:                    closurePath,
		ClosureSignaturePath:           closureSignaturePath,
		WitnessEnrollmentPath:          witnessPath,
		WitnessEnrollmentSignaturePath: witnessSignaturePath,
		PublicationLocation:            location,
		ObservedAt:                     roundTime.Add(-24 * time.Hour).Format(time.RFC3339),
		OutDir:                         filepath.Join(root, "witness-signing"),
	}
	result, err := executeOpsPreparePublicWitnessReceipt(options)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(result.Outputs["canonical"])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte(location)) {
		t.Fatal("canonical receipt contains cleartext publication location")
	}
	var receipt mpcceremony.PublicWitnessReceipt
	if err := mpcceremony.UnmarshalCanonical(canonical, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Witness != witness.Identity || receipt.Closure.Name != "phase1/closure/record.json" ||
		receipt.ObservedAt != options.ObservedAt {
		t.Fatalf("receipt = %#v", receipt)
	}
	requestBytes, err := os.ReadFile(result.Outputs["signing_request"])
	if err != nil {
		t.Fatal(err)
	}
	var request mpcceremony.OperationalSigningRequest
	if err := mpcceremony.UnmarshalCanonical(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	if request.RecordType != mpcceremony.RecordPublicWitness {
		t.Fatalf("signing request record type = %q", request.RecordType)
	}

	canonicalBefore := append([]byte(nil), canonical...)
	if _, err := executeOpsPreparePublicWitnessReceipt(options); err == nil {
		t.Fatal("existing output directory unexpectedly replaced")
	}
	canonicalAfter, err := os.ReadFile(result.Outputs["canonical"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonicalBefore, canonicalAfter) {
		t.Fatal("failed retry changed existing canonical receipt")
	}

	mirror, mirrorBytes, mirrorSignature, _ := commandSignedExternalEnrollment(
		t,
		definition,
		mpcceremony.EnrollmentMirrorOperator,
		"mirror-operator-01",
		0xa1,
	)
	_ = mirror
	writeDecisionTestFile(t, witnessPath, mirrorBytes, 0o600)
	writeDecisionTestFile(t, witnessSignaturePath, mirrorSignature, 0o600)
	wrongRole := options
	wrongRole.OutDir = filepath.Join(root, "wrong-role")
	if _, err := executeOpsPreparePublicWitnessReceipt(wrongRole); err == nil {
		t.Fatal("mirror enrollment unexpectedly prepared a witness receipt")
	}
	if _, err := os.Stat(wrongRole.OutDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-role preparation left output directory: %v", err)
	}

	overlap := witness
	overlap.Identity = definition.Coordinator
	overlapBytes, overlapSignature, err := mpcceremony.SignRecord(
		overlap,
		definition.Coordinator.KeyID,
		coordinatorKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, witnessPath, overlapBytes, 0o600)
	writeDecisionTestFile(t, witnessSignaturePath, overlapSignature, 0o600)
	overlapOptions := options
	overlapOptions.OutDir = filepath.Join(root, "overlap")
	if _, err := executeOpsPreparePublicWitnessReceipt(overlapOptions); err == nil {
		t.Fatal("ceremony actor unexpectedly accepted as public witness")
	}
}

func TestPreparePublicWitnessReceiptRejectsAlteredAndWronglySignedClosure(t *testing.T) {
	root := t.TempDir()
	definition, _, coordinatorKey := decisionSignFixture(t)
	trust := trustOptionsFromArgs(t, writeInspectionTrustFixture(t, root, definition, coordinatorKey))
	round := uint64(40_000_000)
	roundTime, _ := mpcceremony.QuicknetRoundTime(round)
	closeRecord, err := mpcceremony.NewCloseRecord(mpcceremony.CloseRecord{
		CeremonyID:           definition.CeremonyID,
		Phase:                mpcceremony.Phase1,
		PhaseID:              "sha256:" + strings.Repeat("44", 32),
		FinalIndex:           1,
		FinalPayload:         commandArtifact("phase1/final.bin", "final"),
		ChainHeadID:          "sha256:" + strings.Repeat("55", 32),
		AcceptedParticipants: []string{definition.Roster[0].Identity.ID},
		BeaconProvider:       definition.BeaconPolicy.Provider,
		BeaconNetwork:        definition.BeaconPolicy.Network,
		BeaconRound:          round,
		BeaconNotBefore:      roundTime.Format(time.RFC3339),
		ClosedAt:             roundTime.Add(-25 * time.Hour).Format(time.RFC3339),
		CoordinatorID:        definition.Coordinator.ID,
		CoordinatorKeyID:     definition.Coordinator.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeBytes, closeSignature, err := mpcceremony.SignRecord(closeRecord, definition.Coordinator.KeyID, coordinatorKey)
	if err != nil {
		t.Fatal(err)
	}
	closurePath := filepath.Join(root, "phase1", "closure", "record.json")
	closureSignaturePath := filepath.Join(root, "phase1", "closure", "record.sig")
	if err := os.MkdirAll(filepath.Dir(closurePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, closurePath, closeBytes, 0o600)
	writeDecisionTestFile(t, closureSignaturePath, closeSignature, 0o600)
	_, witnessBytes, witnessSignature, witnessKey := commandSignedExternalEnrollment(
		t, definition, mpcceremony.EnrollmentPublicWitness, "public-witness-01", 0x91,
	)
	witnessPath := filepath.Join(root, "witness.json")
	witnessSignaturePath := filepath.Join(root, "witness.sig")
	writeDecisionTestFile(t, witnessPath, witnessBytes, 0o600)
	writeDecisionTestFile(t, witnessSignaturePath, witnessSignature, 0o600)
	options := OpsPreparePublicWitnessReceiptOptions{
		CeremonyPath:                   trust.CeremonyPath,
		CeremonySignaturePath:          trust.CeremonySignaturePath,
		CoordinatorPublicKeyFile:       trust.CoordinatorPublicKeyFile,
		TranscriptRoot:                 root,
		ClosurePath:                    closurePath,
		ClosureSignaturePath:           closureSignaturePath,
		WitnessEnrollmentPath:          witnessPath,
		WitnessEnrollmentSignaturePath: witnessSignaturePath,
		PublicationLocation:            "https://independent.example/closure",
		ObservedAt:                     roundTime.Add(-24 * time.Hour).Format(time.RFC3339),
		OutDir:                         filepath.Join(root, "altered-output"),
	}

	writeDecisionTestFile(t, closurePath, append(closeBytes, '\n'), 0o600)
	if _, err := executeOpsPreparePublicWitnessReceipt(options); err == nil {
		t.Fatal("altered closure unexpectedly accepted")
	}
	writeDecisionTestFile(t, closurePath, closeBytes, 0o600)
	_, wrongSignature, err := mpcceremony.SignRecord(closeRecord, "public-witness-01-key", witnessKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDecisionTestFile(t, closureSignaturePath, wrongSignature, 0o600)
	if _, err := executeOpsPreparePublicWitnessReceipt(options); err == nil {
		t.Fatal("closure signed by witness key unexpectedly accepted")
	}
	if _, err := os.Stat(options.OutDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected closures left output directory: %v", err)
	}
}

func TestWriteOperationalSigningExportCleansPartialPublication(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "partial")
	if _, _, err := writeOperationalSigningExport(outDir, []byte("canonical"), nil); err == nil {
		t.Fatal("empty signing request unexpectedly exported")
	}
	if _, err := os.Stat(outDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial signing export was not removed: %v", err)
	}
}

func trustOptionsFromArgs(t *testing.T, args []string) InspectDefinitionOptions {
	t.Helper()
	invocation, err := parseInvocation(append([]string{"inspect", "definition"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	return invocation.Options.(InspectDefinitionOptions)
}

func commandArtifact(name, contents string) mpcceremony.ArtifactRef {
	return mpcceremony.ArtifactRef{Name: name, Digest: mpcceremony.NewDigest([]byte(contents))}
}
