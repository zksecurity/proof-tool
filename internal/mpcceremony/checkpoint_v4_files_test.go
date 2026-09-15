package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCheckpointV4RealContributionTurn(t *testing.T) {
	if testing.Short() {
		t.Skip("real signed contribution checkpoint round trip")
	}
	if runtime.GOOS != "linux" {
		t.Skip("executable identity and contributor environment require Linux; run in Docker")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	helper := filepath.Join(t.TempDir(), "workflow")
	build := exec.Command("go", "build", "-o", helper, "./internal/mpcceremony/testdata/workflowhelper")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, scenario := range []struct{ name, mirrorMode, extra, rejection string }{
		{name: "observers-disabled", mirrorMode: "0"},
		{name: "observers-enabled", mirrorMode: "1"},
		{name: "audits-enabled", mirrorMode: "1", extra: "MPC_WORKFLOW_V4_AUDITS=1"},
		{name: "missing-witness", mirrorMode: "1", extra: "MPC_WORKFLOW_SKIP_WITNESS=1", rejection: "signed witness minimum"},
		{name: "missing-beacon-evidence", mirrorMode: "0", extra: "MPC_WORKFLOW_SKIP_BEACON_EVIDENCE=1", rejection: "multi-relay beacon evidence is required"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			outputRoot := filepath.Join(t.TempDir(), "ceremony-run")
			run := exec.Command(helper, outputRoot)
			run.Dir = repo
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "MPC_WORKFLOW_") || strings.HasPrefix(entry, "MPC_CEREMONY_TEST_") || strings.HasPrefix(entry, "PROOF_TOOL_TEST_") {
					continue
				}
				run.Env = append(run.Env, entry)
			}
			run.Env = append(run.Env, "MPC_WORKFLOW_CHECKPOINT_V4=1", "PROOF_TOOL_TEST_ZERO_ASSURANCE=1", "MPC_WORKFLOW_V4_MIRROR="+scenario.mirrorMode)
			if scenario.extra != "" {
				run.Env = append(run.Env, scenario.extra)
			}
			output, err := run.CombinedOutput()
			if scenario.rejection != "" {
				if err == nil || !strings.Contains(string(output), scenario.rejection) {
					t.Fatalf("expected %s: %v\n%s", scenario.rejection, err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("real checkpoint turn: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "V4 real phase1 turn passed") || !strings.Contains(string(output), "V4 phase2 and final candidate passed") {
				t.Fatalf("missing completion: %s", output)
			}
			if scenario.extra == "MPC_WORKFLOW_V4_AUDITS=1" && !strings.Contains(string(output), "V4 audits passed: two real replays") {
				t.Fatalf("missing audited completion: %s", output)
			}
			if !strings.Contains(string(output), "V4 operational bundle passed: deterministic checkpoint-only assembly") {
				t.Fatalf("missing bundle completion: %s", output)
			}
			if !strings.Contains(string(output), "V4 terminal branch passed: authenticated abort") {
				t.Fatalf("missing terminal completion: %s", output)
			}
			if !strings.Contains(string(output), "V4 final review passed: no contribution replay input") {
				t.Fatalf("missing final review completion: %s", output)
			}
			if scenario.name == "observers-disabled" {
				testV4CoherentInvalidPublicProof(t, filepath.Join(outputRoot, "ceremony"))
			}
		})
	}
}

func TestCheckpointV4LifecycleCanonicalPaths(t *testing.T) {
	for _, phase := range []Phase{Phase1, Phase2} {
		for _, directory := range []string{"closure", "beacon"} {
			base := string(phase) + "/" + directory + "/record"
			refs := SignedArtifactRefs{Record: inventoryTestRef(base+".json", []byte("record")), Signature: inventoryTestRef(base+".sig", []byte("signature"))}
			if err := requireLifecycleRecordPathV4(refs, phase, directory); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"record", "signature"} {
				bad := refs
				if field == "record" {
					bad.Record.Name = "other/record.json"
				} else {
					bad.Signature.Name = "other/record.sig"
				}
				if err := requireLifecycleRecordPathV4(bad, phase, directory); err == nil {
					t.Fatal("accepted misplaced lifecycle record")
				}
			}
		}
	}
}

func TestCheckpointV4Phase2CloseBoundary(t *testing.T) {
	first := CloseRecord{BeaconRound: 42}
	beacon := BeaconRecord{PublishedAt: "2023-08-23T15:11:30Z"}
	second := CloseRecord{BeaconRound: 43, ClosedAt: "2023-08-23T15:11:31Z"}
	if err := validatePhase2CloseBoundaryV4(first, beacon, second); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CloseRecord){
		"same round":         func(c *CloseRecord) { c.BeaconRound = 42 },
		"older round":        func(c *CloseRecord) { c.BeaconRound = 41 },
		"before publication": func(c *CloseRecord) { c.ClosedAt = "2023-08-23T15:11:29Z" },
		"same time":          func(c *CloseRecord) { c.ClosedAt = beacon.PublishedAt },
	} {
		t.Run(name, func(t *testing.T) {
			bad := second
			change(&bad)
			if err := validatePhase2CloseBoundaryV4(first, beacon, bad); err == nil {
				t.Fatal("invalid phase2 boundary accepted")
			}
		})
	}
}

func TestCheckpointV4RequiredEnrollmentsFitExistingBundle(t *testing.T) {
	// Coordinator, release signer, full roster, auditors, witnesses and mirrors.
	// External security-audit signoffs are later decision evidence, not enrollment.
	maximumRequired := 2 + MaxParticipants + 3*MaxAuditors
	if maximumRequired > 128 {
		t.Fatalf("maximum required enrollments %d exceeds bundle capacity", maximumRequired)
	}
}

func putCheckpointTestFileV4(t *testing.T, root, name string, data []byte) ArtifactRef {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return inventoryTestRef(name, data)
}

func TestCheckpointV4CandidateInventoryMatchesReplayedChain(t *testing.T) {
	_, inventory := candidateInventoryFixture(t)
	scope := inventory.Scope
	base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
	mapped := append([]ArtifactRef(nil), inventory.Files...)
	for i := range mapped {
		mapped[i].Name = base + mapped[i].Name
	}
	verification := inventoryTestRef(base+"verification.json", []byte("verified"))
	last := ChainRecord{Attestation: mapped[0], AttestationSignature: mapped[1], OutputPayload: mapped[2], Erasure: mapped[3], ErasureSignature: mapped[4], Verification: verification}
	evidence := append(mapped, verification)
	if err := verifyCandidateChainInventoryV4(last, scope, inventory, evidence); err != nil {
		t.Fatal(err)
	}
	for i, ref := range inventory.Files[:5] {
		t.Run(ref.Name, func(t *testing.T) {
			changed := inventory
			changed.Files = append([]ArtifactRef(nil), inventory.Files...)
			changed.Files[i].Digest = NewDigest([]byte("different bytes"))
			if err := verifyCandidateChainInventoryV4(last, scope, changed, evidence); err == nil {
				t.Fatal("accepted an inventory different from the replayed chain")
			}
		})
	}
	wrong := append([]ArtifactRef(nil), evidence...)
	wrong[len(wrong)-1].Digest = NewDigest([]byte("another verification"))
	if err := verifyCandidateChainInventoryV4(last, scope, inventory, wrong); err == nil {
		t.Fatal("accepted another verification record")
	}
	if err := verifyCandidateChainInventoryV4(last, scope, inventory, nil); err == nil {
		t.Fatal("accepted missing verification record")
	}
	last.Attestation.Name = "another/attestation.json"
	if err := verifyCandidateChainInventoryV4(last, scope, inventory, evidence); err == nil {
		t.Fatal("accepted different logical path with identical bytes")
	}
}

func putCheckpointTestPairV4(t *testing.T, root, name string, record any, keyID string, key ed25519.PrivateKey) SignedArtifactRefs {
	t.Helper()
	rb, sb, err := SignRecord(record, keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	return SignedArtifactRefs{Record: putCheckpointTestFileV4(t, root, name+".json", rb), Signature: putCheckpointTestFileV4(t, root, name+".sig", sb)}
}

func TestCheckpointV4ReaderStreamsAndConfinesFiles(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte{0x31}, 20<<20)
	ref := putCheckpointTestFileV4(t, root, "payload.bin", data)
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.root.Close()
	if got, err := reader.read(ref, MaxArtifactSize, false); err != nil || got != nil {
		t.Fatalf("streaming: %d %v", len(got), err)
	}
	if _, err := reader.read(ref, MaxArtifactSize, true); err == nil {
		t.Fatal("large payload retained in memory")
	}
	if _, err := reader.read(ref, maxSignedRecordBytes, false); err == nil {
		t.Fatal("size bound ignored")
	}
	wrong := ref
	wrong.Digest = NewDigest(bytes.Repeat([]byte{0x32}, len(data)))
	if _, err := reader.read(wrong, MaxArtifactSize, false); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if err := os.Symlink(filepath.Join(root, "payload.bin"), filepath.Join(root, "linked.bin")); err != nil {
		t.Fatal(err)
	}
	linked := ref
	linked.Name = "linked.bin"
	if _, err := reader.read(linked, MaxArtifactSize, false); err == nil {
		t.Fatal("symlink leaf accepted")
	}
	outside := t.TempDir()
	small := putCheckpointTestFileV4(t, outside, "small.json", []byte("outside"))
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	small.Name = "redirect/small.json"
	if _, err := reader.read(small, 100, true); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	for _, name := range []string{"../outside", "/absolute", "UPPER.json"} {
		small.Name = name
		if _, err := reader.read(small, 100, true); err == nil {
			t.Fatalf("unsafe name accepted %s", name)
		}
	}
	if err := os.Truncate(filepath.Join(root, "payload.bin"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.read(ref, MaxArtifactSize, false); err == nil {
		t.Fatal("truncated payload accepted")
	}
}

func TestStoredCheckpointV4VerifiesAncestryWithoutClaimingPayloadPresence(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	sequence := checkpointTurnV4(t, d, initial, Phase1)
	root := t.TempDir()
	key := adversarialPrivateKey(1)
	putCheckpointTestFileV4(t, root, "ceremony.json", db)
	putCheckpointTestFileV4(t, root, "ceremony.sig", ds)
	anchor := filepath.Join(t.TempDir(), "coordinator.hex")
	if err := os.WriteFile(anchor, []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0600); err != nil {
		t.Fatal(err)
	}
	trust := TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: anchor}
	var previous SignedArtifactRefs
	for i := range sequence {
		if i > 0 {
			refs := previous
			sequence[i].PreviousCheckpoint = &refs
		}
		previous = putCheckpointTestPairV4(t, root, fmt.Sprintf("checkpoints/%04d", i), sequence[i], d.Coordinator.KeyID, key)
	}
	got, err := VerifyStoredCheckpointV4(trust, root, previous)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sequence[len(sequence)-1]) {
		t.Fatal("wrong head")
	}
	// No large payloads exist in this fixture. The API authenticates state,
	// not completeness of downloaded files or contribution mathematics.
	if _, err := os.Stat(filepath.Join(root, got.Progress.Phase1.HeadPayload.Name)); !os.IsNotExist(err) {
		t.Fatal("fixture unexpectedly has payload")
	}
	if err := os.WriteFile(filepath.Join(root, "checkpoints/0001.sig"), []byte("changed signature"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStoredCheckpointV4(trust, root, previous); err == nil {
		t.Fatal("changed predecessor signature accepted")
	}
}

func TestReceiptV4FindsCommittedHandoffAfterRetirement(t *testing.T) {
	d, initial, _, _ := checkpointFixtureV4(t)
	scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, ParticipantID: d.Phase1Policy.Participants[0], ParentHeadID: initial.Progress.Phase1.HeadRecordID}
	participant, _ := d.ParticipantByID(scope.ParticipantID)
	handoff := TransferHandoff{Schema: TransferHandoffSchema, CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, PredecessorHeadID: scope.ParentHeadID,
		Source: TransferSourceBinding{SourceCommit: d.Software.SourceCommit, ToolBinary: d.Software.ToolBinary, R1CS: d.Circuit.R1CS},
		Files:  []ArtifactRef{initial.Progress.Phase1.HeadPayload}, SenderID: d.Coordinator.ID, SenderKeyID: d.Coordinator.KeyID,
		RecipientID: participant.Identity.ID, RecipientKeyID: participant.Identity.KeyID, CreatedAt: "2026-09-16T00:00:00Z", ExpiresAt: "2026-09-16T01:00:00Z"}
	root := t.TempDir()
	h := putCheckpointTestPairV4(t, root, "handoffs/outbound", handoff, d.Coordinator.KeyID, adversarialPrivateKey(1))
	receipt := TransferReceipt{Schema: TransferReceiptSchema, Kind: ReceiptReceiver, HandoffSHA256: h.Record.Digest.SHA256,
		CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, PredecessorHeadID: scope.ParentHeadID, Source: handoff.Source, Files: handoff.Files,
		SenderID: handoff.SenderID, SenderKeyID: handoff.SenderKeyID, RecipientID: handoff.RecipientID, RecipientKeyID: handoff.RecipientKeyID,
		SignerID: handoff.RecipientID, SignerKeyID: handoff.RecipientKeyID, ReceivedAt: "2026-09-16T00:01:00Z"}
	r := putCheckpointTestPairV4(t, root, "receipts/outbound", receipt, participant.Identity.KeyID, adversarialPrivateKey(0x11))
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.root.Close()
	previous := initial
	previous.Transition = CheckpointTransitionV4{Kind: CheckpointDeliveryRetired, Evidence: []ArtifactRef{}}
	tx := CheckpointTransitionV4{Kind: CheckpointPhase1ReceiptAccepted, Scope: &scope, Record: &r}
	known := map[string]SignedArtifactRefs{h.Record.Digest.SHA256: h}
	if err := verifyOutboundReceiptV4(reader, d, previous, tx, known); err != nil {
		t.Fatal(err)
	}
	if err := verifyOutboundReceiptV4(reader, d, previous, tx, map[string]SignedArtifactRefs{}); err == nil {
		t.Fatal("uncommitted handoff accepted")
	}
	receipt.ReceivedAt = "2026-09-16T02:00:00Z"
	r = putCheckpointTestPairV4(t, root, "receipts/late", receipt, participant.Identity.KeyID, adversarialPrivateKey(0x11))
	tx.Record = &r
	if err := verifyOutboundReceiptV4(reader, d, previous, tx, known); err == nil {
		t.Fatal("receipt outside validity window accepted")
	}
}

func TestRejectedInventoryV4ChecksExactPrivateBytes(t *testing.T) {
	_, inventory := candidateInventoryFixture(t)
	root := t.TempDir()
	for i, ref := range inventory.Files {
		inventory.Files[i] = putCheckpointTestFileV4(t, root, ref.Name, []byte("actual candidate bytes for "+ref.Name))
	}
	if err := verifyRejectedInventoryV4(root, inventory); err != nil {
		t.Fatal(err)
	}
	putCheckpointTestFileV4(t, root, "secret-extra.txt", []byte("synthetic extra"))
	if err := verifyRejectedInventoryV4(root, inventory); err == nil {
		t.Fatal("extra file accepted")
	}
	if err := os.Remove(filepath.Join(root, "secret-extra.txt")); err != nil {
		t.Fatal(err)
	}
	putCheckpointTestFileV4(t, root, "attestation.sig", []byte("changed"))
	if err := verifyRejectedInventoryV4(root, inventory); err == nil {
		t.Fatal("wrong rejected inventory accepted")
	}
}
