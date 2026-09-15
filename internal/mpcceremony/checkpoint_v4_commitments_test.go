package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func storeCommitmentSequenceV4(t *testing.T, d CeremonyDefinition, db, ds []byte, root string, sequence []CheckpointV4) (TrustPaths, SignedArtifactRefs) {
	t.Helper()
	putCheckpointTestFileV4(t, root, "ceremony.json", db)
	putCheckpointTestFileV4(t, root, "ceremony.sig", ds)
	key := adversarialPrivateKey(1)
	anchor := filepath.Join(t.TempDir(), "coordinator.hex")
	if err := os.WriteFile(anchor, []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0600); err != nil {
		t.Fatal(err)
	}
	trust := TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: anchor}
	var head SignedArtifactRefs
	for n := range sequence {
		if n > 0 {
			previous := head
			sequence[n].PreviousCheckpoint = &previous
		}
		head = putCheckpointTestPairV4(t, root, fmt.Sprintf("checkpoints/%04d", n), sequence[n], d.Coordinator.KeyID, key)
	}
	return trust, head
}

func TestCheckpointCommitmentsSurviveUnrelatedEdges(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	sequence := checkpointTurnV4(t, d, initial, Phase1)
	roster := checkpointSigned("enrollments/coordinator")
	evidence := checkpointArtifact("enrollments/disclosure.txt", "public")
	next := nextCheckpointV4(t, sequence[len(sequence)-1], CheckpointTransitionV4{Kind: CheckpointEnrollmentRecorded, Record: &roster, Evidence: []ArtifactRef{evidence}})
	sequence = append(sequence, next)
	root := t.TempDir()
	trust, head := storeCommitmentSequenceV4(t, d, db, ds, root, sequence)
	c, index, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sequence != 4 || len(index.Enrollments) != 1 || index.Enrollments[0] != roster || len(index.Turns) != 1 {
		t.Fatalf("lost facts: %+v", index)
	}
	turn := index.Turns[0]
	if len(turn.Outbounds) != 1 || turn.Outbounds[0].Pair != *sequence[1].Transition.Record || turn.InputReceipt == nil || turn.InputReceipt.Pair != *sequence[2].Transition.Record || turn.AcceptedChain == nil || turn.AcceptedChain.Pair != *sequence[3].Transition.Record || turn.ReturnReceipt == nil || turn.ReturnHandoff == nil {
		t.Fatalf("incomplete turn: %+v", turn)
	}
	// The index describes commitments only; none of these payloads were needed.
	if _, err := os.Stat(filepath.Join(root, roster.Record.Name)); !os.IsNotExist(err) {
		t.Fatal("unexpected enrollment bytes")
	}
}

func TestCheckpointCommitmentsRetainAllRetriedOutbounds(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	template := checkpointTurnV4(t, d, initial, Phase1)
	a := template[1]
	scope := *a.Transition.Scope
	retired := nextCheckpointV4(t, a, CheckpointTransitionV4{Kind: CheckpointDeliveryRetired, Scope: &scope, AttemptID: a.Transition.AttemptID, Evidence: []ArtifactRef{}})
	var err error
	retired.Deliveries, err = AdvanceDeliveryV2(a.Deliveries, a.Transition.AttemptID, DeliveryRetired, nil)
	if err != nil {
		t.Fatal(err)
	}
	bPair := checkpointSigned("phase1/outbound-new")
	bAttempt := strings.Repeat("ab", 16)
	b := nextCheckpointV4(t, retired, CheckpointTransitionV4{Kind: CheckpointPhase1OutboundPublished, Scope: &scope, AttemptID: bAttempt, Record: &bPair, Evidence: []ArtifactRef{}})
	b.Deliveries, err = AllocateDeliveryV2(retired.Deliveries, scope, CheckpointSubmissionReceipt, bAttempt)
	if err != nil {
		t.Fatal(err)
	}
	receiptTx := template[2].Transition
	receiptTx.AttemptID = bAttempt
	receipt := nextCheckpointV4(t, b, receiptTx)
	receipt.Deliveries, err = AdvanceDeliveryV2(b.Deliveries, bAttempt, DeliveryAccepted, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Deliveries, err = AllocateDeliveryV2(receipt.Deliveries, scope, CheckpointSubmissionCandidate, receiptTx.NextAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	trust, head := storeCommitmentSequenceV4(t, d, db, ds, root, []CheckpointV4{initial, a, retired, b, receipt})
	_, index, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil {
		t.Fatal(err)
	}
	turn := index.Turns[0]
	if len(turn.Outbounds) != 2 || turn.Outbounds[0].Pair != bPair || turn.Outbounds[1].Pair != *a.Transition.Record || turn.Outbounds[0].CheckpointSequence != 3 || turn.InputReceipt.AttemptID != bAttempt {
		t.Fatalf("retry facts lost: %+v", turn)
	}
	if !reflect.DeepEqual(turn.Scope, scope) {
		t.Fatal("turn scope changed")
	}
	_, repeated, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil || !reflect.DeepEqual(index, repeated) {
		t.Fatal("index is not deterministic", err)
	}
	// Retirement/reallocation alone does not imply a new input packet.
	replacement := strings.Repeat("ef", 16)
	retired.Transition.NextAttemptID = replacement
	retired.Deliveries, err = AllocateDeliveryV2(retired.Deliveries, scope, CheckpointSubmissionReceipt, replacement)
	if err != nil {
		t.Fatal(err)
	}
	trust, head = storeCommitmentSequenceV4(t, d, db, ds, root, []CheckpointV4{initial, a, retired})
	_, reallocated, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil || len(reallocated.Turns) != 1 || len(reallocated.Turns[0].Outbounds) != 1 || reallocated.Turns[0].Outbounds[0].Pair != *a.Transition.Record {
		t.Fatal("reallocation changed published packet", err)
	}
}

func TestTurnCommitmentBoundsV4(t *testing.T) {
	d, initial, _, _ := checkpointFixtureV4(t)
	tx := checkpointTurnV4(t, d, initial, Phase1)[1]
	turns := map[ContributionScope]*TurnCommitmentV4{}
	for n := 0; n < MaxDeliveryAttemptsPerSubmissionV2; n++ {
		tx.Sequence = uint64(MaxDeliveryAttemptsPerSubmissionV2 - n)
		if err := collectTurnCommitmentV4(turns, tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := collectTurnCommitmentV4(turns, tx); err == nil {
		t.Fatal("outbound bound not enforced")
	}
	turns = map[ContributionScope]*TurnCommitmentV4{}
	for _, phase := range []Phase{Phase1, Phase2} {
		for n := 1; n <= MaxParticipants; n++ {
			scope := *tx.Transition.Scope
			scope.Phase = phase
			scope.Index = uint8(n)
			tx.Transition.Scope = &scope
			if err := collectTurnCommitmentV4(turns, tx); err != nil {
				t.Fatal(err)
			}
		}
	}
	scope := *tx.Transition.Scope
	scope.ParticipantID = "extra"
	tx.Transition.Scope = &scope
	if err := collectTurnCommitmentV4(turns, tx); err == nil {
		t.Fatal("turn capacity not enforced")
	}
}
