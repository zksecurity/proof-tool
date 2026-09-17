package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	if c.Sequence != 3 || len(index.Enrollments) != 1 || index.Enrollments[0] != roster || len(index.Turns) != 1 {
		t.Fatalf("lost facts: %+v", index)
	}
	turn := index.Turns[0]
	if len(turn.Allocations) != 1 || turn.Allocations[0].AttemptID != sequence[1].Transition.AttemptID || turn.Allocations[0].CheckpointSequence != 1 || turn.AcceptedChain == nil || turn.AcceptedChain.Pair != *sequence[2].Transition.Record {
		t.Fatalf("incomplete turn: %+v", turn)
	}
	if sequence[2].PreviousCheckpoint == nil || turn.Allocations[0].Checkpoint != *sequence[2].PreviousCheckpoint {
		t.Fatalf("allocation lost its exact signed checkpoint pair: %+v", turn.Allocations[0])
	}
	if _, err := os.Stat(filepath.Join(root, roster.Record.Name)); !os.IsNotExist(err) {
		t.Fatal("unexpected enrollment bytes")
	}
}

func TestCheckpointCommitmentsRetainCandidateAllocations(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	first := checkpointTurnV4(t, d, initial, Phase1)[1]
	scope := *first.Transition.Scope
	retired := nextCheckpointV4(t, first, CheckpointTransitionV4{Kind: CheckpointDeliveryRetired, Scope: &scope, AttemptID: first.Transition.AttemptID, Evidence: []ArtifactRef{}})
	var err error
	retired.Deliveries, err = AdvanceDeliveryV2(first.Deliveries, first.Transition.AttemptID, DeliveryRetired, nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement := fmt.Sprintf("%032x", 999)
	second := nextCheckpointV4(t, retired, CheckpointTransitionV4{Kind: CheckpointPhase1CandidateAllocated, Scope: &scope, AttemptID: replacement, AllocatedAt: "2026-01-01T00:02:00Z", Evidence: []ArtifactRef{}})
	second.Deliveries, err = AllocateDeliveryV2(retired.Deliveries, scope, CheckpointSubmissionCandidate, replacement)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	trust, head := storeCommitmentSequenceV4(t, d, db, ds, root, []CheckpointV4{initial, first, retired, second})
	_, index, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Turns) != 1 || len(index.Turns[0].Allocations) != 2 || index.Turns[0].Allocations[0].AttemptID != replacement || index.Turns[0].Allocations[1].AttemptID != first.Transition.AttemptID {
		t.Fatalf("allocation history lost: %+v", index)
	}
	_, repeated, err := InspectStoredCheckpointV4(trust, root, head)
	if err != nil || !reflect.DeepEqual(index, repeated) {
		t.Fatal("index is not deterministic", err)
	}
}

func TestTurnCommitmentBoundsV4(t *testing.T) {
	d, initial, _, _ := checkpointFixtureV4(t)
	tx := checkpointTurnV4(t, d, initial, Phase1)[1]
	turns := map[ContributionScope]*TurnCommitmentV4{}
	for n := 0; n < MaxDeliveryAttemptsPerSubmissionV2; n++ {
		tx.Sequence = uint64(MaxDeliveryAttemptsPerSubmissionV2 - n)
		tx.Transition.AttemptID = fmt.Sprintf("%032x", n+1)
		if err := collectTurnCommitmentV4(turns, tx, checkpointSigned(fmt.Sprintf("checkpoints/%04d", n))); err != nil {
			t.Fatal(err)
		}
	}
	if err := collectTurnCommitmentV4(turns, tx, checkpointSigned("checkpoints/overflow")); err == nil {
		t.Fatal("allocation bound not enforced")
	}
}
