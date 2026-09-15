package mpcceremony

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointEnrollmentMetadataExactSetAndHead(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	root := t.TempDir()
	disclosure := checkpointArtifact("disclosure.txt", "not retained in metadata fixture")
	record, err := NewEnrollmentRecord(d, db, d.Coordinator, EnrollmentCoordinator, 1, disclosure, d.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	pair := putCheckpointTestPairV4(t, root, "enrollments/coordinator", record, d.Coordinator.KeyID, adversarialPrivateKey(1))
	// A second valid pair at another name is not a committed enrollment.
	putCheckpointTestPairV4(t, root, "loose/coordinator", record, d.Coordinator.KeyID, adversarialPrivateKey(1))
	next := nextCheckpointV4(t, initial, CheckpointTransitionV4{Kind: CheckpointEnrollmentRecorded, Record: &pair, Evidence: []ArtifactRef{disclosure}})
	sequence := []CheckpointV4{initial, next}
	trust, head := storeCommitmentSequenceV4(t, d, db, ds, root, sequence)
	checkpointBytes, err := os.ReadFile(filepath.Join(root, head.Record.Name))
	if err != nil {
		t.Fatal(err)
	}
	checkpointSignature, err := os.ReadFile(filepath.Join(root, head.Signature.Name))
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := DiscoverSignedCheckpointV4(d, db, ds, checkpointBytes, checkpointSignature)
	if err != nil || discovery.Enrollment == nil || *discovery.Enrollment != pair || len(discovery.VerificationDependencies) != 0 {
		t.Fatal("enrollment guidance dependency conflated with structural dependencies", err)
	}
	got, err := InspectCheckpointEnrollmentsV4(trust, root, head)
	if err != nil {
		t.Fatal(err)
	}
	if got.CeremonyID != d.CeremonyID || got.Checkpoint != head || len(got.Enrollments) != 1 || got.Enrollments[0].Refs != pair || got.Enrollments[0].Enrollment.Identity.ID != d.Coordinator.ID {
		t.Fatalf("wrong exact metadata: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, disclosure.Name)); !os.IsNotExist(err) {
		t.Fatal("disclosure was unexpectedly read")
	}
	for _, ref := range []ArtifactRef{pair.Record, pair.Signature} {
		path := filepath.Join(root, ref.Name)
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectCheckpointEnrollmentsV4(trust, root, head); err == nil {
			t.Fatal("missing committed enrollment accepted")
		}
		putCheckpointTestFileV4(t, root, ref.Name, []byte("substituted"))
		if _, err := InspectCheckpointEnrollmentsV4(trust, root, head); err == nil {
			t.Fatal("substituted enrollment accepted")
		}
		putCheckpointTestFileV4(t, root, ref.Name, bytes)
	}
	previous := *sequence[1].PreviousCheckpoint
	old, err := InspectCheckpointEnrollmentsV4(trust, root, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Enrollments) != 0 {
		t.Fatal("later enrollment leaked into older head")
	}
	// Structural ancestry alone does not read enrollment contents. The batch
	// must also bind the signed disclosure reference to the committed edge.
	wrong := nextCheckpointV4(t, initial, CheckpointTransitionV4{Kind: CheckpointEnrollmentRecorded, Record: &pair, Evidence: []ArtifactRef{checkpointArtifact("different-disclosure.txt", "wrong")}})
	wrongTrust, wrongHead := storeCommitmentSequenceV4(t, d, db, ds, root, []CheckpointV4{initial, wrong})
	if _, err := InspectCheckpointEnrollmentsV4(wrongTrust, root, wrongHead); err == nil {
		t.Fatal("uncommitted disclosure reference accepted")
	}
}
