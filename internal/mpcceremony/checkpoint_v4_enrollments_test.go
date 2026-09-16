package mpcceremony

import (
	"bytes"
	"reflect"
	"testing"
)

func TestCheckpointV4EnrollmentEdgePreservesActiveDelivery(t *testing.T) {
	d, start, _, _ := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, start, Phase1)
	previous := turn[1]
	pair := checkpointSigned("enrollments/participant")
	disclosure := checkpointArtifact("enrollments/disclosure.txt", "one operator")
	next := nextCheckpointV4(t, previous, CheckpointTransitionV4{Kind: CheckpointEnrollmentRecorded, Record: &pair, Evidence: []ArtifactRef{disclosure}})
	if err := ValidateCheckpointTransitionV4(previous, next); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(previous.Deliveries, next.Deliveries) {
		t.Fatal("delivery changed")
	}
	next.Deliveries = []DeliverySlotV2{}
	if err := ValidateCheckpointTransitionV4(previous, next); err == nil {
		t.Fatal("enrollment removed active delivery")
	}
}

func TestCheckpointV4EnrollmentDisclosureLimitMatchesBundle(t *testing.T) {
	d, _, db, _ := checkpointFixtureV4(t)
	for _, size := range []int{maxEnrollmentDisclosureBytes, maxEnrollmentDisclosureBytes + 1} {
		root := t.TempDir()
		disclosure := putCheckpointTestFileV4(t, root, "disclosure.txt", bytes.Repeat([]byte("x"), size))
		record, err := NewEnrollmentRecord(d, db, d.Coordinator, EnrollmentCoordinator, 1, disclosure, d.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		refs := putCheckpointTestPairV4(t, root, "enrollment", record, d.Coordinator.KeyID, adversarialPrivateKey(1))
		reader, err := openCheckpointReaderV4(root)
		if err != nil {
			t.Fatal(err)
		}
		_, err = readCheckpointEnrollmentV4(reader, d, db, refs)
		_ = reader.root.Close()
		if (err == nil) != (size <= maxEnrollmentDisclosureBytes) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestCheckpointV4ObserverAssignmentBound(t *testing.T) {
	d, _, _, _ := checkpointFixtureV4(t)
	d.AssurancePolicy.PublicWitnessesPerPhase = 1
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	db, err := MarshalCanonical(d)
	if err != nil {
		t.Fatal(err)
	}
	identity := adversarialIdentity(t, "witness-01", 0xa1)
	for _, index := range []uint16{0, MaxAuditors, MaxAuditors + 1} {
		root := t.TempDir()
		disclosure := putCheckpointTestFileV4(t, root, "disclosure.txt", []byte("fixture observer"))
		record, err := NewEnrollmentRecord(d, db, identity, EnrollmentPublicWitness, index, disclosure, d.CreatedAt)
		if index == 0 {
			if err == nil {
				t.Fatal("zero assignment accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		refs := putCheckpointTestPairV4(t, root, "enrollment", record, identity.KeyID, adversarialPrivateKey(0xa1))
		reader, err := openCheckpointReaderV4(root)
		if err != nil {
			t.Fatal(err)
		}
		_, err = readCheckpointEnrollmentV4(reader, d, db, refs)
		_ = reader.root.Close()
		if (err == nil) != (index <= MaxAuditors) {
			t.Fatalf("index %d: %v", index, err)
		}
	}
}

func TestCheckpointV4DisabledMirrorsRejectEvidence(t *testing.T) {
	d, _, db, _ := checkpointFixtureV4(t)
	d.AssurancePolicy.MirrorsPerAcceptedHead = 0
	// Disabled controls reject records before attempting to read their bytes.
	if _, err := verifyCheckpointMirrorsV4(nil, d, db, nil, nil, []SignedArtifactRefs{checkpointSigned("mirror")}); err == nil {
		t.Fatal("disabled mirror record accepted")
	}
}

func TestCheckpointV4EnrollmentAuthenticatesDisclosureAndUniqueness(t *testing.T) {
	d, _, db, _ := checkpointFixtureV4(t)
	root := t.TempDir()
	disclosure := putCheckpointTestFileV4(t, root, "enrollments/disclosure.txt", []byte("single operator test"))
	record, err := NewEnrollmentRecord(d, db, d.Coordinator, EnrollmentCoordinator, 1, disclosure, d.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	refs := putCheckpointTestPairV4(t, root, "enrollments/coordinator", record, d.Coordinator.KeyID, adversarialPrivateKey(1))
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.root.Close() }()
	tx := CheckpointTransitionV4{Kind: CheckpointEnrollmentRecorded, Record: &refs, Evidence: []ArtifactRef{disclosure}}
	records := map[string]EnrollmentRecord{}
	if err = verifyNewCheckpointEnrollmentV4(reader, d, db, tx, records); err != nil {
		t.Fatal(err)
	}
	if err = verifyNewCheckpointEnrollmentV4(reader, d, db, tx, records); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	tx.Evidence = []ArtifactRef{inventoryTestRef("enrollments/other.txt", []byte("other"))}
	if err = verifyNewCheckpointEnrollmentV4(reader, d, db, tx, map[string]EnrollmentRecord{}); err == nil {
		t.Fatal("different disclosure accepted")
	}
	putCheckpointTestFileV4(t, root, disclosure.Name, []byte("changed disclosure"))
	if _, err = loadCheckpointEnrollmentsV4(reader, d, db, []SignedArtifactRefs{refs}); err == nil {
		t.Fatal("changed historical disclosure accepted")
	}
}
