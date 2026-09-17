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
	"time"
)

func TestCheckpointDiscoveryV4OnlyRequestsAncestryDependencies(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, initial, Phase1)
	key := adversarialPrivateKey(1)
	for _, c := range turn {
		raw, sig, err := SignRecord(c, d.Coordinator.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DiscoverSignedCheckpointV4(d, db, ds, raw, sig)
		if err != nil {
			t.Fatal(err)
		}
		if got.CeremonyID != d.CeremonyID || got.Sequence != c.Sequence || !reflect.DeepEqual(got.PreviousCheckpoint, c.PreviousCheckpoint) || got.VerificationDependencies == nil || len(got.VerificationDependencies) != 0 {
			t.Fatalf("unexpected discovery %+v", got)
		}
		// Nothing has been written to disk: a valid signature alone discovers
		// links, but cannot establish that the ancestor or payload even exists.
		if _, err := DiscoverSignedCheckpointV4(d, db, ds, append(raw, '\n'), sig); err == nil {
			t.Fatal("tampered checkpoint accepted")
		}
		wrong := append([]byte(nil), sig...)
		wrong[0] ^= 1
		if _, err := DiscoverSignedCheckpointV4(d, db, ds, raw, wrong); err == nil {
			t.Fatal("tampered signature accepted")
		}
	}
	for _, kind := range []CheckpointTransitionKind{CheckpointIncidentRecorded, CheckpointAborted, CheckpointRestarted} {
		pair := checkpointSigned("governance/record")
		tx := CheckpointTransitionV4{Kind: kind, Record: &pair, Evidence: checkpointArtifacts(checkpointArtifact("governance/statement.txt", "statement"))}
		if kind == CheckpointRestarted {
			next := checkpointSigned("restart/ceremony")
			tx.RestartDefinition = &next
			tx.Evidence = appendCheckpointArtifacts(tx.Evidence, next.Record, next.Signature)
		}
		c := nextCheckpointV4(t, initial, tx)
		if kind != CheckpointIncidentRecorded {
			c.Progress.Terminal = &CheckpointTerminalV4{Kind: governanceKindV4(kind), Record: pair, RestartDefinition: tx.RestartDefinition}
		}
		raw, sig, err := SignRecord(c, d.Coordinator.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DiscoverSignedCheckpointV4(d, db, ds, raw, sig)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]ArtifactRef{pair.Record, pair.Signature}, tx.Evidence...)
		if !reflect.DeepEqual(got.VerificationDependencies, want) {
			t.Fatalf("%s: %+v", kind, got)
		}
	}
}

func TestCheckpointDiscoveryV4CompleteStoredDependencyContract(t *testing.T) {
	for _, kind := range []CheckpointTransitionKind{CheckpointPhase1CandidateAccepted, CheckpointIncidentRecorded, CheckpointAborted, CheckpointRestarted} {
		t.Run(string(kind), func(t *testing.T) {
			d, initial, db, ds := checkpointFixtureV4(t)
			key := adversarialPrivateKey(1)
			source, stage := t.TempDir(), t.TempDir()
			sequence := []CheckpointV4{initial}
			if kind == CheckpointPhase1CandidateAccepted {
				sequence = checkpointTurnV4(t, d, initial, Phase1)
			} else {
				statement := putCheckpointTestFileV4(t, source, "governance/statement.txt", []byte("Public fixture statement.\n"))
				evidence := []ArtifactRef{statement}
				created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
				record := GovernanceRecord{Schema: GovernanceRecordSchema, Kind: governanceKindV4(kind), CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, HeadID: initial.Progress.Phase1.HeadRecordID, Evidence: evidence, ReasonCode: "fixture", StatementSHA256: statement.Digest.SHA256, SignerID: d.Coordinator.ID, SignerKeyID: d.Coordinator.KeyID, RecordedAt: created.Add(time.Second).Format(time.RFC3339Nano)}
				var restart *SignedArtifactRefs
				if kind == CheckpointRestarted {
					next := d
					next.SessionNonceHex = strings.Repeat("de", 32)
					var err error
					next, err = FinalizeCeremonyDefinition(next)
					if err != nil {
						t.Fatal(err)
					}
					pair := putCheckpointTestPairV4(t, source, "restart/ceremony", next, next.Coordinator.KeyID, key)
					restart = &pair
					evidence = checkpointArtifacts(statement, pair.Record, pair.Signature)
					record.Evidence, record.NewCeremonyID = evidence, next.CeremonyID
				}
				rp := putCheckpointTestPairV4(t, source, "governance/record", record, d.Coordinator.KeyID, key)
				next := nextCheckpointV4(t, initial, CheckpointTransitionV4{Kind: kind, Record: &rp, Evidence: evidence, RestartDefinition: restart})
				if kind != CheckpointIncidentRecorded {
					next.Progress.Terminal = &CheckpointTerminalV4{Kind: governanceKindV4(kind), Record: rp, RestartDefinition: restart}
				}
				sequence = append(sequence, next)
			}
			var head SignedArtifactRefs
			for n := range sequence {
				if n > 0 {
					previous := head
					sequence[n].PreviousCheckpoint = &previous
				}
				head = putCheckpointTestPairV4(t, source, fmt.Sprintf("checkpoints/%04d", n), sequence[n], d.Coordinator.KeyID, key)
			}
			putCheckpointTestFileV4(t, stage, "ceremony.json", db)
			putCheckpointTestFileV4(t, stage, "ceremony.sig", ds)
			anchor := filepath.Join(t.TempDir(), "coordinator.hex")
			if err := os.WriteFile(anchor, []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0600); err != nil {
				t.Fatal(err)
			}
			trust := TrustPaths{DefinitionPath: filepath.Join(stage, "ceremony.json"), DefinitionSignaturePath: filepath.Join(stage, "ceremony.sig"), CoordinatorPublicKeyPath: anchor}
			copyRef := func(ref ArtifactRef) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(source, ref.Name))
				if err != nil {
					t.Fatal(err)
				}
				putCheckpointTestFileV4(t, stage, ref.Name, data)
				return data
			}
			var dependencies []ArtifactRef
			for current := &head; current != nil; {
				raw, sig := copyRef(current.Record), copyRef(current.Signature)
				discovery, err := DiscoverSignedCheckpointV4(d, db, ds, raw, sig)
				if err != nil {
					t.Fatal(err)
				}
				for _, ref := range discovery.VerificationDependencies {
					copyRef(ref)
					dependencies = append(dependencies, ref)
				}
				current = discovery.PreviousCheckpoint
			}
			if _, err := VerifyStoredCheckpointV4(trust, stage, head); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(stage, sequence[len(sequence)-1].Progress.Phase1.HeadPayload.Name)); !os.IsNotExist(err) {
				t.Fatal("sync unexpectedly copied contribution payload")
			}
			for _, ref := range dependencies {
				if err := os.Remove(filepath.Join(stage, ref.Name)); err != nil {
					t.Fatal(err)
				}
				if _, err := VerifyStoredCheckpointV4(trust, stage, head); err == nil {
					t.Fatalf("missing dependency accepted: %s", ref.Name)
				}
				copyRef(ref)
			}
		})
	}
}

func TestCheckpointDiscoveryV4DoesNotAuthorizeIllegalTransition(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, initial, Phase1)
	c := turn[1]
	c.Sequence += 2 // Individually signed, but an illegal sequence jump.
	raw, sig, err := SignRecord(c, d.Coordinator.KeyID, adversarialPrivateKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverSignedCheckpointV4(d, db, ds, raw, sig); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointTransitionV4(initial, c); err == nil {
		t.Fatal("discovery must not replace transition verification")
	}
}

func TestCheckpointDiscoveryV4DependencySizeLimits(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	for _, target := range []string{"record", "signature", "statement", "restart-record", "restart-signature"} {
		for _, over := range []bool{false, true} {
			pair := checkpointSigned("governance/record")
			statement := checkpointArtifact("governance/statement.txt", "public")
			restart := checkpointSigned("restart/ceremony")
			var ref *ArtifactRef
			var limit int64
			switch target {
			case "record":
				ref, limit = &pair.Record, maxSignedRecordBytes
			case "signature":
				ref, limit = &pair.Signature, 4096
			case "statement":
				ref, limit = &statement, 1<<20
			case "restart-record":
				ref, limit = &restart.Record, maxSignedRecordBytes
			case "restart-signature":
				ref, limit = &restart.Signature, 4096
			}
			ref.Digest.Size = limit
			if over {
				ref.Digest.Size++
			}
			tx := CheckpointTransitionV4{Kind: CheckpointRestarted, Record: &pair, RestartDefinition: &restart, Evidence: checkpointArtifacts(statement, restart.Record, restart.Signature)}
			c := nextCheckpointV4(t, initial, tx)
			c.Progress.Terminal = &CheckpointTerminalV4{Kind: GovernanceRestart, Record: pair, RestartDefinition: &restart}
			raw, sig, err := SignRecord(c, d.Coordinator.KeyID, adversarialPrivateKey(1))
			if err != nil {
				t.Fatal(err)
			}
			_, err = DiscoverSignedCheckpointV4(d, db, ds, raw, sig)
			if (err != nil) != over {
				t.Fatalf("%s over=%v: %v", target, over, err)
			}
		}
	}
}
