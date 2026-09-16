package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCheckpointV4TerminationPreservesActiveDeliveries(t *testing.T) {
	d, genesis, _, _ := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, genesis, Phase1)
	for _, start := range []CheckpointV4{genesis, turn[1], turn[2]} {
		for _, kind := range []CheckpointTransitionKind{CheckpointIncidentRecorded, CheckpointAborted, CheckpointRestarted} {
			record := checkpointSigned("governance/record")
			tx := CheckpointTransitionV4{Kind: kind, Record: &record, Evidence: checkpointArtifacts(checkpointArtifact("governance/statement.txt", "public"))}
			if kind == CheckpointRestarted {
				fresh := checkpointSigned("restart/ceremony")
				tx.RestartDefinition = &fresh
				tx.Evidence = appendCheckpointArtifacts(tx.Evidence, fresh.Record, fresh.Signature)
			}
			next := nextCheckpointV4(t, start, tx)
			if kind != CheckpointIncidentRecorded {
				next.Progress.Terminal = &CheckpointTerminalV4{Kind: governanceKindV4(kind), Record: record, RestartDefinition: tx.RestartDefinition}
			}
			if err := ValidateCheckpointTransitionV4(start, next); err != nil {
				t.Fatalf("%s at %d: %v", kind, start.Sequence, err)
			}
			if !reflect.DeepEqual(start.Deliveries, next.Deliveries) {
				t.Fatal("history changed")
			}
			bad := cloneCheckpointV4(t, next)
			bad.Transition.NextAttemptID = strings.Repeat("ab", 16)
			if err := ValidateCheckpointTransitionV4(start, bad); err == nil {
				t.Fatal("governance reallocated a delivery")
			}
			if next.Progress.Terminal == nil {
				continue
			}
			repeated := nextCheckpointV4(t, next, tx)
			repeated.AcceptedArtifacts = append([]ArtifactRef{}, next.AcceptedArtifacts...)
			if err := repeated.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := ValidateCheckpointTransitionV4(next, repeated); err == nil || !strings.Contains(err.Error(), "no transition may follow ceremony termination") {
				t.Fatalf("structurally valid child did not reach terminal gate: %v", err)
			}
			for _, later := range []CheckpointTransitionKind{CheckpointIncidentRecorded, CheckpointAborted, CheckpointRestarted, CheckpointEnrollmentRecorded, CheckpointPhase1Closed, CheckpointPhase1CandidateAllocated, CheckpointFinalReleaseRecorded} {
				child := nextCheckpointV4(t, next, tx)
				child.Transition.Kind = later
				child.Progress.Terminal = nil
				if err := ValidateCheckpointTransitionV4(next, child); err == nil {
					t.Fatalf("%s followed termination", later)
				}
			}
		}
	}
}

func TestCheckpointV4GovernanceSemanticBinding(t *testing.T) {
	d, previous, _, _ := checkpointFixtureV4(t)
	root := t.TempDir()
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.root.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	statement := putCheckpointTestFileV4(t, root, "governance/statement.txt", []byte("Public test statement; no private logs.\n"))
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	r := GovernanceRecord{Schema: GovernanceRecordSchema, Kind: GovernanceAbort, CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, HeadID: previous.Progress.Phase1.HeadRecordID, Evidence: []ArtifactRef{statement}, ReasonCode: "test-stop", StatementSHA256: statement.Digest.SHA256, SignerID: d.Coordinator.ID, SignerKeyID: d.Coordinator.KeyID, RecordedAt: created.Add(time.Second).Format(time.RFC3339Nano)}
	makeTx := func(r GovernanceRecord, signer ed25519.PrivateKey) CheckpointTransitionV4 {
		pair := putCheckpointTestPairV4(t, root, "governance/record", r, r.SignerKeyID, signer)
		return CheckpointTransitionV4{Kind: CheckpointAborted, Record: &pair, Evidence: []ArtifactRef{statement}}
	}
	tx := makeTx(r, key)
	if err := verifyCheckpointGovernanceV4(reader, d, previous, tx); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*GovernanceRecord){
		"wrong head":        func(r *GovernanceRecord) { r.HeadID = NewDigest([]byte("stale")).SHA256 },
		"wrong phase":       func(r *GovernanceRecord) { r.Phase = Phase2 },
		"wrong index":       func(r *GovernanceRecord) { r.Index = 2 },
		"wrong identity":    func(r *GovernanceRecord) { r.SignerID = d.Roster[0].Identity.ID },
		"wrong statement":   func(r *GovernanceRecord) { r.StatementSHA256 = NewDigest([]byte("other")).SHA256 },
		"predates ceremony": func(r *GovernanceRecord) { r.RecordedAt = created.Add(-time.Second).Format(time.RFC3339Nano) },
		"wrong action":      func(r *GovernanceRecord) { r.Kind = GovernanceIncident },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if err := verifyCheckpointGovernanceV4(reader, d, previous, makeTx(bad, key)); err == nil {
				t.Fatal("accepted bad governance")
			}
		})
	}
	if err := verifyCheckpointGovernanceV4(reader, d, previous, makeTx(r, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)))); err == nil {
		t.Fatal("accepted another signing key")
	}
	tx = makeTx(r, key)
	duplicate := previous
	duplicate.AcceptedArtifacts = appendCheckpointArtifacts(previous.AcceptedArtifacts, tx.Record.Record)
	if err := verifyCheckpointGovernanceV4(reader, d, duplicate, tx); err == nil {
		t.Fatal("accepted duplicate governance record")
	}
	// Phase 2 genesis has the same legacy one-based convention, but another head.
	phase2 := previous
	phase2.Progress.Phase2 = &CheckpointPhaseState{Phase: Phase2, HeadRecordID: NewDigest([]byte("phase2-genesis")).SHA256}
	r.Phase = Phase2
	r.HeadID = phase2.Progress.Phase2.HeadRecordID
	if err := verifyCheckpointGovernanceV4(reader, d, phase2, makeTx(r, key)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointV4GovernanceCanReuseExactPublicStatement(t *testing.T) {
	_, before, _, _ := checkpointFixtureV4(t)
	statement := checkpointArtifact("governance/public.txt", "reviewed")
	incident := checkpointSigned("governance/incident")
	after := nextCheckpointV4(t, before, CheckpointTransitionV4{Kind: CheckpointIncidentRecorded, Record: &incident, Evidence: []ArtifactRef{statement}})
	if err := ValidateCheckpointTransitionV4(before, after); err != nil {
		t.Fatal(err)
	}
	stop := checkpointSigned("governance/abort")
	tx := CheckpointTransitionV4{Kind: CheckpointAborted, Record: &stop, Evidence: []ArtifactRef{statement}}
	terminal := nextCheckpointV4(t, after, tx)
	terminal.AcceptedArtifacts = appendCheckpointArtifacts(append([]ArtifactRef{}, after.AcceptedArtifacts...), stop.Record, stop.Signature)
	terminal.Progress.Terminal = &CheckpointTerminalV4{Kind: GovernanceAbort, Record: stop}
	if err := ValidateCheckpointTransitionV4(after, terminal); err != nil {
		t.Fatal(err)
	}
	bad := cloneCheckpointV4(t, terminal)
	bad.AcceptedArtifacts = appendCheckpointArtifacts(bad.AcceptedArtifacts, checkpointArtifact("unexpected.txt", "not authorized"))
	if err := ValidateCheckpointTransitionV4(after, bad); err == nil {
		t.Fatal("unrelated new artifact accepted")
	}
}

func TestCheckpointV4RestartAuthenticatesExactNewDefinition(t *testing.T) {
	d, previous, _, _ := checkpointFixtureV4(t)
	root := t.TempDir()
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.root.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	statement := putCheckpointTestFileV4(t, root, "restart/statement.txt", []byte("Public restart fixture.\n"))
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	next := d
	next.SessionNonceHex = strings.Repeat("de", 32)
	next, err = FinalizeCeremonyDefinition(next)
	if err != nil {
		t.Fatal(err)
	}
	makeTx := func(next CeremonyDefinition, signer ed25519.PrivateKey) CheckpointTransitionV4 {
		pair := putCheckpointTestPairV4(t, root, "restart/ceremony", next, next.Coordinator.KeyID, signer)
		evidence := checkpointArtifacts(statement, pair.Record, pair.Signature)
		r := GovernanceRecord{Schema: GovernanceRecordSchema, Kind: GovernanceRestart, CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1, HeadID: previous.Progress.Phase1.HeadRecordID, Evidence: evidence, ReasonCode: "test-restart", StatementSHA256: statement.Digest.SHA256, SignerID: d.Coordinator.ID, SignerKeyID: d.Coordinator.KeyID, NewCeremonyID: next.CeremonyID, RecordedAt: created.Add(time.Second).Format(time.RFC3339Nano)}
		rp := putCheckpointTestPairV4(t, root, "restart/record", r, d.Coordinator.KeyID, key)
		return CheckpointTransitionV4{Kind: CheckpointRestarted, Record: &rp, Evidence: evidence, RestartDefinition: &pair}
	}
	tx := makeTx(next, key)
	if err := verifyCheckpointGovernanceV4(reader, d, previous, tx); err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointGovernanceV4(reader, d, previous, makeTx(next, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)))); err == nil {
		t.Fatal("accepted wrong new-definition signature")
	}
	legacy := next
	legacy.Schema = DefinitionSchemaV3
	legacy.ReleaseVerification = ""
	legacy, err = FinalizeCeremonyDefinition(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointGovernanceV4(reader, d, previous, makeTx(legacy, key)); err == nil {
		t.Fatal("accepted legacy restart target")
	}
	future := next
	future.CreatedAt = created.Add(2 * time.Second).Format(time.RFC3339Nano)
	future, err = FinalizeCeremonyDefinition(future)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointGovernanceV4(reader, d, previous, makeTx(future, key)); err == nil {
		t.Fatal("restart predates new definition")
	}
}
