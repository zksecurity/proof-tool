package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"proof-tool/internal/keybundle"
)

// These fixtures test structural guidance transitions, not contribution math.
// A real signed ceremony round trip separately exercises semantic authoring.
func checkpointFixtureV4(t *testing.T) (CeremonyDefinition, CheckpointV4, []byte, []byte) {
	t.Helper()
	d := trustedCoordinatorDefinition(t)
	d.Mode = ModeRehearsal
	d.AssurancePolicy.ExternalSecurityAuditSignoffs = 0
	d.Phase1Policy.Minimum = 1
	d.Phase2Policy.Minimum = 1
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	db, ds, err := SignRecord(d, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	def := SignedArtifactRefs{Record: inventoryTestRef("ceremony.json", db), Signature: inventoryTestRef("ceremony.sig", ds)}
	chain := checkpointSigned("phase1/chain-0000")
	c := CheckpointV4{Schema: CheckpointSchemaV4, Workflow: StorageFirstWorkflowV2, CeremonyID: d.CeremonyID, Definition: def,
		AssurancePolicy: cloneAssurancePolicy(d.AssurancePolicy), ReleaseVerification: CoordinatorReplayReleaseV1,
		Transition:        CheckpointTransitionV4{Kind: CheckpointInitial, Evidence: []ArtifactRef{}},
		Progress:          CheckpointProgressV4{Phase1: CheckpointPhaseState{Phase: Phase1, HeadRecordID: NewDigest([]byte("head-0")).SHA256, HeadPayload: d.Phase1Genesis, Chain: chain}},
		AcceptedArtifacts: checkpointArtifacts(def.Record, def.Signature, d.Circuit.R1CS, chain.Record, chain.Signature, d.Phase1Genesis), Deliveries: []DeliverySlotV2{}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return d, c, db, ds
}

func cloneCheckpointV4(t *testing.T, c CheckpointV4) CheckpointV4 {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out CheckpointV4
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func nextCheckpointV4(t *testing.T, p CheckpointV4, transition CheckpointTransitionV4) CheckpointV4 {
	t.Helper()
	c := cloneCheckpointV4(t, p)
	raw, err := MarshalCanonical(p)
	if err != nil {
		t.Fatal(err)
	}
	ref := checkpointSigned(fmt.Sprintf("checkpoints/%04d", p.Sequence))
	ref.Record.Digest = NewDigest(raw)
	c.PreviousCheckpoint = &ref
	c.Sequence++
	c.Transition = transition
	c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, append(signedArtifacts(transition.Record), transition.Evidence...)...)
	return c
}

func checkpointTurnV4(t *testing.T, d CeremonyDefinition, start CheckpointV4, phase Phase) []CheckpointV4 {
	t.Helper()
	state := start.Progress.Phase1
	participant := d.Phase1Policy.Participants[0]
	allocate, accept := CheckpointPhase1CandidateAllocated, CheckpointPhase1CandidateAccepted
	if phase == Phase2 {
		state = *start.Progress.Phase2
		participant = d.Phase2Policy.Participants[0]
		allocate = CheckpointPhase2CandidateAllocated
		accept = CheckpointPhase2CandidateAccepted
	}
	scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: state.AcceptedCount + 1, ParticipantID: participant, ParentHeadID: state.HeadRecordID}
	id := fmt.Sprintf("%032x", start.Sequence+100)
	c1 := nextCheckpointV4(t, start, CheckpointTransitionV4{Kind: allocate, Scope: &scope, AttemptID: id, AllocatedAt: "2026-01-01T00:01:00Z", Evidence: []ArtifactRef{}})
	var err error
	c1.Deliveries, err = AllocateDeliveryV2(start.Deliveries, scope, CheckpointSubmissionCandidate, id)
	if err != nil {
		t.Fatal(err)
	}
	_, inventory := candidateInventoryFixture(t)
	inventory.Scope = scope
	chain := checkpointSigned(fmt.Sprintf("%s/chain-%04d", phase, scope.Index))
	evidence := []ArtifactRef{}
	for _, ref := range inventory.Files {
		ref.Name = fmt.Sprintf("%s/contributions/%04d/%s", phase, scope.Index, ref.Name)
		evidence = append(evidence, ref)
	}
	evidence = checkpointArtifacts(append(evidence, checkpointArtifact(fmt.Sprintf("%s/contributions/%04d/verification.json", phase, scope.Index), "verification"))...)
	c2 := nextCheckpointV4(t, c1, CheckpointTransitionV4{Kind: accept, Scope: &scope, AttemptID: id, Record: &chain, Evidence: evidence, Contribution: &inventory})
	c2.Deliveries, err = AdvanceDeliveryV2(c1.Deliveries, id, DeliveryAccepted, &inventory)
	if err != nil {
		t.Fatal(err)
	}
	nextState := CheckpointPhaseState{Phase: phase, AcceptedCount: scope.Index, HeadRecordID: NewDigest([]byte(string(phase) + "accepted-head")).SHA256, HeadPayload: evidence[2], Chain: chain}
	if phase == Phase1 {
		c2.Progress.Phase1 = nextState
	} else {
		c2.Progress.Phase2 = &nextState
	}
	sequence := []CheckpointV4{start, c1, c2}
	for i := 1; i < len(sequence); i++ {
		if err := ValidateCheckpointTransitionV4(sequence[i-1], sequence[i]); err != nil {
			t.Fatalf("%s edge %d: %v", phase, i, err)
		}
	}
	return sequence
}

func TestCheckpointV4FullStructuralLifecycle(t *testing.T) {
	d, c, definition, definitionSignature := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, c, Phase1)
	c = turn[len(turn)-1]
	stages := []CheckpointTransitionKind{CheckpointPhase1Closed, CheckpointPhase1BeaconRecorded, CheckpointPhase1Sealed, CheckpointPhase2Initialized, CheckpointPhase2Closed, CheckpointPhase2BeaconRecorded, CheckpointFinalCandidateRecorded, CheckpointReleaseReviewRecorded, CheckpointFinalReleaseRecorded}
	for _, kind := range stages {
		record := checkpointSigned("lifecycle/" + string(kind))
		evidence := []ArtifactRef{}
		if kind != CheckpointPhase1Closed && kind != CheckpointPhase2Closed && kind != CheckpointReleaseReviewRecorded {
			evidence = append(evidence, checkpointArtifact("lifecycle/"+string(kind)+".bin", "payload"))
		}
		if kind == CheckpointFinalReleaseRecorded {
			record = SignedArtifactRefs{Record: checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestFile, "manifest"), Signature: checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestSignatureFile, "signature")}
			evidence = checkpointArtifacts(checkpointArtifact(FinalReleasePackagePrefixV4+FinalTranscriptFile, "transcript"), checkpointArtifact(FinalReleasePackagePrefixV4+ReleaseChecksumsFile, "checksums"), checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestPublicKeyFile, "public key"))
		}
		next := nextCheckpointV4(t, c, CheckpointTransitionV4{Kind: kind, Record: &record, Evidence: evidence})
		switch kind {
		case CheckpointPhase1Closed:
			next.Progress.Phase1Closure = &record
		case CheckpointPhase1BeaconRecorded:
			next.Progress.Phase1Beacon = &record
		case CheckpointPhase1Sealed:
			next.Progress.Phase1Seal = &record
		case CheckpointPhase2Initialized:
			next.Progress.Phase2 = &CheckpointPhaseState{Phase: Phase2, HeadRecordID: NewDigest([]byte("p2genesis")).SHA256, HeadPayload: evidence[0], Chain: record}
		case CheckpointPhase2Closed:
			next.Progress.Phase2Closure = &record
		case CheckpointPhase2BeaconRecorded:
			next.Progress.Phase2Beacon = &record
		case CheckpointFinalCandidateRecorded:
			next.Progress.FinalCandidate = &record
			next.Transition.ReplayVerification = &CheckpointReplayVerificationV4{Method: CoordinatorReplayReleaseV1, ToolBinary: d.Software.ToolBinary}
			for _, mutate := range []func(*CheckpointReplayVerificationV4){
				func(claim *CheckpointReplayVerificationV4) { claim.Method = "signature-only" },
				func(claim *CheckpointReplayVerificationV4) { claim.ToolBinary = Digest{} },
			} {
				bad := cloneCheckpointV4(t, next)
				mutate(bad.Transition.ReplayVerification)
				if err := ValidateCheckpointTransitionV4(c, bad); err == nil {
					t.Fatal("invalid final replay claim accepted")
				}
			}
			bad := cloneCheckpointV4(t, next)
			bad.Transition.ReplayVerification = nil
			if err := ValidateCheckpointTransitionV4(c, bad); err == nil {
				t.Fatal("missing final replay claim accepted")
			}
		case CheckpointReleaseReviewRecorded:
			next.Progress.ReleaseReview = &record
			lateAudit := checkpointSigned("audits/late")
			lateIncident := checkpointSigned("governance/late")
			for _, tx := range []CheckpointTransitionV4{
				{Kind: CheckpointAuditRecorded, Record: &lateAudit, Evidence: []ArtifactRef{}},
				{Kind: CheckpointIncidentRecorded, Record: &lateIncident, Evidence: checkpointArtifacts(checkpointArtifact("governance/late.txt", "late"))},
			} {
				late := nextCheckpointV4(t, next, tx)
				if err := ValidateCheckpointTransitionV4(next, late); err == nil {
					t.Fatalf("%s accepted after release review", tx.Kind)
				}
			}
		case CheckpointFinalReleaseRecorded:
			next.Progress.FinalRelease = &record
		}
		if err := ValidateCheckpointTransitionV4(c, next); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		c = next
		if kind == CheckpointPhase2Initialized {
			turn = checkpointTurnV4(t, d, c, Phase2)
			c = turn[len(turn)-1]
		}
	}
	if c.Progress.FinalRelease == nil {
		t.Fatal("did not reach final release")
	}
	raw, signature, err := SignRecord(c, d.Coordinator.KeyID, adversarialPrivateKey(1))
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := DiscoverSignedCheckpointV4(d, definition, definitionSignature, raw, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(discovery.VerificationDependencies, c.Transition.Evidence) {
		t.Fatalf("final-release discovery dependencies = %+v, want signed bootstrap evidence %+v", discovery.VerificationDependencies, c.Transition.Evidence)
	}
	for _, kind := range []CheckpointTransitionKind{CheckpointIncidentRecorded, CheckpointAborted, CheckpointRestarted} {
		pair := checkpointSigned("governance/after-release")
		tx := CheckpointTransitionV4{Kind: kind, Record: &pair, Evidence: checkpointArtifacts(checkpointArtifact("governance/statement.txt", "public"))}
		if kind == CheckpointRestarted {
			fresh := checkpointSigned("restart/definition")
			tx.RestartDefinition = &fresh
			tx.Evidence = appendCheckpointArtifacts(tx.Evidence, fresh.Record, fresh.Signature)
		}
		next := nextCheckpointV4(t, c, tx)
		if kind != CheckpointIncidentRecorded {
			next.Progress.Terminal = &CheckpointTerminalV4{Kind: governanceKindV4(kind), Record: pair, RestartDefinition: tx.RestartDefinition}
		}
		if err := ValidateCheckpointTransitionV4(c, next); err == nil {
			t.Fatalf("%s allowed after release", kind)
		}
	}
}

func TestCheckpointV4RejectsSkippedOrAlteredTurnEdges(t *testing.T) {
	d, c, _, _ := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, c, Phase1)
	for name, mutate := range map[string]func(*CheckpointV4){
		"wrong parent":          func(n *CheckpointV4) { n.PreviousCheckpoint.Record.Digest = NewDigest([]byte("other checkpoint")) },
		"wrong sequence":        func(n *CheckpointV4) { n.Sequence++ },
		"changed policy":        func(n *CheckpointV4) { n.AssurancePolicy.PublicWitnessesPerPhase++ },
		"changed runtime claim": func(n *CheckpointV4) { n.ReleaseVerification = "none" },
		"hidden extra file": func(n *CheckpointV4) {
			n.AcceptedArtifacts = appendCheckpointArtifacts(n.AcceptedArtifacts, checkpointArtifact("unexpected.json", "extra"))
		},
		"wrong slot":     func(n *CheckpointV4) { n.Transition.AttemptID = strings.Repeat("e", 32) },
		"skipped count":  func(n *CheckpointV4) { n.Progress.Phase1.AcceptedCount++ },
		"changed result": func(n *CheckpointV4) { n.Transition.Contribution.Files[0].Digest = NewDigest([]byte("changed")) },
		"extra candidate file": func(n *CheckpointV4) {
			n.Transition.Contribution.Files = append(n.Transition.Contribution.Files, checkpointArtifact("extra.json", "extra"))
		},
		"missing verification": func(n *CheckpointV4) {
			for i, ref := range n.Transition.Evidence {
				if strings.HasSuffix(ref.Name, "verification.json") {
					n.Transition.Evidence = append(n.Transition.Evidence[:i], n.Transition.Evidence[i+1:]...)
					break
				}
			}
		},
		"discard history":       func(n *CheckpointV4) { n.Deliveries = n.Deliveries[1:] },
		"advance another phase": func(n *CheckpointV4) { n.Progress.Phase2 = &n.Progress.Phase1 },
	} {
		t.Run(name, func(t *testing.T) {
			n := cloneCheckpointV4(t, turn[2])
			mutate(&n)
			if err := ValidateCheckpointTransitionV4(turn[1], n); err == nil {
				t.Fatal("invalid edge accepted")
			}
		})
	}
	if err := ValidateCheckpointTransitionV4(turn[0], turn[2]); err == nil {
		t.Fatal("allocation step skipped")
	}
	n := cloneCheckpointV4(t, turn[2])
	n.Sequence = turn[0].Sequence + 1
	raw, _ := MarshalCanonical(turn[0])
	n.PreviousCheckpoint.Record.Digest = NewDigest(raw)
	if err := ValidateCheckpointTransitionV4(turn[0], n); err == nil {
		t.Fatal("candidate accepted before allocation")
	}
}

func TestCheckpointV4AuthenticatesExactPolicyAndRejectsLegacy(t *testing.T) {
	d, c, db, ds := checkpointFixtureV4(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	cb, cs, err := SignRecord(c, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpointV4(d, db, ds, cb, cs); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpoint(d, db, ds, cb, cs); err == nil {
		t.Fatal("old checkpoint verifier accepted v4")
	}
	old := adversarialDefinition(t)
	odb, ods, err := SignRecord(old, old.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpointV4(old, odb, ods, cb, cs); err == nil {
		t.Fatal("v4 checker accepted old definition")
	}
	changed := cloneCheckpointV4(t, c)
	changed.AssurancePolicy.PublicWitnessesPerPhase++
	bad, bads, err := SignRecord(changed, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpointV4(d, db, ds, bad, bads); err == nil {
		t.Fatal("signed but changed policy accepted")
	}
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	bad, bads, err = SignRecord(c, d.Coordinator.KeyID, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedCheckpointV4(d, db, ds, bad, bads); err == nil {
		t.Fatal("wrong coordinator key accepted")
	}
	for _, field := range []string{"relay_release_id", "manifest_key", "acknowledgement"} {
		if bytes.Contains(cb, []byte(field)) {
			t.Fatalf("transport field %s leaked into v4", field)
		}
	}
}

func TestCheckpointV4RejectsOverlappingArtifactNames(t *testing.T) {
	refs := checkpointArtifacts(checkpointArtifact("a", "file"), checkpointArtifact("a-b", "middle"), checkpointArtifact("a/b", "child"))
	if err := validateV4ArtifactSet(refs, 10); err == nil {
		t.Fatal("non-adjacent file/directory collision accepted")
	}
}

func TestCheckpointV4DeliveryRetryAndRejectionEdges(t *testing.T) {
	d, initial, _, _ := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, initial, Phase1)
	previous := turn[1]
	for _, kind := range []CheckpointTransitionKind{CheckpointDeliveryRetired, CheckpointContributionRejected} {
		t.Run(string(kind), func(t *testing.T) {
			transition := CheckpointTransitionV4{Kind: kind, Scope: turn[2].Transition.Scope, AttemptID: turn[2].Transition.AttemptID, NextAttemptID: strings.Repeat("e", 32), Evidence: []ArtifactRef{}}
			status := DeliveryRetired
			if kind == CheckpointContributionRejected {
				status = DeliveryRejected
				transition.Contribution = turn[2].Transition.Contribution
			}
			next := nextCheckpointV4(t, previous, transition)
			var err error
			next.Deliveries, err = AdvanceDeliveryV2(previous.Deliveries, transition.AttemptID, status, transition.Contribution)
			if err != nil {
				t.Fatal(err)
			}
			next.Deliveries, err = AllocateDeliveryV2(next.Deliveries, *transition.Scope, CheckpointSubmissionCandidate, transition.NextAttemptID)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateCheckpointTransitionV4(previous, next); err != nil {
				t.Fatal(err)
			}
			changed := cloneCheckpointV4(t, next)
			changed.Deliveries[1].Status = DeliveryRetired
			changed.Deliveries[1].ContributionResultID = ""
			if kind == CheckpointContributionRejected {
				if err := ValidateCheckpointTransitionV4(previous, changed); err == nil {
					t.Fatal("rejection silently retired")
				}
			}
			accept := turn[2].Transition
			accept.AttemptID = transition.NextAttemptID
			final := nextCheckpointV4(t, next, accept)
			final.Progress = turn[2].Progress
			final.Deliveries, err = AdvanceDeliveryV2(next.Deliveries, accept.AttemptID, DeliveryAccepted, accept.Contribution)
			if kind == CheckpointContributionRejected {
				if err == nil {
					t.Fatal("rejected result accepted through replacement")
				}
				final.Deliveries = append([]DeliverySlotV2{}, next.Deliveries...)
				last := len(final.Deliveries) - 1
				final.Deliveries[last].Status = DeliveryAccepted
				final.Deliveries[last].ContributionResultID, _ = accept.Contribution.ID()
				if err := ValidateCheckpointTransitionV4(next, final); err == nil {
					t.Fatal("hand-constructed rejection bypass accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateCheckpointTransitionV4(next, final); err != nil {
					t.Fatal(err)
				}
			}
			// Rejected payload hashes may be public state, but their unaccepted
			// bytes must never enter the public accepted-artifact inventory.
			bad := cloneCheckpointV4(t, next)
			bad.AcceptedArtifacts = appendCheckpointArtifacts(bad.AcceptedArtifacts, checkpointArtifact("rejected.bin", "unaccepted"))
			if err := ValidateCheckpointTransitionV4(previous, bad); err == nil {
				t.Fatal("rejected payload published as accepted")
			}
		})
	}
}

func TestCheckpointV4RetirementAtLimitCanCloseAfterMinimum(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, initial, Phase1)
	previous := turn[2]
	scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: Phase1, Index: 2, ParticipantID: d.Phase1Policy.Participants[1], ParentHeadID: previous.Progress.Phase1.HeadRecordID}
	id := fmt.Sprintf("%032x", 200)
	c := nextCheckpointV4(t, previous, CheckpointTransitionV4{Kind: CheckpointPhase1CandidateAllocated, Scope: &scope, AttemptID: id, AllocatedAt: "2026-01-01T00:02:00Z", Evidence: []ArtifactRef{}})
	var err error
	c.Deliveries, err = AllocateDeliveryV2(previous.Deliveries, scope, CheckpointSubmissionCandidate, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointTransitionV4(previous, c); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxDeliveryAttemptsPerSubmissionV2; i++ {
		tx := CheckpointTransitionV4{Kind: CheckpointDeliveryRetired, Scope: &scope, AttemptID: id, Evidence: []ArtifactRef{}}
		n := nextCheckpointV4(t, c, tx)
		n.Deliveries, err = AdvanceDeliveryV2(c.Deliveries, id, DeliveryRetired, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateCheckpointTransitionV4(c, n); err != nil {
			t.Fatal(err)
		}
		c = n
		if i < MaxDeliveryAttemptsPerSubmissionV2-1 {
			nextID := fmt.Sprintf("%032x", 201+i)
			n = nextCheckpointV4(t, c, CheckpointTransitionV4{Kind: CheckpointDeliveryReallocated, Scope: &scope, AttemptID: id, NextAttemptID: nextID, Evidence: []ArtifactRef{}})
			n.Deliveries, err = AllocateDeliveryV2(c.Deliveries, scope, CheckpointSubmissionCandidate, nextID)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateCheckpointTransitionV4(c, n); err != nil {
				t.Fatal(err)
			}
			c = n
			id = nextID
		}
	}
	if _, err := AllocateDeliveryV2(c.Deliveries, scope, CheckpointSubmissionCandidate, strings.Repeat("f", 32)); err == nil {
		t.Fatal("attempt budget exceeded")
	}
	closure := checkpointSigned("phase1/closure")
	n := nextCheckpointV4(t, c, CheckpointTransitionV4{Kind: CheckpointPhase1Closed, Record: &closure, Evidence: []ArtifactRef{}})
	n.Progress.Phase1Closure = &closure
	if err := ValidateCheckpointTransitionV4(c, n); err != nil {
		t.Fatal(err)
	}
	key := adversarialPrivateKey(1)
	pb, ps, err := SignRecord(c, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	n.PreviousCheckpoint.Signature.Digest = NewDigest(ps)
	nb, ns, err := SignRecord(n, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointEdgeV4(d, db, ds, pb, ps, nb, ns); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointV4ExactPredecessorSignatureAndMinimum(t *testing.T) {
	d, initial, db, ds := checkpointFixtureV4(t)
	turn := checkpointTurnV4(t, d, initial, Phase1)
	next := turn[1]
	key := adversarialPrivateKey(1)
	pb, ps, err := SignRecord(initial, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	next.PreviousCheckpoint.Signature.Digest = NewDigest(ps)
	nb, ns, err := SignRecord(next, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointEdgeV4(d, db, ds, pb, ps, nb, ns); err != nil {
		t.Fatal(err)
	}
	next.PreviousCheckpoint.Signature.Digest = NewDigest([]byte("wrong predecessor signature"))
	nb, ns, err = SignRecord(next, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointEdgeV4(d, db, ds, pb, ps, nb, ns); err == nil {
		t.Fatal("wrong signature reference accepted")
	}
	closure := checkpointSigned("phase1/closure")
	closed := nextCheckpointV4(t, initial, CheckpointTransitionV4{Kind: CheckpointPhase1Closed, Record: &closure, Evidence: []ArtifactRef{}})
	closed.Progress.Phase1Closure = &closure
	closed.PreviousCheckpoint.Signature.Digest = NewDigest(ps)
	nb, ns, err = SignRecord(closed, d.Coordinator.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointEdgeV4(d, db, ds, pb, ps, nb, ns); err == nil {
		t.Fatal("phase closed before signed contribution minimum")
	}
}

func TestAppendUniqueSortedArtifactsV4KeepsEmptyListExplicit(t *testing.T) {
	artifacts := appendUniqueSortedArtifactsV4(nil)
	if artifacts == nil || len(artifacts) != 0 {
		t.Fatalf("empty artifact list = %#v, want explicit empty list", artifacts)
	}
}
