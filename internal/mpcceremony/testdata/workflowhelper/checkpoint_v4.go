package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	m "proof-tool/internal/mpcceremony"
)

// Test-only, single-process fixture. Cryptographic contributions and signatures
// are real; environment/cleanup statements are fixtures, not erasure evidence.
func runCheckpointV4Turn(output, root string, trust m.TrustPaths, circuit *m.CompiledCircuit, d m.CeremonyDefinition, coordinator ed25519.PrivateKey, coordinatorPath string, participant ed25519.PrivateKey, participantPath string) error {
	ref := func(name string) (m.ArtifactRef, error) {
		b, err := os.ReadFile(filepath.Join(root, name)) // tiny test artifacts only
		return m.ArtifactRef{Name: name, Digest: m.NewDigest(b)}, err
	}
	pair := func(name string) (m.SignedArtifactRefs, error) {
		r, err := ref(name + ".json")
		if err != nil {
			return m.SignedArtifactRefs{}, err
		}
		s, err := ref(name + ".sig")
		return m.SignedArtifactRefs{Record: r, Signature: s}, err
	}
	writePair := func(name string, value any, keyID string, key ed25519.PrivateKey) (m.SignedArtifactRefs, error) {
		r, s, err := m.SignRecord(value, keyID, key)
		if err != nil {
			return m.SignedArtifactRefs{}, err
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return m.SignedArtifactRefs{}, err
		}
		if err := os.WriteFile(path+".json", r, 0600); err != nil {
			return m.SignedArtifactRefs{}, err
		}
		if err := os.WriteFile(path+".sig", s, 0600); err != nil {
			return m.SignedArtifactRefs{}, err
		}
		return pair(name)
	}
	sorted := func(refs []m.ArtifactRef) []m.ArtifactRef {
		refs = append([]m.ArtifactRef{}, refs...)
		sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
		return refs
	}
	paths := m.PhaseTranscriptPaths{RootDir: root, ChainPath: filepath.Join(root, "phase1/chain-0000.json"), ChainSignaturePath: filepath.Join(root, "phase1/chain-0000.sig")}
	chain, chainRefs, err := m.VerifyAcceptedPhase1Chain(trust, circuit, paths)
	if err != nil {
		return err
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		return err
	}
	payload, err := chain.HeadPayload()
	if err != nil {
		return err
	}
	definition, err := pair("ceremony")
	if err != nil {
		return err
	}
	c := m.CheckpointV4{Schema: m.CheckpointSchemaV4, Workflow: m.StorageFirstWorkflowV2, CeremonyID: d.CeremonyID, Definition: definition, AssurancePolicy: d.AssurancePolicy, ReleaseVerification: m.CoordinatorReplayReleaseV1,
		Transition:        m.CheckpointTransitionV4{Kind: m.CheckpointInitial, Evidence: []m.ArtifactRef{}},
		Progress:          m.CheckpointProgressV4{Phase1: m.CheckpointPhaseState{Phase: m.Phase1, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}},
		AcceptedArtifacts: sorted([]m.ArtifactRef{definition.Record, definition.Signature, chainRefs.Record, chainRefs.Signature, payload}), Deliveries: []m.DeliverySlotV2{}}
	var committed m.SignedArtifactRefs
	commit := func() error {
		if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: c, Circuit: circuit}); err != nil {
			return fmt.Errorf("prepare %s: %w", c.Transition.Kind, err)
		}
		var err error
		committed, err = writePair(fmt.Sprintf("checkpoints/%04d", c.Sequence), c, d.Coordinator.KeyID, coordinator)
		if err != nil {
			return err
		}
		_, err = m.VerifyStoredCheckpointV4(trust, root, committed)
		return err
	}
	next := func(tx m.CheckpointTransitionV4) {
		previous := committed
		c.PreviousCheckpoint = &previous
		c.Sequence++
		c.Transition = tx
		refs := append([]m.ArtifactRef{}, c.AcceptedArtifacts...)
		if tx.Record != nil {
			refs = append(refs, tx.Record.Record, tx.Record.Signature)
		}
		refs = append(refs, tx.Evidence...)
		// Different signed records may name the same retained statement. Keep
		// the inventory a set; a same-name/different-digest conflict still fails.
		unique := make([]m.ArtifactRef, 0, len(refs))
		for _, ref := range refs {
			if !slices.Contains(unique, ref) {
				unique = append(unique, ref)
			}
		}
		c.AcceptedArtifacts = sorted(unique)
	}
	if err := commit(); err != nil {
		return err
	}
	p := d.Roster[0].Identity
	beforeEnrollment := c
	beforeEnrollmentRefs := committed
	disclosureName := "enrollments/participant-01/disclosure.txt"
	if err := os.MkdirAll(filepath.Join(root, "enrollments/participant-01"), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, disclosureName), []byte("Test fixture: one process operates every role on one machine.\n"), 0600); err != nil {
		return err
	}
	disclosure, err := ref(disclosureName)
	if err != nil {
		return err
	}
	db, err := os.ReadFile(trust.DefinitionPath)
	if err != nil {
		return err
	}
	enrollment, err := m.NewEnrollmentRecord(d, db, p, m.EnrollmentParticipant, 1, disclosure, "2023-08-23T15:00:30Z")
	if err != nil {
		return err
	}
	enrollmentRefs, err := writePair("enrollments/participant-01/record", enrollment, p.KeyID, participant)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &enrollmentRefs, Evidence: []m.ArtifactRef{disclosure}})
	if err = commit(); err != nil {
		return err
	}
	scope := m.ContributionScope{CeremonyID: d.CeremonyID, Phase: m.Phase1, Index: 1, ParticipantID: p.ID, ParentHeadID: head}
	handoff, err := m.NewTransferHandoff(d, m.Phase1, 1, head, []m.ArtifactRef{payload}, d.Coordinator, p, "2023-08-23T15:01:00Z", "2023-08-23T16:01:00Z")
	if err != nil {
		return err
	}
	handoffRefs, err := writePair("custody/outbound", handoff, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	const first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const second = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const candidateAttempt = "cccccccccccccccccccccccccccccccc"
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1OutboundPublished, Scope: &scope, AttemptID: first, Record: &handoffRefs, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionReceipt, first)
	if err != nil {
		return err
	}
	missingEnrollment := c
	missingEnrollment.Sequence = beforeEnrollment.Sequence + 1
	missingEnrollment.PreviousCheckpoint = &beforeEnrollmentRefs
	missingEnrollment.AcceptedArtifacts = sorted(append(append([]m.ArtifactRef{}, beforeEnrollment.AcceptedArtifacts...), handoffRefs.Record, handoffRefs.Signature))
	if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: missingEnrollment, Circuit: circuit}); err == nil || !strings.Contains(err.Error(), "enrollment") {
		return fmt.Errorf("outbound without committed enrollment: %v", err)
	}
	if err = commit(); err != nil {
		return err
	}
	// Retire without replacement, then reallocate. The receipt still binds the
	// original signed handoff, not a transport-attempt envelope.
	next(m.CheckpointTransitionV4{Kind: m.CheckpointDeliveryRetired, Scope: &scope, AttemptID: first, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AdvanceDeliveryV2(c.Deliveries, first, m.DeliveryRetired, nil)
	if err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointDeliveryReallocated, Scope: &scope, AttemptID: first, NextAttemptID: second, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionReceipt, second)
	if err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	hb, err := os.ReadFile(filepath.Join(root, handoffRefs.Record.Name))
	if err != nil {
		return err
	}
	receipt, err := m.NewTransferReceipt(handoff, hb, m.ReceiptReceiver, "2023-08-23T15:02:00Z")
	if err != nil {
		return err
	}
	receiptRefs, err := writePair("custody/receipt", receipt, p.KeyID, participant)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1ReceiptAccepted, Scope: &scope, AttemptID: second, NextAttemptID: candidateAttempt, Record: &receiptRefs, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AdvanceDeliveryV2(c.Deliveries, second, m.DeliveryAccepted, nil)
	if err != nil {
		return err
	}
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionCandidate, candidateAttempt)
	if err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	candidateDir := filepath.Join(output, "candidates/v4-turn")
	environment := m.ContributionEnvironment{OS: runtime.GOOS, Architecture: runtime.GOARCH, EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}
	if _, err = m.CreateContributionCandidate(m.ContributionFilesOptions{Trust: trust, Circuit: circuit, Phase: m.Phase1, Transcript: paths, ParticipantID: p.ID, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:03:00Z", CandidateDir: candidateDir}); err != nil {
		return err
	}
	if _, err = m.CreateErasureAttestationFiles(m.CreateErasureAttestationFilesOptions{Trust: trust, ParticipantID: p.ID, ParticipantPrivateKeyPath: participantPath, CandidateDir: candidateDir, DestroyedAt: "2023-08-23T15:04:00Z"}); err != nil {
		return err
	}
	returnFiles := []m.ArtifactRef{}
	computedInventory, err := m.InspectContributionInventoryV4(trust, paths, scope, candidateDir)
	if err != nil {
		return err
	}
	if computedInventory.Complete != nil || computedInventory.ComputedCandidateID == "" {
		return errors.New("computed inventory reconstruction failed")
	}
	for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"} {
		b, err := os.ReadFile(filepath.Join(candidateDir, name))
		if err != nil {
			return err
		}
		returnFiles = append(returnFiles, m.ArtifactRef{Name: "phase1/contributions/0001/" + name, Digest: m.NewDigest(b)})
	}
	returnHandoff, err := m.NewTransferHandoff(d, m.Phase1, 1, scope.ParentHeadID, returnFiles, p, d.Coordinator, "2023-08-23T15:04:10Z", "2023-08-23T16:04:10Z")
	if err != nil {
		return err
	}
	returnRefs, err := writePair("custody/return-handoff", returnHandoff, p.KeyID, participant)
	if err != nil {
		return err
	}
	rhBytes, err := os.ReadFile(filepath.Join(root, returnRefs.Record.Name))
	if err != nil {
		return err
	}
	returnReceipt, err := m.NewTransferReceipt(returnHandoff, rhBytes, m.ReceiptReceiver, "2023-08-23T15:04:20Z")
	if err != nil {
		return err
	}
	returnReceiptRefs, err := writePair("custody/return-receipt", returnReceipt, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	for _, ref := range []m.ArtifactRef{returnRefs.Record, returnRefs.Signature} {
		b, err := os.ReadFile(filepath.Join(root, ref.Name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(candidateDir, filepath.Base(ref.Name)), b, 0600); err != nil {
			return err
		}
	}
	completeInventory, err := m.InspectContributionInventoryV4(trust, paths, scope, candidateDir)
	if err != nil {
		return err
	}
	if completeInventory.Complete == nil || completeInventory.ComputedCandidateID != computedInventory.ComputedCandidateID || completeInventory.CandidateResultID == computedInventory.ComputedCandidateID {
		return errors.New("complete inventory reconstruction failed")
	}
	accepted, err := m.VerifyAndAcceptContribution(m.AcceptContributionFilesOptions{Trust: trust, Circuit: circuit, Phase: m.Phase1, Transcript: paths, CandidateDir: candidateDir, CoordinatorPrivateKeyPath: coordinatorPath, AcceptedAt: "2023-08-23T15:05:00Z"})
	if err != nil {
		return err
	}
	paths.ChainPath = accepted.ChainPath
	paths.ChainSignaturePath = accepted.ChainSignaturePath
	chain, chainRefs, err = m.VerifyAcceptedPhase1Chain(trust, circuit, paths)
	if err != nil {
		return err
	}
	last := chain.Records[0]
	files := []m.ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	returnEvidence := []m.ArtifactRef{}
	for _, pair := range []m.SignedArtifactRefs{returnRefs, returnReceiptRefs} {
		for _, original := range []m.ArtifactRef{pair.Record, pair.Signature} {
			b, err := os.ReadFile(filepath.Join(root, original.Name))
			if err != nil {
				return err
			}
			name := "phase1/contributions/0001/" + filepath.Base(original.Name)
			if err = os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
				return err
			}
			returnEvidence = append(returnEvidence, m.ArtifactRef{Name: name, Digest: m.NewDigest(b)})
		}
	}
	files = append(files, returnEvidence[:2]...)
	inventory := m.CandidateInventory{Schema: m.CandidateInventorySchemaV1, Scope: scope, Files: append([]m.ArtifactRef{}, files...)}
	for i := range inventory.Files {
		inventory.Files[i].Name = filepath.Base(inventory.Files[i].Name)
	}
	if id, err := inventory.ID(); err != nil || id != completeInventory.CandidateResultID {
		return errors.New("accepted inventory differs from inspected candidate")
	}
	evidence := append(append([]m.ArtifactRef{}, files...), returnEvidence[2:]...)
	evidence = append(evidence, last.Verification)
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1CandidateAccepted, Scope: &scope, AttemptID: candidateAttempt, Record: &chainRefs, Evidence: sorted(evidence), Contribution: &inventory})
	c.Deliveries, err = m.AdvanceDeliveryV2(c.Deliveries, candidateAttempt, m.DeliveryAccepted, &inventory)
	if err != nil {
		return err
	}
	head, err = chain.HeadRecordID()
	if err != nil {
		return err
	}
	payload, err = chain.HeadPayload()
	if err != nil {
		return err
	}
	c.Progress.Phase1 = m.CheckpointPhaseState{Phase: m.Phase1, AcceptedCount: 1, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}
	lateReceipt := returnReceipt
	lateReceipt.ReceivedAt = "2023-08-23T15:06:00Z"
	lateRefs, err := writePair("phase1/contributions/0001/return-receipt", lateReceipt, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	bad := c
	bad.Transition.Evidence = append([]m.ArtifactRef{}, c.Transition.Evidence...)
	bad.AcceptedArtifacts = append([]m.ArtifactRef{}, c.AcceptedArtifacts...)
	for _, replacement := range []m.ArtifactRef{lateRefs.Record, lateRefs.Signature} {
		for i := range bad.Transition.Evidence {
			if bad.Transition.Evidence[i].Name == replacement.Name {
				bad.Transition.Evidence[i] = replacement
			}
		}
		for i := range bad.AcceptedArtifacts {
			if bad.AcceptedArtifacts[i].Name == replacement.Name {
				bad.AcceptedArtifacts[i] = replacement
			}
		}
	}
	_, lateErr := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: bad, Circuit: circuit})
	if lateErr == nil || !strings.Contains(lateErr.Error(), "timestamps") {
		return fmt.Errorf("late signed return receipt: expected custody chronology rejection, got %v", lateErr)
	}
	if _, err = writePair("phase1/contributions/0001/return-receipt", returnReceipt, d.Coordinator.KeyID, coordinator); err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	// Real-file negative: identical length, wrong payload digest must fail before
	// a second checkpoint can be prepared. Restore to retain an inspectable run.
	file := filepath.Join(root, last.OutputPayload.Name)
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	changed := append([]byte(nil), b...)
	changed[len(changed)-1] ^= 1
	if err = os.WriteFile(file, changed, 0600); err != nil {
		return err
	}
	_, rejectErr := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: c, Circuit: circuit})
	if err = os.WriteFile(file, b, 0600); err != nil {
		return err
	}
	if rejectErr == nil {
		return fmt.Errorf("corrupted accepted contribution passed checkpoint preparation")
	}
	beforeMirrors, beforeMirrorsRefs := c, committed
	if d.AssurancePolicy.MirrorsPerAcceptedHead > 0 {
		mirrorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xb1}, 32))
		mirror, err := m.NewIdentity("mirror-01", "Fixture mirror", "mirror-key", mirrorKey.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		mr, err := m.NewEnrollmentRecord(d, db, mirror, m.EnrollmentMirrorOperator, 1, disclosure, "2023-08-23T15:00:31Z")
		if err != nil {
			return err
		}
		mrRefs, err := writePair("enrollments/mirror-01/record", mr, mirror.KeyID, mirrorKey)
		if err != nil {
			return err
		}
		// Give this enrollment its own disclosure reference; immutable evidence
		// must add precisely its own supporting file rather than re-add a path.
		mirrorDisclosureName := "enrollments/mirror-01/disclosure.txt"
		if err = os.WriteFile(filepath.Join(root, mirrorDisclosureName), []byte("One-process mirror fixture.\n"), 0600); err != nil {
			return err
		}
		md, err := ref(mirrorDisclosureName)
		if err != nil {
			return err
		}
		mr.IndependenceDisclosure = md
		mrRefs, err = writePair("enrollments/mirror-01/record", mr, mirror.KeyID, mirrorKey)
		if err != nil {
			return err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &mrRefs, Evidence: []m.ArtifactRef{md}})
		if err = commit(); err != nil {
			return err
		}
		mf, err := m.MirrorReceiptFiles(last, chainRefs)
		if err != nil {
			return err
		}
		mirrorReceipt, err := m.NewImmutableMirrorReceipt(d.CeremonyID, m.Phase1, 1, head, mf, mirror, m.NewDigest([]byte("fixture archive")).SHA256, "2023-08-23T15:05:30Z")
		if err != nil {
			return err
		}
		mirrorRefs, err := writePair("mirrors/phase1-0001", mirrorReceipt, mirror.KeyID, mirrorKey)
		if err != nil {
			return err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointMirrorRecorded, Record: &mirrorRefs, Evidence: []m.ArtifactRef{}})
		if err = commit(); err != nil {
			return err
		}
	}
	// Historical genuine drand response tests binding and mathematics, not a
	// live wait. Normal closure commands keep their current-time requirements.
	roundTime, err := m.QuicknetRoundTime(42)
	if err != nil {
		return err
	}
	participants, err := chain.ParticipantIDs()
	if err != nil {
		return err
	}
	closure, err := m.NewCloseRecord(m.CloseRecord{CeremonyID: d.CeremonyID, Phase: m.Phase1, PhaseID: chain.PhaseID, FinalIndex: 1, FinalPayload: payload, ChainHeadID: head, AcceptedParticipants: participants, BeaconProvider: d.BeaconPolicy.Provider, BeaconNetwork: d.BeaconPolicy.Network, BeaconRound: 42, BeaconNotBefore: roundTime.Format(time.RFC3339Nano), ClosedAt: "2023-08-23T15:06:00Z", CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID})
	if err != nil {
		return err
	}
	closureRefs, err := writePair("phase1/closure/record", closure, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1Closed, Record: &closureRefs, Evidence: []m.ArtifactRef{}})
	c.Progress.Phase1Closure = &closureRefs
	if d.AssurancePolicy.MirrorsPerAcceptedHead > 0 {
		missing := c
		missing.Sequence = beforeMirrors.Sequence + 1
		missing.PreviousCheckpoint = &beforeMirrorsRefs
		missing.AcceptedArtifacts = sorted(append(append([]m.ArtifactRef{}, beforeMirrors.AcceptedArtifacts...), closureRefs.Record, closureRefs.Signature))
		if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: missing, Circuit: circuit}); err == nil || !strings.Contains(err.Error(), "mirror") {
			return fmt.Errorf("closure without required mirror: %v", err)
		}
	}
	if err = commit(); err != nil {
		return err
	}
	raw := filepath.Join(output, "quicknet-v4-42.json")
	if d.AssurancePolicy.PublicWitnessesPerPhase > 0 {
		witnessKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, 32))
		witness, err := m.NewIdentity("witness-01", "Fixture witness", "witness-key", witnessKey.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Join(root, "enrollments/witness-01"), 0700); err != nil {
			return err
		}
		wdName := "enrollments/witness-01/disclosure.txt"
		if err = os.WriteFile(filepath.Join(root, wdName), []byte("One-process witness fixture, not independent observation.\n"), 0600); err != nil {
			return err
		}
		wd, err := ref(wdName)
		if err != nil {
			return err
		}
		wr, err := m.NewEnrollmentRecord(d, db, witness, m.EnrollmentPublicWitness, 1, wd, "2023-08-23T15:00:32Z")
		if err != nil {
			return err
		}
		wrRefs, err := writePair("enrollments/witness-01/record", wr, witness.KeyID, witnessKey)
		if err != nil {
			return err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &wrRefs, Evidence: []m.ArtifactRef{wd}})
		if err = commit(); err != nil {
			return err
		}
		receipt := m.PublicWitnessReceipt{Schema: m.PublicWitnessReceiptSchema, CeremonyID: d.CeremonyID, Phase: m.Phase1, CloseID: closure.CloseID, ChainHeadID: closure.ChainHeadID, Closure: closureRefs.Record, BeaconRound: 42, BeaconScheduledAt: roundTime.Format(time.RFC3339Nano), PublicationLocationSHA: m.NewDigest([]byte("fixture publication")).SHA256, Witness: witness, ObservedAt: "2023-08-23T15:06:30Z"}
		wrRefs, err = writePair("witnesses/phase1", receipt, witness.KeyID, witnessKey)
		if err != nil {
			return err
		}
		if os.Getenv("MPC_WORKFLOW_SKIP_WITNESS") != "1" {
			next(m.CheckpointTransitionV4{Kind: m.CheckpointWitnessRecorded, Record: &wrRefs, Evidence: []m.ArtifactRef{}})
			if err = commit(); err != nil {
				return err
			}
		}
	}
	if err = os.WriteFile(raw, []byte(quicknetRound42), 0600); err != nil {
		return err
	}
	beacon, err := m.RecordBeaconFiles(m.RecordBeaconFilesOptions{Trust: trust, TranscriptRoot: root, Phase: m.Phase1, ClosePath: filepath.Join(root, closureRefs.Record.Name), CloseSignaturePath: filepath.Join(root, closureRefs.Signature.Name), RawResponsePath: raw, PublishedAt: "2023-08-23T15:11:30Z", CoordinatorPrivateKeyPath: coordinatorPath})
	if err != nil {
		return err
	}
	beaconName, err := filepath.Rel(root, beacon.BeaconPath)
	if err != nil {
		return err
	}
	beaconSignatureName, err := filepath.Rel(root, beacon.SignaturePath)
	if err != nil {
		return err
	}
	br, err := ref(filepath.ToSlash(beaconName))
	if err != nil {
		return err
	}
	bs, err := ref(filepath.ToSlash(beaconSignatureName))
	if err != nil {
		return err
	}
	beaconRefs := m.SignedArtifactRefs{Record: br, Signature: bs}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1BeaconRecorded, Record: &beaconRefs, Evidence: []m.ArtifactRef{beacon.Beacon.RawResponse}})
	c.Progress.Phase1Beacon = &beaconRefs
	if err = commit(); err != nil {
		return err
	}
	beaconEvidence := m.MultiRelayBeaconEvidence{Schema: m.MultiRelayBeaconEvidenceSchema, CeremonyID: d.CeremonyID, Phase: m.Phase1, CloseID: closure.CloseID, BeaconRound: 42, Provider: d.BeaconPolicy.Provider, Network: d.BeaconPolicy.Network, CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID, RecordedAt: "2023-08-23T15:11:30Z"}
	rawRefs := []m.ArtifactRef{}
	for _, id := range []string{"fixture-a", "fixture-b"} {
		name := "phase1/beacon-evidence/" + id + ".json"
		if err = os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(root, name), []byte(quicknetRound42), 0600); err != nil {
			return err
		}
		rr, err := ref(name)
		if err != nil {
			return err
		}
		rawRefs = append(rawRefs, rr)
		beaconEvidence.Observations = append(beaconEvidence.Observations, m.RelayObservation{RelayID: id, OperatorID: id, EndpointSHA256: m.NewDigest([]byte(id)).SHA256, RawResponse: rr, RetrievedAt: "2023-08-23T15:11:30Z", VerifiedRandomness: beacon.Beacon.RandomnessHex})
	}
	beRefs, err := writePair("phase1/beacon-evidence/record", beaconEvidence, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	if os.Getenv("MPC_WORKFLOW_SKIP_BEACON_EVIDENCE") != "1" {
		next(m.CheckpointTransitionV4{Kind: m.CheckpointBeaconEvidenceRecorded, Record: &beRefs, Evidence: sorted(rawRefs)})
		if err = commit(); err != nil {
			return err
		}
	}
	seal, err := m.SealPhase1Files(m.SealPhase1FilesOptions{Trust: trust, Circuit: circuit, TranscriptRoot: root, ClosePath: filepath.Join(root, closureRefs.Record.Name), CloseSignaturePath: filepath.Join(root, closureRefs.Signature.Name), BeaconPath: beacon.BeaconPath, BeaconSignaturePath: beacon.SignaturePath, CoordinatorPrivateKeyPath: coordinatorPath, OutputDir: filepath.Join(root, "phase1/sealed")})
	if err != nil {
		return err
	}
	sealName, err := filepath.Rel(root, seal.SealPath)
	if err != nil {
		return err
	}
	sealSigName, err := filepath.Rel(root, seal.SignaturePath)
	if err != nil {
		return err
	}
	sr, err := ref(filepath.ToSlash(sealName))
	if err != nil {
		return err
	}
	ss, err := ref(filepath.ToSlash(sealSigName))
	if err != nil {
		return err
	}
	sealRefs := m.SignedArtifactRefs{Record: sr, Signature: ss}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1Sealed, Record: &sealRefs, Evidence: seal.Seal.Outputs})
	c.Progress.Phase1Seal = &sealRefs
	if err = commit(); err != nil {
		return err
	}
	p2, err := m.InitializePhase2Files(m.InitPhase2FilesOptions{Trust: trust, Circuit: circuit, TranscriptRoot: root, Phase1SealPath: seal.SealPath, Phase1SealSignaturePath: seal.SignaturePath, CoordinatorPrivateKeyPath: coordinatorPath, OutputDir: filepath.Join(root, "phase2")})
	if err != nil {
		return err
	}
	p2Chain, p2Refs, err := m.VerifyAcceptedPhase2Chain(trust, circuit, root, seal.SealPath, seal.SignaturePath, m.PhaseTranscriptPaths{RootDir: root, ChainPath: p2.ChainPath, ChainSignaturePath: p2.ChainSignaturePath})
	if err != nil {
		return err
	}
	p2Head, err := p2Chain.HeadRecordID()
	if err != nil {
		return err
	}
	p2Payload, err := p2Chain.HeadPayload()
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2Initialized, Record: &p2Refs, Evidence: []m.ArtifactRef{p2Payload}})
	c.Progress.Phase2 = &m.CheckpointPhaseState{Phase: m.Phase2, HeadRecordID: p2Head, HeadPayload: p2Payload, Chain: p2Refs}
	if err = commit(); err != nil {
		return err
	}
	fmt.Println("V4 real phase1 turn passed: initial, outbound, retirement, reallocation, receipt, contribution, cleanup, full replay, exact acceptance, corruption rejected, closure, drand, seal, phase2 genesis")
	return runCheckpointV4Final(output, root, trust, circuit, d, coordinator, coordinatorPath, participant, participantPath, &c, next, commit, writePair, ref, sorted)
}
