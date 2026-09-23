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
	initial, err := m.PrepareInitialCheckpointV4(m.InitialCheckpointV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root})
	if err != nil {
		return fmt.Errorf("derive initial checkpoint: %w", err)
	}
	c := initial.Checkpoint
	var committed m.SignedArtifactRefs
	commit := func() error {
		if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: c, Circuit: circuit, RequireCurrentReplayExecutable: true}); err != nil {
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
	const candidateAttempt = "cccccccccccccccccccccccccccccccc"
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1CandidateAllocated, Scope: &scope, AttemptID: candidateAttempt, AllocatedAt: "2023-08-23T15:01:00Z", Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionCandidate, candidateAttempt)
	if err != nil {
		return err
	}
	missingEnrollment := c
	missingEnrollment.Sequence = beforeEnrollment.Sequence + 1
	missingEnrollment.PreviousCheckpoint = &beforeEnrollmentRefs
	missingEnrollment.AcceptedArtifacts = append([]m.ArtifactRef{}, beforeEnrollment.AcceptedArtifacts...)
	if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: missingEnrollment, Circuit: circuit}); err == nil || !strings.Contains(err.Error(), "enrollment") {
		return fmt.Errorf("allocation without committed enrollment: %v", err)
	}
	allocated, err := m.PrepareCandidateAllocationCheckpointV4(m.CandidateAllocationCheckpointV4Options{Trust: trust, ArtifactRoot: root, Checkpoint: committed, AttemptID: candidateAttempt, AllocatedAt: "2023-08-23T15:01:00Z"})
	if err != nil {
		return err
	}
	if allocated.Scope != scope {
		return errors.New("derived allocation scope differs from signed schedule")
	}
	c = allocated.Checkpoint
	if err = commit(); err != nil {
		return err
	}
	candidateDir := filepath.Join(output, "candidates/v4-turn")
	environment := m.ContributionEnvironment{OS: runtime.GOOS, Architecture: runtime.GOARCH, EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}
	wrongCandidateDir := candidateDir + "-wrong-attempt"
	if _, wrongErr := m.CreateAllocatedContributionCandidateV4(m.AllocatedContributionFilesV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, AttemptID: "dddddddddddddddddddddddddddddddd", ExpectedPhase: scope.Phase, ExpectedParticipantID: scope.ParticipantID, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:03:00Z", CandidateDir: wrongCandidateDir}); wrongErr == nil {
		return errors.New("unallocated candidate attempt was accepted")
	}
	if _, statErr := os.Lstat(wrongCandidateDir); !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("rejected allocation wrote candidate output: %v", statErr)
	}
	wrongPhase := m.Phase2
	if scope.Phase == m.Phase2 {
		wrongPhase = m.Phase1
	}
	for _, mismatch := range []struct {
		phase       m.Phase
		participant string
		name        string
	}{{wrongPhase, scope.ParticipantID, "phase"}, {scope.Phase, "wrong-participant", "participant"}} {
		out := candidateDir + "-wrong-" + mismatch.name
		if _, mismatchErr := m.CreateAllocatedContributionCandidateV4(m.AllocatedContributionFilesV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, AttemptID: candidateAttempt, ExpectedPhase: mismatch.phase, ExpectedParticipantID: mismatch.participant, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:03:00Z", CandidateDir: out}); mismatchErr == nil {
			return fmt.Errorf("mismatched %s accepted", mismatch.name)
		}
		if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("mismatched %s wrote candidate output: %v", mismatch.name, statErr)
		}
	}
	var contributionStages []string
	if _, err = m.CreateAllocatedContributionCandidateV4(m.AllocatedContributionFilesV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, AttemptID: candidateAttempt, ExpectedPhase: scope.Phase, ExpectedParticipantID: scope.ParticipantID, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:03:00Z", CandidateDir: candidateDir, Progress: func(stage string, index, total int) {
		contributionStages = append(contributionStages, fmt.Sprintf("%d/%d %s", index, total, stage))
	}}); err != nil {
		return err
	}
	if err := checkAllocatedContributionStages(contributionStages); err != nil {
		return err
	}
	generated, err := m.InspectComputationOutputV4(trust, paths, scope, candidateDir)
	if err != nil {
		return err
	}
	if len(generated.Files) != 3 {
		return errors.New("preliminary computation inspection did not return three files")
	}
	if _, err = m.CreateErasureAttestationFiles(m.CreateErasureAttestationFilesOptions{Trust: trust, ParticipantID: p.ID, ParticipantPrivateKeyPath: participantPath, CandidateDir: candidateDir, DestroyedAt: "2023-08-23T15:04:00Z"}); err != nil {
		return err
	}
	computedInventory, err := m.InspectContributionInventoryV4(trust, paths, scope, candidateDir)
	if err != nil {
		return err
	}
	if computedInventory.Complete == nil || computedInventory.ComputedCandidateID == "" || computedInventory.CandidateResultID != computedInventory.ComputedCandidateID {
		return errors.New("computed inventory reconstruction failed")
	}
	acceptOptions := m.AcceptAllocatedCandidateV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, AttemptID: candidateAttempt, CandidateDir: candidateDir, CoordinatorPrivateKeyPath: coordinatorPath, AcceptedAt: "2023-08-23T15:05:00Z"}
	acceptedCheckpoint, err := m.VerifyAndAcceptAllocatedCandidateV4(acceptOptions)
	if err != nil {
		return err
	}
	if err := checkAcceptedCheckpointRetryV4(acceptOptions, acceptedCheckpoint); err != nil {
		return err
	}
	accepted := acceptedCheckpoint.Accepted
	paths.ChainPath = accepted.ChainPath
	paths.ChainSignaturePath = accepted.ChainSignaturePath
	chain, chainRefs, err = m.VerifyAcceptedPhase1Chain(trust, circuit, paths)
	if err != nil {
		return err
	}
	last := chain.Records[0]
	files := []m.ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	inventory := m.CandidateInventory{Schema: m.CandidateInventorySchemaV1, Scope: scope, Files: append([]m.ArtifactRef{}, files...)}
	for i := range inventory.Files {
		inventory.Files[i].Name = filepath.Base(inventory.Files[i].Name)
	}
	if id, err := inventory.ID(); err != nil || id != computedInventory.CandidateResultID {
		return errors.New("accepted inventory differs from inspected candidate")
	}
	acceptedInventoryID, err := acceptedCheckpoint.Candidate.ID()
	if err != nil {
		return err
	}
	if acceptedCheckpoint.Scope != scope || acceptedInventoryID != computedInventory.CandidateResultID {
		return errors.New("derived acceptance differs from verified candidate")
	}
	head, err = chain.HeadRecordID()
	if err != nil {
		return err
	}
	payload, err = chain.HeadPayload()
	if err != nil {
		return err
	}
	c = acceptedCheckpoint.Checkpoint
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
	if os.Getenv("MPC_WORKFLOW_CHECK_P1_REUSE") == "1" {
		opts := m.RecordedCheckpointV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, Kind: m.CheckpointPhase1Sealed, Record: sealRefs, Evidence: seal.Seal.Outputs}
		if err := checkCoordinatorPhase1RecordMethods(opts, coordinatorPath, participantPath); err != nil {
			return err
		}
	}
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
	recordOptions := m.RecordedCheckpointV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: committed, Kind: m.CheckpointPhase2Initialized, Record: p2Refs, Evidence: []m.ArtifactRef{p2Payload}}
	for _, corrupt := range []string{"record", "evidence"} {
		bad := recordOptions
		if corrupt == "record" {
			bad.Record.Record.Digest.Size++
		} else {
			bad.Evidence = append([]m.ArtifactRef(nil), recordOptions.Evidence...)
			bad.Evidence[0].Digest.Size++
		}
		if _, err := m.PrepareRecordedCheckpointV4(bad); err == nil {
			return fmt.Errorf("record phase2 genesis accepted changed %s", corrupt)
		}
	}
	if os.Getenv("MPC_WORKFLOW_CHECK_P1_REUSE") == "1" {
		if err := checkCoordinatorPhase1RecordMethods(recordOptions, coordinatorPath, participantPath); err != nil {
			return err
		}
	}
	recordedGenesis, err := m.PrepareRecordedCheckpointV4(recordOptions)
	if err != nil {
		return fmt.Errorf("record phase2 genesis: %w", err)
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2Initialized, Record: &p2Refs, Evidence: []m.ArtifactRef{p2Payload}})
	c.Progress.Phase2 = &m.CheckpointPhaseState{Phase: m.Phase2, HeadRecordID: p2Head, HeadPayload: p2Payload, Chain: p2Refs}
	if *recordedGenesis.Checkpoint.Progress.Phase2 != *c.Progress.Phase2 {
		return fmt.Errorf("recorded genesis projection differs from verified chain")
	}

	if err = commit(); err != nil {
		return err
	}
	fmt.Println("V4 real phase1 turn passed: initial, allocation, contribution, cleanup, full replay, exact acceptance, corruption rejected, closure, drand, seal, phase2 genesis")
	if os.Getenv("MPC_WORKFLOW_STOP_AFTER_P1_REUSE") == "1" {
		return nil
	}
	return runCheckpointV4Final(output, root, trust, circuit, d, coordinator, coordinatorPath, participant, participantPath, &c, next, commit, writePair, ref, sorted)
}

func checkAllocatedContributionStages(got []string) error {
	want := []string{
		"1/5 Checking assignment and signed records",
		"2/5 Checking input files",
		"3/5 Creating your contribution",
		"4/5 Checking your contribution",
		"5/5 Saving contribution and attestation",
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("allocated contribution stages = %v, want %v", got, want)
	}
	return nil
}

// Exercise a stopped coordinator retry using the same predecessor and immutable
// accepted artifacts, including operational failure rather than rejection when
// an existing accepted chain differs from the exact retry bytes.
func checkAcceptedCheckpointRetryV4(options m.AcceptAllocatedCandidateV4Options, expected m.AcceptedCandidateCheckpointV4) error {
	retry, err := m.VerifyAndAcceptAllocatedCandidateV4(options)
	if err != nil {
		return fmt.Errorf("retry allocated acceptance: %w", err)
	}
	if !bytes.Equal(retry.Canonical, expected.Canonical) {
		return errors.New("acceptance retry changed canonical checkpoint")
	}
	path := expected.Accepted.ChainPath
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	changed := append([]byte(nil), original...)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(path, changed, 0600); err != nil {
		return err
	}
	failed, retryErr := m.VerifyAndAcceptAllocatedCandidateV4(options)
	retained, readErr := os.ReadFile(path)
	if err := os.WriteFile(path, original, 0600); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if retryErr == nil || m.IsCandidateInvalid(retryErr) || len(failed.Canonical) != 0 {
		return fmt.Errorf("changed accepted chain must fail operationally without a checkpoint: %v", retryErr)
	}
	if !bytes.Equal(retained, changed) {
		return errors.New("failed acceptance retry overwrote existing chain bytes")
	}
	recovered, err := m.VerifyAndAcceptAllocatedCandidateV4(options)
	if err != nil || !bytes.Equal(recovered.Canonical, expected.Canonical) {
		return fmt.Errorf("restored acceptance retry did not recover exact checkpoint: %v", err)
	}
	return nil
}

func checkCoordinatorPhase1RecordMethods(options m.RecordedCheckpointV4Options, coordinator, wrongKey string) error {
	independent, err := m.PrepareRecordedCheckpointV4(options)
	if err != nil {
		return err
	}
	accepted, err := m.PrepareCoordinatorRecordedCheckpointV4(options, coordinator, false)
	if err != nil {
		return err
	}
	forced, err := m.PrepareCoordinatorRecordedCheckpointV4(options, coordinator, true)
	if err != nil {
		return err
	}
	if !bytes.Equal(independent.Canonical, accepted.Canonical) || !bytes.Equal(independent.Canonical, forced.Canonical) {
		return errors.New("verification methods changed checkpoint bytes")
	}
	if accepted.Phase1VerificationMethod != "coordinator-acceptance-and-beacon-v1" || independent.Phase1VerificationMethod != "independent-full-replay-v1" || forced.Phase1VerificationMethod != "independent-full-replay-v1" {
		return errors.New("wrong Phase 1 verification method label")
	}
	if _, err := m.PrepareCoordinatorRecordedCheckpointV4(options, wrongKey, false); err == nil {
		return errors.New("participant signing key authorized coordinator reuse")
	}
	return nil
}
