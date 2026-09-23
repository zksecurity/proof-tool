package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	m "proof-tool/internal/mpcceremony"
)

// Continuation of the same real cryptographic fixture. Historical times and
// single-process observer statements do not establish a live ceremony.
func runCheckpointV4Final(output, root string, trust m.TrustPaths, circuit *m.CompiledCircuit, d m.CeremonyDefinition, coordinator ed25519.PrivateKey, coordinatorPath string, participant ed25519.PrivateKey, participantPath string, c *m.CheckpointV4,
	next func(m.CheckpointTransitionV4), commit func() error,
	writePair func(string, any, string, ed25519.PrivateKey) (m.SignedArtifactRefs, error),
	ref func(string) (m.ArtifactRef, error), sorted func([]m.ArtifactRef) []m.ArtifactRef) error {
	p := d.Roster[0].Identity
	scope := m.ContributionScope{CeremonyID: d.CeremonyID, Phase: m.Phase2, Index: 1, ParticipantID: p.ID, ParentHeadID: c.Progress.Phase2.HeadRecordID}
	path := func(r m.ArtifactRef) string { return filepath.Join(root, r.Name) }
	seal := *c.Progress.Phase1Seal
	paths := m.PhaseTranscriptPaths{RootDir: root, ChainPath: path(c.Progress.Phase2.Chain.Record), ChainSignaturePath: path(c.Progress.Phase2.Chain.Signature)}
	const candidateAttempt = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2CandidateAllocated, Scope: &scope, AttemptID: candidateAttempt, AllocatedAt: "2023-08-23T15:11:30.1Z", Evidence: []m.ArtifactRef{}})
	var err error
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionCandidate, candidateAttempt)
	if err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	checkpointRecord, err := ref(fmt.Sprintf("checkpoints/%04d.json", c.Sequence))
	if err != nil {
		return err
	}
	checkpointSignature, err := ref(fmt.Sprintf("checkpoints/%04d.sig", c.Sequence))
	if err != nil {
		return err
	}
	checkpoint := m.SignedArtifactRefs{Record: checkpointRecord, Signature: checkpointSignature}
	candidateDir := filepath.Join(output, "candidates/v4-phase2")
	environment := m.ContributionEnvironment{OS: runtime.GOOS, Architecture: runtime.GOARCH, EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}
	var contributionStages []string
	if _, err = m.CreateAllocatedContributionCandidateV4(m.AllocatedContributionFilesV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: checkpoint, AttemptID: candidateAttempt, ExpectedPhase: scope.Phase, ExpectedParticipantID: scope.ParticipantID, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:11:30.3Z", CandidateDir: candidateDir, Progress: func(stage string, index, total int) {
		contributionStages = append(contributionStages, fmt.Sprintf("%d/%d %s", index, total, stage))
	}}); err != nil {
		return err
	}
	if err := checkAllocatedContributionStages(contributionStages); err != nil {
		return err
	}
	if _, err = m.CreateErasureAttestationFiles(m.CreateErasureAttestationFilesOptions{Trust: trust, ParticipantID: p.ID, ParticipantPrivateKeyPath: participantPath, CandidateDir: candidateDir, DestroyedAt: "2023-08-23T15:11:30.4Z"}); err != nil {
		return err
	}
	files := []m.ArtifactRef{}
	for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"} {
		b, err := os.ReadFile(filepath.Join(candidateDir, name))
		if err != nil {
			return err
		}
		files = append(files, m.ArtifactRef{Name: "phase2/contributions/0001/" + name, Digest: m.NewDigest(b)})
	}
	acceptOptions := m.AcceptAllocatedCandidateV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: checkpoint, AttemptID: candidateAttempt, CandidateDir: candidateDir, CoordinatorPrivateKeyPath: coordinatorPath, AcceptedAt: "2023-08-23T15:11:30.5Z"}
	preparedAcceptance, err := m.VerifyAndAcceptAllocatedCandidateV4(acceptOptions)
	if err != nil {
		return err
	}
	if err := checkAcceptedCheckpointRetryV4(acceptOptions, preparedAcceptance); err != nil {
		return err
	}
	accepted := preparedAcceptance.Accepted
	paths.ChainPath, paths.ChainSignaturePath = accepted.ChainPath, accepted.ChainSignaturePath
	chain, chainRefs, err := m.VerifyAcceptedPhase2Chain(trust, circuit, root, path(seal.Record), path(seal.Signature), paths)
	if err != nil {
		return err
	}
	last := chain.Records[0]
	files = []m.ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	inv := m.CandidateInventory{Schema: m.CandidateInventorySchemaV1, Scope: scope, Files: append([]m.ArtifactRef{}, files...)}
	for i := range inv.Files {
		inv.Files[i].Name = filepath.Base(inv.Files[i].Name)
	}
	evidence := append([]m.ArtifactRef{}, files...)
	evidence = append(evidence, last.Verification)
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2CandidateAccepted, Scope: &scope, AttemptID: candidateAttempt, Record: &chainRefs, Evidence: sorted(evidence), Contribution: &inv})
	c.Deliveries, err = m.AdvanceDeliveryV2(c.Deliveries, candidateAttempt, m.DeliveryAccepted, &inv)
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
	c.Progress.Phase2 = &m.CheckpointPhaseState{Phase: m.Phase2, AcceptedCount: 1, HeadRecordID: head, HeadPayload: payload, Chain: chainRefs}
	independentAcceptance, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: *c, Circuit: circuit})
	if err != nil {
		return err
	}
	if !bytes.Equal(preparedAcceptance.Canonical, independentAcceptance) {
		return fmt.Errorf("allocated Phase 2 acceptance differs from independently verified manual projection")
	}

	if err = commit(); err != nil {
		return err
	}
	if d.Mode == m.ModeProduction {
		headr, err := ref(fmt.Sprintf("checkpoints/%04d.json", c.Sequence))
		if err != nil {
			return err
		}
		heads, err := ref(fmt.Sprintf("checkpoints/%04d.sig", c.Sequence))
		if err != nil {
			return err
		}
		committed := m.SignedArtifactRefs{Record: headr, Signature: heads}
		chain, chainRefs, err = addSecondProductionContribution(output, root, trust, circuit, d, m.Phase2, c, &committed, coordinatorPath, next, commit, writePair, ref)
		if err != nil {
			return fmt.Errorf("second Phase 2 contribution: %w", err)
		}
		last = chain.Records[1]
		head, err = chain.HeadRecordID()
		if err != nil {
			return err
		}
		payload, err = chain.HeadPayload()
		if err != nil {
			return err
		}
	}
	if d.AssurancePolicy.MirrorsPerAcceptedHead > 0 {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xb1}, 32))
		identity, err := m.NewIdentity("mirror-01", "Fixture mirror", "mirror-key", key.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		mf, err := m.MirrorReceiptFiles(last, chainRefs)
		if err != nil {
			return err
		}
		mr, err := m.NewImmutableMirrorReceipt(d.CeremonyID, m.Phase2, 1, head, mf, identity, m.NewDigest([]byte("fixture archive phase2")).SHA256, "2023-08-23T15:11:30.6Z")
		if err != nil {
			return err
		}
		refs, err := writePair("mirrors/phase2-0001", mr, identity.KeyID, key)
		if err != nil {
			return err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointMirrorRecorded, Record: &refs, Evidence: []m.ArtifactRef{}})
		if err = commit(); err != nil {
			return err
		}
	}
	roundTime, err := m.QuicknetRoundTime(43)
	if err != nil {
		return err
	}
	participants, err := chain.ParticipantIDs()
	if err != nil {
		return err
	}
	closure, err := m.NewCloseRecord(m.CloseRecord{CeremonyID: d.CeremonyID, Phase: m.Phase2, PhaseID: chain.PhaseID, FinalIndex: uint8(len(chain.Records)), FinalPayload: payload, ChainHeadID: head, AcceptedParticipants: participants, BeaconProvider: d.BeaconPolicy.Provider, BeaconNetwork: d.BeaconPolicy.Network, BeaconRound: 43, BeaconNotBefore: roundTime.Format(time.RFC3339Nano), ClosedAt: "2023-08-23T15:11:30.7Z", CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID})
	if err != nil {
		return err
	}
	cr, err := writePair("phase2/closure/record", closure, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2Closed, Record: &cr, Evidence: []m.ArtifactRef{}})
	c.Progress.Phase2Closure = &cr
	for _, badCase := range []struct {
		round        uint64
		closed, want string
	}{
		{42, "2023-08-23T15:11:29Z", "later beacon round"},
		{41, "2023-08-23T15:11:26Z", "later beacon round"},
		{43, "2023-08-23T15:11:30Z", "follow phase1 beacon publication"},
	} {
		badClose := closure
		badClose.BeaconRound = badCase.round
		badClose.ClosedAt = badCase.closed
		when, err := m.QuicknetRoundTime(badCase.round)
		if err != nil {
			return err
		}
		badClose.BeaconNotBefore = when.Format(time.RFC3339Nano)
		badClose, err = m.NewCloseRecord(badClose)
		if err != nil {
			return err
		}
		badRefs, err := writePair("phase2/closure/record", badClose, d.Coordinator.KeyID, coordinator)
		if err != nil {
			return err
		}
		bad := *c
		bad.Transition.Record = &badRefs
		bad.Progress.Phase2Closure = &badRefs
		bad.AcceptedArtifacts = append([]m.ArtifactRef{}, c.AcceptedArtifacts...)
		for i, r := range bad.AcceptedArtifacts {
			if r.Name == badRefs.Record.Name {
				bad.AcceptedArtifacts[i] = badRefs.Record
			}
			if r.Name == badRefs.Signature.Name {
				bad.AcceptedArtifacts[i] = badRefs.Signature
			}
		}
		_, reject := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: bad, Circuit: circuit})
		if reject == nil || !strings.Contains(reject.Error(), badCase.want) {
			return fmt.Errorf("signed bad phase2 closure: want %s, got %v", badCase.want, reject)
		}
	}
	if _, err = writePair("phase2/closure/record", closure, d.Coordinator.KeyID, coordinator); err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	if d.AssurancePolicy.PublicWitnessesPerPhase > 0 {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, 32))
		identity, err := m.NewIdentity("witness-01", "Fixture witness", "witness-key", key.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		wr := m.PublicWitnessReceipt{Schema: m.PublicWitnessReceiptSchema, CeremonyID: d.CeremonyID, Phase: m.Phase2, CloseID: closure.CloseID, ChainHeadID: head, Closure: cr.Record, BeaconRound: 43, BeaconScheduledAt: roundTime.Format(time.RFC3339Nano), PublicationLocationSHA: m.NewDigest([]byte("fixture publication phase2")).SHA256, Witness: identity, ObservedAt: "2023-08-23T15:11:30.8Z"}
		refs, err := writePair("witnesses/phase2", wr, identity.KeyID, key)
		if err != nil {
			return err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointWitnessRecorded, Record: &refs, Evidence: []m.ArtifactRef{}})
		if err = commit(); err != nil {
			return err
		}
	}
	raw := filepath.Join(output, "quicknet-v4-43.json")
	if err = os.WriteFile(raw, []byte(quicknetRound43), 0600); err != nil {
		return err
	}
	beacon, err := m.RecordBeaconFiles(m.RecordBeaconFilesOptions{Trust: trust, TranscriptRoot: root, Phase: m.Phase2, ClosePath: path(cr.Record), CloseSignaturePath: path(cr.Signature), RawResponsePath: raw, PublishedAt: "2023-08-23T15:11:33Z", CoordinatorPrivateKeyPath: coordinatorPath})
	if err != nil {
		return err
	}
	br, err := ref("phase2/beacon/record.json")
	if err != nil {
		return err
	}
	bs, err := ref("phase2/beacon/record.sig")
	if err != nil {
		return err
	}
	brefs := m.SignedArtifactRefs{Record: br, Signature: bs}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2BeaconRecorded, Record: &brefs, Evidence: []m.ArtifactRef{beacon.Beacon.RawResponse}})
	c.Progress.Phase2Beacon = &brefs
	if err = commit(); err != nil {
		return err
	}
	pr := c.Progress
	replay := m.ReplayPaths{TranscriptRoot: root, CoordinatorPublicKeyHex: d.Coordinator.Ed25519PublicKeyHex, DefinitionPath: trust.DefinitionPath, DefinitionSignaturePath: trust.DefinitionSignaturePath, Phase1ChainPath: path(pr.Phase1.Chain.Record), Phase1ChainSignaturePath: path(pr.Phase1.Chain.Signature), Phase1ClosePath: path(pr.Phase1Closure.Record), Phase1CloseSignaturePath: path(pr.Phase1Closure.Signature), Phase1BeaconPath: path(pr.Phase1Beacon.Record), Phase1BeaconSignaturePath: path(pr.Phase1Beacon.Signature), Phase1SealPath: path(pr.Phase1Seal.Record), Phase1SealSignaturePath: path(pr.Phase1Seal.Signature), Phase2ChainPath: path(pr.Phase2.Chain.Record), Phase2ChainSignaturePath: path(pr.Phase2.Chain.Signature), Phase2ClosePath: path(pr.Phase2Closure.Record), Phase2CloseSignaturePath: path(pr.Phase2Closure.Signature), Phase2BeaconPath: path(pr.Phase2Beacon.Record), Phase2BeaconSignaturePath: path(pr.Phase2Beacon.Signature)}
	preliminary := filepath.Join(output, "v4-preliminary")
	if _, err = m.PrepareFinalization(m.PrepareFinalizationOptions{Replay: replay, Circuit: circuit, OutDir: preliminary, CoordinatorSigningKey: coordinatorPath, PreparedAt: mustUTC("2023-08-23T15:11:34Z")}); err != nil {
		return err
	}
	publicEvidence := filepath.Join(output, "v4-public-evidence.json")
	if err = writeTinyPublicEvidence(publicEvidence, d.CeremonyID, circuit, preliminary); err != nil {
		return err
	}
	final := filepath.Join(root, "final/candidate")
	if err = os.MkdirAll(filepath.Dir(final), 0700); err != nil {
		return err
	}
	if _, err = m.Finalize(m.FinalizeOptions{Replay: replay, Circuit: circuit, OutDir: final, CoordinatorSigningKey: coordinatorPath, PublicEvidencePath: publicEvidence, FinalizedAt: mustUTC("2023-08-23T15:11:35Z")}); err != nil {
		return err
	}
	_, refs, err := m.VerifyFinalCandidateCheckpoint(replay, circuit, final)
	if err != nil {
		return err
	}
	var finalRefs m.SignedArtifactRefs
	evidence = []m.ArtifactRef{}
	for _, r := range refs {
		r.Name = "final/candidate/" + r.Name
		switch filepath.Base(r.Name) {
		case m.CandidateMetadataFile:
			finalRefs.Record = r
		case m.CandidateSignatureFile:
			finalRefs.Signature = r
		default:
			evidence = append(evidence, r)
		}
	}
	running, err := m.RunningSoftwareBindingForMode(d.Software.ProofToolVersion, d.Mode)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointFinalCandidateRecorded, Record: &finalRefs, Evidence: sorted(evidence), ReplayVerification: &m.CheckpointReplayVerificationV4{Method: m.CoordinatorReplayReleaseV1, ToolBinary: running.ToolBinary}})
	c.Progress.FinalCandidate = &finalRefs
	if err = commit(); err != nil {
		return err
	}
	// Unsuccessful authoring attempts below are never signed or stored.
	for _, mutation := range []string{"missing-method", "wrong-executable", "missing-file"} {
		bad := *c
		tx := bad.Transition
		claim := *tx.ReplayVerification
		tx.ReplayVerification = &claim
		switch mutation {
		case "missing-method":
			claim.Method = ""
		case "wrong-executable":
			claim.ToolBinary = m.NewDigest([]byte("not the approved verifier"))
		case "missing-file":
			tx.Evidence = append([]m.ArtifactRef{}, tx.Evidence[1:]...)
		}
		bad.Transition = tx
		if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: bad, Circuit: circuit}); err == nil {
			return fmt.Errorf("final candidate accepted %s", mutation)
		}
	}
	extra := filepath.Join(final, "unexpected.txt")
	if err = os.WriteFile(extra, []byte("not in the approved candidate"), 0600); err != nil {
		return err
	}
	_, extraErr := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: *c, Circuit: circuit})
	if err = os.Remove(extra); err != nil {
		return err
	}
	if extraErr == nil {
		return fmt.Errorf("final candidate accepted an extra file")
	}
	fmt.Println("V4 phase2 and final candidate passed: real contribution, cleanup, optional observers, second drand round, coordinator full replay, exact final inventory")
	var committedAudits []m.SignedArtifactRefs
	if d.AssurancePolicy.PassingCeremonyAudits > 0 {
		db, err := os.ReadFile(trust.DefinitionPath)
		if err != nil {
			return err
		}
		for i, identity := range d.Auditors {
			beforeEnrollment := *c
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x83 + i)}, 32))
			keyPath := filepath.Join(output, "identity-keys", identity.ID+".ed25519.private.hex")
			name := "enrollments/" + identity.ID + "/disclosure.txt"
			if err = os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(root, name), []byte("Single-process audit fixture, not independent operators.\n"), 0600); err != nil {
				return err
			}
			disclosure, err := ref(name)
			if err != nil {
				return err
			}
			enrollment, err := m.NewEnrollmentRecord(d, db, identity, m.EnrollmentAuditor, uint16(i+1), disclosure, "2023-08-23T15:11:36Z")
			if err != nil {
				return err
			}
			er, err := writePair("enrollments/"+identity.ID+"/record", enrollment, identity.KeyID, key)
			if err != nil {
				return err
			}
			next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &er, Evidence: []m.ArtifactRef{disclosure}})
			beforeEnrollmentRef := *c.PreviousCheckpoint
			if err = commit(); err != nil {
				return err
			}
			name = "audits/" + identity.ID
			if err = os.MkdirAll(filepath.Join(root, "audits"), 0700); err != nil {
				return err
			}
			if _, err = m.Audit(m.AuditOptions{Replay: replay, Circuit: circuit, CandidateDir: final, AuditorID: identity.ID, AuditorSigningKey: keyPath, OutPath: filepath.Join(root, name+".json"), SignatureOutPath: filepath.Join(root, name+".sig"), AuditedAt: mustUTC("2023-08-23T15:11:37Z")}); err != nil {
				return err
			}
			r, err := ref(name + ".json")
			if err != nil {
				return err
			}
			s, err := ref(name + ".sig")
			if err != nil {
				return err
			}
			ar := m.SignedArtifactRefs{Record: r, Signature: s}
			committedAudits = append(committedAudits, ar)
			next(m.CheckpointTransitionV4{Kind: m.CheckpointAuditRecorded, Record: &ar, Evidence: []m.ArtifactRef{}})
			missing := *c
			missing.Sequence = beforeEnrollment.Sequence + 1
			missing.PreviousCheckpoint = &beforeEnrollmentRef
			missing.AcceptedArtifacts = sorted(append(append([]m.ArtifactRef{}, beforeEnrollment.AcceptedArtifacts...), ar.Record, ar.Signature))
			if _, err := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: missing, Circuit: circuit}); err == nil || !strings.Contains(err.Error(), "committed auditor enrollment") {
				return fmt.Errorf("audit without enrollment: %v", err)
			}
			if err = commit(); err != nil {
				return err
			}
		}
		fmt.Println("V4 audits passed: two real replays, committed enrollment, partial collection then full minimum")
	}
	headRefs := func() (m.SignedArtifactRefs, error) {
		name := fmt.Sprintf("checkpoints/%04d", c.Sequence)
		r, err := ref(name + ".json")
		if err != nil {
			return m.SignedArtifactRefs{}, err
		}
		s, err := ref(name + ".sig")
		return m.SignedArtifactRefs{Record: r, Signature: s}, err
	}
	db, err := os.ReadFile(trust.DefinitionPath)
	if err != nil {
		return err
	}
	owners := []struct {
		identity m.Identity
		role     m.EnrollmentRole
		index    uint16
		seed     byte
	}{
		{d.Coordinator, m.EnrollmentCoordinator, 1, 0x81},
		{d.ReleaseSigner, m.EnrollmentReleaseSigner, 1, 0x82},
	}
	if d.Mode != m.ModeProduction {
		owners = append(owners, struct {
			identity m.Identity
			role     m.EnrollmentRole
			index    uint16
			seed     byte
		}{d.Roster[1].Identity, m.EnrollmentParticipant, 2, 0x92})
	}
	for _, owner := range owners {
		head, err := headRefs()
		if err != nil {
			return err
		}
		missing, err := m.PrepareOperationalBundleV4(trust, root, head, mustUTC("2023-08-23T15:11:38Z"))
		if err == nil || !strings.Contains(err.Error(), "required proof-of-possession enrollment") || missing.Bundle.Schema != "" {
			return fmt.Errorf("missing required %s enrollment did not block bundle: %v", owner.identity.ID, err)
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{owner.seed}, 32))
		name := "enrollments/" + owner.identity.ID + "/disclosure.txt"
		if err = os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(root, name), []byte("One process controls every fixture role; no independence claim.\n"), 0600); err != nil {
			return err
		}
		disclosure, err := ref(name)
		if err != nil {
			return err
		}
		record, err := m.NewEnrollmentRecord(d, db, owner.identity, owner.role, owner.index, disclosure, "2023-08-23T15:11:37.5Z")
		if err != nil {
			return err
		}
		pair, err := writePair("enrollments/"+owner.identity.ID+"/record", record, owner.identity.KeyID, key)
		if err != nil {
			return err
		}
		// Even a valid signed enrollment already on disk is not committed until
		// the coordinator adds it to the authenticated checkpoint history.
		loose, looseErr := m.PrepareOperationalBundleV4(trust, root, head, mustUTC("2023-08-23T15:11:38Z"))
		if looseErr == nil || !strings.Contains(looseErr.Error(), "required proof-of-possession enrollment") || loose.Bundle.Schema != "" {
			return fmt.Errorf("loose uncommitted enrollment was used: %v", looseErr)
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &pair, Evidence: []m.ArtifactRef{disclosure}})
		if err = commit(); err != nil {
			return err
		}
	}
	// Incidents are public, explicitly selected evidence, not automatic logs.
	if err = os.MkdirAll(filepath.Join(root, "governance"), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "governance/statement.txt"), []byte("Single-process rehearsal fixture; no independent operators or erasure evidence.\n"), 0600); err != nil {
		return err
	}
	statement, err := ref("governance/statement.txt")
	if err != nil {
		return err
	}
	incident := m.GovernanceRecord{Schema: m.GovernanceRecordSchema, Kind: m.GovernanceIncident, CeremonyID: d.CeremonyID, Phase: m.Phase2, Index: c.Progress.Phase2.AcceptedCount, HeadID: c.Progress.Phase2.HeadRecordID, Evidence: []m.ArtifactRef{statement}, ReasonCode: "fixture-notice", StatementSHA256: statement.Digest.SHA256, SignerID: d.Coordinator.ID, SignerKeyID: d.Coordinator.KeyID, RecordedAt: "2023-08-23T15:11:37.7Z"}
	ir, err := writePair("governance/incident", incident, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	beforeIncident := *c
	wrongIncident := incident
	wrongIncident.HeadID = c.Progress.Phase1.HeadRecordID
	wrongPair, err := writePair("governance/wrong-head", wrongIncident, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointIncidentRecorded, Record: &wrongPair, Evidence: []m.ArtifactRef{statement}})
	// Deliberately bypass PrepareCheckpointV4: later inspection and bundle
	// preparation must still catch a signed but semantically wrong head.
	wrongCheckpoint, err := writePair("governance/wrong-checkpoint", *c, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	badBundle, rejected := m.PrepareOperationalBundleV4(trust, root, wrongCheckpoint, mustUTC("2023-08-23T15:11:38Z"))
	if rejected == nil || !strings.Contains(rejected.Error(), "exact current phase and head") || badBundle.Bundle.Schema != "" {
		return fmt.Errorf("signed wrong-head incident accepted: %v", rejected)
	}
	*c = beforeIncident
	next(m.CheckpointTransitionV4{Kind: m.CheckpointIncidentRecorded, Record: &ir, Evidence: []m.ArtifactRef{statement}})
	if err = commit(); err != nil {
		return err
	}
	checkpoint, err = headRefs()
	if err != nil {
		return err
	}
	prepared, err := m.PrepareOperationalBundleV4(trust, root, checkpoint, mustUTC("2023-08-23T15:11:38Z"))
	if err != nil {
		return err
	}
	if len(prepared.Bundle.GovernanceRecords) != 1 || prepared.Bundle.GovernanceRecords[0] != ir {
		return fmt.Errorf("committed incident missing from bundle")
	}
	again, err := m.PrepareOperationalBundleV4(trust, root, checkpoint, mustUTC("2023-08-23T15:11:38Z"))
	if err != nil {
		return err
	}
	preparedBytes, err := m.MarshalCanonical(prepared)
	if err != nil {
		return err
	}
	againBytes, err := m.MarshalCanonical(again)
	if err != nil {
		return err
	}
	if !bytes.Equal(preparedBytes, againBytes) || prepared.SourceCheckpoint != checkpoint {
		return fmt.Errorf("bundle derivation was not byte-identical for the same checkpoint and time")
	}
	for _, target := range []string{prepared.Bundle.Phase1.AcceptedHeads[0].AcceptedChainPrefix.Record.Name, prepared.Bundle.Phase2.AcceptedHeads[0].AcceptedChainPrefix.Record.Name, prepared.Bundle.Phase2.RawBeaconResponses[0].Name} {
		original, err := os.ReadFile(filepath.Join(root, target))
		if err != nil {
			return err
		}
		corrupted := bytes.Clone(original)
		corrupted[len(corrupted)-1] ^= 1
		if err = os.WriteFile(filepath.Join(root, target), corrupted, 0600); err != nil {
			return err
		}
		bad, reject := m.PrepareOperationalBundleV4(trust, root, checkpoint, mustUTC("2023-08-23T15:11:38Z"))
		if err = os.WriteFile(filepath.Join(root, target), original, 0600); err != nil {
			return err
		}
		if reject == nil || bad.Bundle.Schema != "" {
			return fmt.Errorf("corrupted bundle input %s was not rejected", target)
		}
	}
	brs, err := writePair("operational/evidence-bundle", prepared.Bundle, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	bb, err := os.ReadFile(path(brs.Record))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(path(brs.Signature))
	if err != nil {
		return err
	}
	first, err := m.LoadAuthenticatedCloseEvidence(root, prepared.Bundle.Phase1.Close)
	if err != nil {
		return err
	}
	second, err := m.LoadAuthenticatedCloseEvidence(root, prepared.Bundle.Phase2.Close)
	if err != nil {
		return err
	}
	if _, err = m.VerifyOperationalEvidenceBundle(m.VerifyOperationalEvidenceOptions{Definition: d, CoordinatorPublicKey: coordinator.Public().(ed25519.PublicKey), EvidenceRoot: root, BundleBytes: bb, BundleSignatureBytes: sig, Phase1Close: first, Phase2Close: second}); err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointReleaseReviewRecorded, Record: &brs, Evidence: []m.ArtifactRef{}})
	c.Progress.ReleaseReview = &brs
	if err = commit(); err != nil {
		return err
	}
	checkpoint, err = headRefs()
	if err != nil {
		return err
	}
	fmt.Println("V4 operational bundle passed: deterministic checkpoint-only assembly, all roster enrollments, original bundle verifier, corruption rejected")
	if err := runCheckpointV4Review(root, trust, d, *c, checkpoint, brs, committedAudits, coordinator); err != nil {
		return err
	}
	beforeStop := *c
	stop := incident
	stop.Kind = m.GovernanceAbort
	stop.ReasonCode = "fixture-stop"
	stopPair, err := writePair("governance/abort", stop, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointAborted, Record: &stopPair, Evidence: []m.ArtifactRef{statement}})
	c.Progress.Terminal = &m.CheckpointTerminalV4{Kind: m.GovernanceAbort, Record: stopPair}
	// Stopping must not require an unrelated retained contribution payload.
	stopPayloadPath := path(c.Progress.Phase1.HeadPayload)
	if err = os.Rename(stopPayloadPath, stopPayloadPath+".stop-test"); err != nil {
		return err
	}
	_, stopErr := m.PrepareCheckpointV4(m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: *c, Circuit: circuit})
	if err = os.Rename(stopPayloadPath+".stop-test", stopPayloadPath); err != nil {
		return err
	}
	if stopErr != nil {
		return fmt.Errorf("stop blocked by unrelated missing payload: %w", stopErr)
	}
	stopped, err := writePair("governance/terminal-checkpoint", *c, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	if _, err = m.VerifyStoredCheckpointV4(trust, root, stopped); err != nil {
		return err
	}
	if result, err := m.PrepareOperationalBundleV4(trust, root, stopped, mustUTC("2023-08-23T15:11:38Z")); err == nil || result.Bundle.Schema != "" {
		return fmt.Errorf("terminal checkpoint allowed release bundle: %v", err)
	}
	*c = beforeStop
	fmt.Println("V4 terminal branch passed: authenticated abort, missing unrelated payload, no release bundle")
	return nil
}
