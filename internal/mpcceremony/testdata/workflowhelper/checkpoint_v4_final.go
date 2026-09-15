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
	handoff, err := m.NewTransferHandoff(d, m.Phase2, 1, scope.ParentHeadID, []m.ArtifactRef{c.Progress.Phase2.HeadPayload}, d.Coordinator, p, "2023-08-23T15:11:30.1Z", "2023-08-23T16:11:30.1Z")
	if err != nil {
		return err
	}
	hr, err := writePair("custody/phase2-outbound", handoff, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	const receiptAttempt = "dddddddddddddddddddddddddddddddd"
	const candidateAttempt = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2OutboundPublished, Scope: &scope, AttemptID: receiptAttempt, Record: &hr, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AllocateDeliveryV2(c.Deliveries, scope, m.CheckpointSubmissionReceipt, receiptAttempt)
	if err != nil {
		return err
	}
	if err = commit(); err != nil {
		return err
	}
	hb, err := os.ReadFile(path(hr.Record))
	if err != nil {
		return err
	}
	receipt, err := m.NewTransferReceipt(handoff, hb, m.ReceiptReceiver, "2023-08-23T15:11:30.2Z")
	if err != nil {
		return err
	}
	rr, err := writePair("custody/phase2-receipt", receipt, p.KeyID, participant)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase2ReceiptAccepted, Scope: &scope, AttemptID: receiptAttempt, NextAttemptID: candidateAttempt, Record: &rr, Evidence: []m.ArtifactRef{}})
	c.Deliveries, err = m.AdvanceDeliveryV2(c.Deliveries, receiptAttempt, m.DeliveryAccepted, nil)
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
	candidateDir := filepath.Join(output, "candidates/v4-phase2")
	environment := m.ContributionEnvironment{OS: runtime.GOOS, Architecture: runtime.GOARCH, EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}
	if _, err = m.CreateContributionCandidate(m.ContributionFilesOptions{Trust: trust, Circuit: circuit, Phase: m.Phase2, Transcript: paths, Phase1SealPath: path(seal.Record), Phase1SealSignaturePath: path(seal.Signature), ParticipantID: p.ID, ParticipantPrivateKeyPath: participantPath, Environment: environment, ContributedAt: "2023-08-23T15:11:30.3Z", CandidateDir: candidateDir}); err != nil {
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
	rh, err := m.NewTransferHandoff(d, m.Phase2, 1, scope.ParentHeadID, files, p, d.Coordinator, "2023-08-23T15:11:30.41Z", "2023-08-23T16:11:30.41Z")
	if err != nil {
		return err
	}
	rhr, err := writePair("custody/phase2-return-handoff", rh, p.KeyID, participant)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path(rhr.Record))
	if err != nil {
		return err
	}
	returnReceipt, err := m.NewTransferReceipt(rh, b, m.ReceiptReceiver, "2023-08-23T15:11:30.42Z")
	if err != nil {
		return err
	}
	rrr, err := writePair("custody/phase2-return-receipt", returnReceipt, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	accepted, err := m.VerifyAndAcceptContribution(m.AcceptContributionFilesOptions{Trust: trust, Circuit: circuit, Phase: m.Phase2, Transcript: paths, Phase1SealPath: path(seal.Record), Phase1SealSignaturePath: path(seal.Signature), CandidateDir: candidateDir, CoordinatorPrivateKeyPath: coordinatorPath, AcceptedAt: "2023-08-23T15:11:30.5Z"})
	if err != nil {
		return err
	}
	paths.ChainPath, paths.ChainSignaturePath = accepted.ChainPath, accepted.ChainSignaturePath
	chain, chainRefs, err := m.VerifyAcceptedPhase2Chain(trust, circuit, root, path(seal.Record), path(seal.Signature), paths)
	if err != nil {
		return err
	}
	last := chain.Records[0]
	files = []m.ArtifactRef{last.Attestation, last.AttestationSignature, last.OutputPayload, last.Erasure, last.ErasureSignature}
	returns := []m.ArtifactRef{}
	for i, pair := range []m.SignedArtifactRefs{rhr, rrr} {
		base := "return-handoff"
		if i == 1 {
			base = "return-receipt"
		}
		for j, r := range []m.ArtifactRef{pair.Record, pair.Signature} {
			ext := ".json"
			if j == 1 {
				ext = ".sig"
			}
			b, err := os.ReadFile(path(r))
			if err != nil {
				return err
			}
			name := "phase2/contributions/0001/" + base + ext
			if err = os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
				return err
			}
			returns = append(returns, m.ArtifactRef{Name: name, Digest: m.NewDigest(b)})
		}
	}
	files = append(files, returns[:2]...)
	inv := m.CandidateInventory{Schema: m.CandidateInventorySchemaV1, Scope: scope, Files: append([]m.ArtifactRef{}, files...)}
	for i := range inv.Files {
		inv.Files[i].Name = filepath.Base(inv.Files[i].Name)
	}
	evidence := append(append([]m.ArtifactRef{}, files...), returns[2:]...)
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
	if err = commit(); err != nil {
		return err
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
	closure, err := m.NewCloseRecord(m.CloseRecord{CeremonyID: d.CeremonyID, Phase: m.Phase2, PhaseID: chain.PhaseID, FinalIndex: 1, FinalPayload: payload, ChainHeadID: head, AcceptedParticipants: participants, BeaconProvider: d.BeaconPolicy.Provider, BeaconNetwork: d.BeaconPolicy.Network, BeaconRound: 43, BeaconNotBefore: roundTime.Format(time.RFC3339Nano), ClosedAt: "2023-08-23T15:11:30.7Z", CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID})
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
	be := m.MultiRelayBeaconEvidence{Schema: m.MultiRelayBeaconEvidenceSchema, CeremonyID: d.CeremonyID, Phase: m.Phase2, CloseID: closure.CloseID, BeaconRound: 43, Provider: d.BeaconPolicy.Provider, Network: d.BeaconPolicy.Network, CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID, RecordedAt: "2023-08-23T15:11:33Z"}
	raws := []m.ArtifactRef{}
	for _, id := range []string{"fixture-a", "fixture-b"} {
		name := "phase2/beacon-evidence/" + id + ".json"
		if err = os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(root, name), []byte(quicknetRound43), 0600); err != nil {
			return err
		}
		r, err := ref(name)
		if err != nil {
			return err
		}
		raws = append(raws, r)
		be.Observations = append(be.Observations, m.RelayObservation{RelayID: id, OperatorID: id, EndpointSHA256: m.NewDigest([]byte(id)).SHA256, RawResponse: r, RetrievedAt: "2023-08-23T15:11:33Z", VerifiedRandomness: beacon.Beacon.RandomnessHex})
	}
	ber, err := writePair("phase2/beacon-evidence/record", be, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointBeaconEvidenceRecorded, Record: &ber, Evidence: sorted(raws)})
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
	fmt.Println("V4 phase2 and final candidate passed: real contribution, custody, optional observers, second drand round, coordinator full replay, exact final inventory")
	return nil
}
