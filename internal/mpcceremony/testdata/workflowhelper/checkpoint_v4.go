package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

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
		c.AcceptedArtifacts = sorted(refs)
	}
	if err := commit(); err != nil {
		return err
	}
	p := d.Roster[0].Identity
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
	inventory := m.CandidateInventory{Schema: m.CandidateInventorySchemaV1, Scope: scope, Files: append([]m.ArtifactRef{}, files...)}
	for i := range inventory.Files {
		inventory.Files[i].Name = filepath.Base(inventory.Files[i].Name)
	}
	next(m.CheckpointTransitionV4{Kind: m.CheckpointPhase1CandidateAccepted, Scope: &scope, AttemptID: candidateAttempt, Record: &chainRefs, Evidence: sorted(append(files, last.Verification)), Contribution: &inventory})
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
	fmt.Println("V4 real phase1 turn passed: initial, outbound, retirement, reallocation, receipt, contribution, cleanup, full replay, exact acceptance, corruption rejected")
	return nil
}
