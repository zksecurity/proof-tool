package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	m "proof-tool/internal/mpcceremony"
)

// addSecondProductionContribution completes the signed schedule in the local
// production-mode fixture. Every key is deterministic test material and every
// participant role is operated by this one process; this is a control-flow test.
func addSecondProductionContribution(
	output, root string, trust m.TrustPaths, circuit *m.CompiledCircuit,
	d m.CeremonyDefinition, phase m.Phase, c *m.CheckpointV4,
	committed *m.SignedArtifactRefs, coordinatorPath string,
	next func(m.CheckpointTransitionV4), commit func() error,
	writePair func(string, any, string, ed25519.PrivateKey) (m.SignedArtifactRefs, error),
	ref func(string) (m.ArtifactRef, error),
) (m.Chain, m.SignedArtifactRefs, error) {
	var empty m.Chain
	var emptyRefs m.SignedArtifactRefs
	participant := d.Roster[1].Identity
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x92}, ed25519.SeedSize))
	keyPath := filepath.Join(output, "identity-keys", "participant-02.ed25519.private.hex")
	if phase == m.Phase1 {
		name := "enrollments/participant-02/disclosure.txt"
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			return empty, emptyRefs, err
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte("Single-process test fixture; no independent custody.\n"), 0600); err != nil {
			return empty, emptyRefs, err
		}
		disclosure, err := ref(name)
		if err != nil {
			return empty, emptyRefs, err
		}
		db, err := os.ReadFile(trust.DefinitionPath)
		if err != nil {
			return empty, emptyRefs, err
		}
		enrollment, err := m.NewEnrollmentRecord(d, db, participant, m.EnrollmentParticipant, 2, disclosure, "2023-08-23T15:05:01Z")
		if err != nil {
			return empty, emptyRefs, err
		}
		pair, err := writePair("enrollments/participant-02/record", enrollment, participant.KeyID, key)
		if err != nil {
			return empty, emptyRefs, err
		}
		next(m.CheckpointTransitionV4{Kind: m.CheckpointEnrollmentRecorded, Record: &pair, Evidence: []m.ArtifactRef{disclosure}})
		if err := commit(); err != nil {
			return empty, emptyRefs, err
		}
	}
	state := c.Progress.Phase1
	if phase == m.Phase2 {
		state = *c.Progress.Phase2
	}
	scope := m.ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: 2, ParticipantID: participant.ID, ParentHeadID: state.HeadRecordID}
	attempt := "abababababababababababababababab"
	allocatedAt, contributedAt, destroyedAt, acceptedAt := "2023-08-23T15:05:02Z", "2023-08-23T15:05:03Z", "2023-08-23T15:05:04Z", "2023-08-23T15:05:05Z"
	if phase == m.Phase2 {
		attempt = strings.Repeat("bc", 16)
		allocatedAt, contributedAt, destroyedAt, acceptedAt = "2023-08-23T15:11:30.51Z", "2023-08-23T15:11:30.52Z", "2023-08-23T15:11:30.53Z", "2023-08-23T15:11:30.54Z"
	}
	allocated, err := m.PrepareCandidateAllocationCheckpointV4(m.CandidateAllocationCheckpointV4Options{Trust: trust, ArtifactRoot: root, Checkpoint: *committed, AttemptID: attempt, AllocatedAt: allocatedAt})
	if err != nil {
		return empty, emptyRefs, err
	}
	if allocated.Scope != scope {
		return empty, emptyRefs, fmt.Errorf("%s second allocation differs from signed schedule", phase)
	}
	*c = allocated.Checkpoint
	if err := commit(); err != nil {
		return empty, emptyRefs, err
	}
	headr, err := ref(fmt.Sprintf("checkpoints/%04d.json", c.Sequence))
	if err != nil {
		return empty, emptyRefs, err
	}
	heads, err := ref(fmt.Sprintf("checkpoints/%04d.sig", c.Sequence))
	if err != nil {
		return empty, emptyRefs, err
	}
	*committed = m.SignedArtifactRefs{Record: headr, Signature: heads}
	dir := filepath.Join(output, "candidates", "v4-"+string(phase)+"-second")
	environment := m.ContributionEnvironment{OS: runtime.GOOS, Architecture: runtime.GOARCH, EntropySource: "operating-system-csprng", ContributorSwapDisabled: true, ContributorCrashDumpsDisabled: true, ContributorTelemetryDisabled: true, EphemeralEnvironment: true, EphemeralCleanupRequired: true, HostRemnantsNotExcluded: true}
	if _, err := m.CreateAllocatedContributionCandidateV4(m.AllocatedContributionFilesV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: *committed, AttemptID: attempt, ExpectedPhase: phase, ExpectedParticipantID: participant.ID, ParticipantPrivateKeyPath: keyPath, Environment: environment, ContributedAt: contributedAt, CandidateDir: dir}); err != nil {
		return empty, emptyRefs, err
	}
	if _, err := m.CreateErasureAttestationFiles(m.CreateErasureAttestationFilesOptions{Trust: trust, ParticipantID: participant.ID, ParticipantPrivateKeyPath: keyPath, CandidateDir: dir, DestroyedAt: destroyedAt}); err != nil {
		return empty, emptyRefs, err
	}
	accepted, err := m.VerifyAndAcceptAllocatedCandidateV4(m.AcceptAllocatedCandidateV4Options{Trust: trust, Circuit: circuit, ArtifactRoot: root, Checkpoint: *committed, AttemptID: attempt, CandidateDir: dir, CoordinatorPrivateKeyPath: coordinatorPath, AcceptedAt: acceptedAt})
	if err != nil {
		return empty, emptyRefs, err
	}
	*c = accepted.Checkpoint
	if err := commit(); err != nil {
		return empty, emptyRefs, err
	}
	paths := m.PhaseTranscriptPaths{RootDir: root, ChainPath: accepted.Accepted.ChainPath, ChainSignaturePath: accepted.Accepted.ChainSignaturePath}
	if phase == m.Phase1 {
		return m.VerifyAcceptedPhase1Chain(trust, circuit, paths)
	}
	seal := *c.Progress.Phase1Seal
	return m.VerifyAcceptedPhase2Chain(trust, circuit, root, filepath.Join(root, seal.Record.Name), filepath.Join(root, seal.Signature.Name), paths)
}
