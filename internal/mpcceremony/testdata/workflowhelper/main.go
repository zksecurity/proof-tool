package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/blake2b"

	"proof-tool/internal/circuit/rehearsal"
	"proof-tool/internal/mpcceremony"
	"proof-tool/internal/prover"
)

const (
	quicknetRound42 = `{"round":42,"randomness":"8ada64bae5c6c0f5540a6a13af56e663240edfbd2c76ac6a8f27671eb7259ce3","signature":"95a9f9f5b231b7714de1553105d8ffdf3dcda24cfdb1e689319bccf79a9c8ce430a91b811fbfaf763900bc998b5d686a"}`
	quicknetRound43 = `{"round":43,"randomness":"c8f7c61c7024f8b45ffbf5be58b1f112a26be93c26f5461af9f8522233705dbb","signature":"a96a579010b3d2261959104b29b5b46685b3a6b6f6aae7304ef72d44fe7d44e667bcdd500935d7deb58a2b4d89419ea6"}`
)

type tinyCommittedCircuit struct {
	Public frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

func (c *tinyCommittedCircuit) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("compiler does not implement frontend.Committer")
	}
	commitment, err := committer.Commit(c.Secret)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	api.AssertIsEqual(c.Public, c.Secret)
	return nil
}

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: workflowhelper OUTPUT_ROOT [OPERATIONAL_EVIDENCE_HELPER]")
		os.Exit(2)
	}
	operationalEvidenceHelper := ""
	if len(os.Args) == 3 {
		operationalEvidenceHelper = os.Args[2]
	}
	if err := run(os.Args[1], operationalEvidenceHelper); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(outputRoot, operationalEvidenceHelper string) error {
	checkpointV4 := os.Getenv("MPC_WORKFLOW_CHECKPOINT_V4") == "1"
	zeroAssurance := os.Getenv("PROOF_TOOL_TEST_ZERO_ASSURANCE") == "1"
	checkpointPhase2One := os.Getenv("MPC_WORKFLOW_PHASE2_ONE") == "1"
	var circuit *mpcceremony.CompiledCircuit
	var err error
	if checkpointPhase2One || checkpointV4 {
		circuit, err = mpcceremony.CompileForKeyVersion(mpcceremony.KeyVersionRehearsal)
	} else {
		compiled, compileErr := frontend.Compile(
			ecc.BLS12_381.ScalarField(),
			r1cs.NewBuilder,
			&tinyCommittedCircuit{},
		)
		if compileErr != nil {
			return fmt.Errorf("compile tiny circuit: %w", compileErr)
		}
		native, ok := compiled.(*cs.R1CS)
		if !ok {
			return fmt.Errorf("compiled circuit type %T, want *bls12-381.R1CS", compiled)
		}
		circuit, err = mpcceremony.BindDestinationV2R1CS(native)
	}
	if err != nil {
		return fmt.Errorf("compile tiny circuit: %w", err)
	}
	var software mpcceremony.SoftwareBinding
	if binary := os.Getenv("MPC_CEREMONY_TEST_BINARY"); binary != "" {
		software, err = mpcceremony.SoftwareBindingFromExecutableFileForMode(binary, prover.ProofToolVersion, mpcceremony.ModeRehearsal)
		if err != nil {
			return fmt.Errorf("bind test command executable: %w", err)
		}
	} else {
		software, err = mpcceremony.RunningSoftwareBindingForMode(prover.ProofToolVersion, mpcceremony.ModeRehearsal)
		if err != nil {
			return fmt.Errorf("bind helper executable: %w", err)
		}
	}

	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		return err
	}
	keyDir := filepath.Join(outputRoot, "identity-keys")
	candidateRoot := filepath.Join(outputRoot, "candidates")
	for _, dir := range []string{keyDir, candidateRoot} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
	}

	privateKey := func(fill byte) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	}
	coordinatorPrivate := privateKey(0x81)
	releasePrivate := privateKey(0x82)
	auditor1Private := privateKey(0x83)
	auditor2Private := privateKey(0x84)
	participant1Private := privateKey(0x91)
	participant2Private := privateKey(0x92)
	identity := func(id string, key ed25519.PrivateKey) (mpcceremony.Identity, error) {
		return mpcceremony.NewIdentity(
			id,
			"Integration "+id,
			id+"-key",
			key.Public().(ed25519.PublicKey),
		)
	}
	coordinator, err := identity("coordinator", coordinatorPrivate)
	if err != nil {
		return err
	}
	releaseSigner, err := identity("release-signer", releasePrivate)
	if err != nil {
		return err
	}
	auditor1, err := identity("auditor-01", auditor1Private)
	if err != nil {
		return err
	}
	auditor2, err := identity("auditor-02", auditor2Private)
	if err != nil {
		return err
	}
	participant1, err := identity("participant-01", participant1Private)
	if err != nil {
		return err
	}
	participant2, err := identity("participant-02", participant2Private)
	if err != nil {
		return err
	}
	writePrivateKey := func(name string, key ed25519.PrivateKey) (string, error) {
		path := filepath.Join(keyDir, name+".ed25519.private.hex")
		err := os.WriteFile(path, []byte(hex.EncodeToString(key.Seed())+"\n"), 0o600)
		return path, err
	}
	coordinatorKeyPath, err := writePrivateKey("coordinator", coordinatorPrivate)
	if err != nil {
		return err
	}
	participant1KeyPath, err := writePrivateKey("participant-01", participant1Private)
	if err != nil {
		return err
	}
	participant2KeyPath, err := writePrivateKey("participant-02", participant2Private)
	if err != nil {
		return err
	}
	releaseKeyPath, err := writePrivateKey("release-signer", releasePrivate)
	if err != nil {
		return err
	}
	auditor1KeyPath, auditor2KeyPath := "", ""
	if !zeroAssurance {
		auditor1KeyPath, err = writePrivateKey("auditor-01", auditor1Private)
		if err != nil {
			return err
		}
		auditor2KeyPath, err = writePrivateKey("auditor-02", auditor2Private)
		if err != nil {
			return err
		}
	}
	externalKeys := []struct {
		name string
		fill byte
	}{
		{name: "witness-01", fill: 0xa1},
		{name: "witness-02", fill: 0xa2},
		{name: "mirror-01", fill: 0xb1},
		{name: "mirror-02", fill: 0xb2},
	}
	if !zeroAssurance {
		for _, external := range externalKeys {
			if _, err := writePrivateKey(external.name, privateKey(external.fill)); err != nil {
				return err
			}
		}
	}
	trustedCoordinatorPath := filepath.Join(keyDir, "trusted-coordinator.ed25519.public.hex")
	if err := os.WriteFile(
		trustedCoordinatorPath,
		[]byte(hex.EncodeToString(coordinatorPrivate.Public().(ed25519.PublicKey))+"\n"),
		0o600,
	); err != nil {
		return err
	}

	ceremonyRoot := filepath.Join(outputRoot, "ceremony")
	phaseMinimum := uint8(2)
	phase2Minimum := uint8(2)
	if os.Getenv("MPC_WORKFLOW_PHASE1_ONE") == "1" || checkpointPhase2One || checkpointV4 {
		phaseMinimum = 1
	}
	if checkpointPhase2One || checkpointV4 {
		phase2Minimum = 1
	}
	auditors := []mpcceremony.Identity{}
	assurance := &mpcceremony.AssurancePolicy{}
	if !zeroAssurance {
		auditors = []mpcceremony.Identity{auditor1, auditor2}
		assurance.PublicWitnessesPerPhase = 1
		assurance.MirrorsPerAcceptedHead = 1
		assurance.PassingCeremonyAudits = 1
	}
	releaseVerification := ""
	if checkpointV4 {
		releaseVerification = mpcceremony.CoordinatorReplayReleaseV1
		if os.Getenv("MPC_WORKFLOW_V4_MIRROR") == "1" {
			assurance.MirrorsPerAcceptedHead = 1
			assurance.PublicWitnessesPerPhase = 1
		}
	}
	initialized, err := mpcceremony.InitializeCeremonyFiles(mpcceremony.InitFilesOptions{
		RootDir: ceremonyRoot,
		Circuit: circuit,
		Definition: mpcceremony.DefinitionOptions{
			ReleaseVerification: releaseVerification,
			Mode:                mpcceremony.ModeRehearsal,
			CreatedAt:           "2023-08-23T15:00:00Z",
			SessionNonceHex:     "abababababababababababababababababababababababababababababababab",
			Software:            software,
			Coordinator:         coordinator,
			ReleaseSigner:       releaseSigner,
			Auditors:            auditors,
			AssurancePolicy:     assurance,
			Roster: []mpcceremony.Participant{
				{Identity: participant1},
				{Identity: participant2},
			},
			Phase1Policy: mpcceremony.PhasePolicy{
				Participants: []string{"participant-01", "participant-02"},
				Minimum:      phaseMinimum,
			},
			Phase2Policy: mpcceremony.PhasePolicy{
				Participants: []string{"participant-01", "participant-02"},
				Minimum:      phase2Minimum,
			},
			BeaconPolicy: mpcceremony.BeaconPolicy{
				Provider:                  mpcceremony.BeaconProviderDrand,
				Network:                   mpcceremony.BeaconNetworkQuicknet,
				ChainHashHex:              mpcceremony.BeaconQuicknetChainHash,
				PublicKeyHex:              mpcceremony.BeaconQuicknetPublicKey,
				Scheme:                    mpcceremony.BeaconQuicknetScheme,
				GenesisTimeUnix:           mpcceremony.BeaconQuicknetGenesis,
				PeriodSeconds:             mpcceremony.BeaconQuicknetPeriod,
				Extraction:                mpcceremony.BeaconExtractionV1,
				MinimumChallengeBytes:     32,
				MinimumWitnessLeadSeconds: 1,
				FutureRoundRequired:       true,
			},
		},
		CoordinatorPrivateKeyPath: coordinatorKeyPath,
	})
	if err != nil {
		return fmt.Errorf("initialize ceremony: %w", err)
	}
	trust := mpcceremony.TrustPaths{
		DefinitionPath:           initialized.DefinitionPath,
		DefinitionSignaturePath:  initialized.DefinitionSignaturePath,
		CoordinatorPublicKeyPath: trustedCoordinatorPath,
	}
	trusted, err := mpcceremony.LoadSignedDefinition(trust)
	if err != nil {
		return err
	}
	if checkpointV4 {
		return runCheckpointV4Turn(outputRoot, ceremonyRoot, trust, circuit, trusted.Definition, coordinatorPrivate, coordinatorKeyPath, participant1Private, participant1KeyPath)
	}
	writeHistoricalClose := func(
		phase mpcceremony.Phase,
		chain mpcceremony.Chain,
		round uint64,
		closedAt string,
	) (mpcceremony.ClosePhaseFilesResult, error) {
		roundTime, err := mpcceremony.QuicknetRoundTime(round)
		if err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		headID, _ := chain.HeadRecordID()
		headPayload, _ := chain.HeadPayload()
		participants, _ := chain.ParticipantIDs()
		closeRecord, err := mpcceremony.NewCloseRecord(mpcceremony.CloseRecord{
			CeremonyID:           trusted.Definition.CeremonyID,
			Phase:                phase,
			PhaseID:              chain.PhaseID,
			FinalIndex:           uint8(len(chain.Records)),
			FinalPayload:         headPayload,
			ChainHeadID:          headID,
			AcceptedParticipants: participants,
			BeaconProvider:       trusted.Definition.BeaconPolicy.Provider,
			BeaconNetwork:        trusted.Definition.BeaconPolicy.Network,
			BeaconRound:          round,
			BeaconNotBefore:      roundTime.Format(time.RFC3339Nano),
			ClosedAt:             closedAt,
			CoordinatorID:        trusted.Definition.Coordinator.ID,
			CoordinatorKeyID:     trusted.Definition.Coordinator.KeyID,
		})
		if err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		if err := mpcceremony.ValidateClose(trusted.Definition, chain, closeRecord); err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		recordBytes, signatureBytes, err := mpcceremony.SignRecord(
			closeRecord,
			trusted.Definition.Coordinator.KeyID,
			coordinatorPrivate,
		)
		if err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		closeDir := filepath.Join(ceremonyRoot, string(phase), "closure")
		if err := os.Mkdir(closeDir, 0o700); err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		recordPath := filepath.Join(closeDir, "record.json")
		signaturePath := filepath.Join(closeDir, "record.sig")
		if err := os.WriteFile(signaturePath, signatureBytes, 0o600); err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		if err := os.WriteFile(recordPath, recordBytes, 0o600); err != nil {
			return mpcceremony.ClosePhaseFilesResult{}, err
		}
		return mpcceremony.ClosePhaseFilesResult{
			Close:         closeRecord,
			ClosePath:     recordPath,
			SignaturePath: signaturePath,
		}, nil
	}
	environment := mpcceremony.ContributionEnvironment{
		OS:                            "linux",
		Architecture:                  "amd64",
		EntropySource:                 "operating-system-csprng",
		ContributorSwapDisabled:       true,
		ContributorCrashDumpsDisabled: true,
		ContributorTelemetryDisabled:  true,
		EphemeralEnvironment:          true,
		EphemeralCleanupRequired:      true,
		HostRemnantsNotExcluded:       true,
	}
	environmentPath := filepath.Join(outputRoot, "environment.json")
	environmentBytes, err := mpcceremony.MarshalCanonical(environment)
	if err != nil {
		return err
	}
	if err := os.WriteFile(environmentPath, environmentBytes, 0o600); err != nil {
		return err
	}
	testCommand := os.Getenv("MPC_CEREMONY_TEST_BINARY")
	runTestCommand := func(args ...string) error {
		output, commandErr := exec.Command(testCommand, args...).CombinedOutput()
		if commandErr != nil {
			return fmt.Errorf("run test mpc-ceremony %s: %w\n%s", strings.Join(args[:2], " "), commandErr, output)
		}
		return nil
	}
	participantKeyPaths := []string{participant1KeyPath, participant2KeyPath}
	contributeAndAccept := func(
		phase mpcceremony.Phase,
		index int,
		chainPaths mpcceremony.PhaseTranscriptPaths,
		phase1SealPath string,
		phase1SealSignaturePath string,
		contributedAt string,
		destroyedAt string,
		acceptedAt string,
	) (mpcceremony.PhaseTranscriptPaths, error) {
		participantID := fmt.Sprintf("participant-%02d", index)
		candidateDir := filepath.Join(
			candidateRoot,
			fmt.Sprintf("%s-%s", phase, participantID),
		)
		if testCommand != "" {
			command := []string{string(phase), "contribute",
				"--ceremony", trust.DefinitionPath,
				"--ceremony-signature", trust.DefinitionSignaturePath,
				"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
				"--transcript-dir", ceremonyRoot,
				"--chain", chainPaths.ChainPath,
				"--chain-signature", chainPaths.ChainSignaturePath,
				"--participant-id", participantID,
				"--participant-signing-key", participantKeyPaths[index-1],
				"--environment", environmentPath,
				"--contributed-at", contributedAt,
				"--out-dir", candidateDir,
			}
			if phase == mpcceremony.Phase2 {
				command = append(command,
					"--phase1-seal", phase1SealPath,
					"--phase1-seal-signature", phase1SealSignaturePath,
				)
			}
			if err := runTestCommand(command...); err != nil {
				return mpcceremony.PhaseTranscriptPaths{}, err
			}
			if err := runTestCommand(
				string(phase), "attest-erasure",
				"--ceremony", trust.DefinitionPath,
				"--ceremony-signature", trust.DefinitionSignaturePath,
				"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
				"--participant-id", participantID,
				"--participant-signing-key", participantKeyPaths[index-1],
				"--candidate-dir", candidateDir,
				"--destroyed-at", destroyedAt,
			); err != nil {
				return mpcceremony.PhaseTranscriptPaths{}, err
			}
			command = []string{string(phase), "verify",
				"--ceremony", trust.DefinitionPath,
				"--ceremony-signature", trust.DefinitionSignaturePath,
				"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
				"--transcript-dir", ceremonyRoot,
				"--chain", chainPaths.ChainPath,
				"--chain-signature", chainPaths.ChainSignaturePath,
				"--candidate-dir", candidateDir,
				"--coordinator-signing-key", coordinatorKeyPath,
				"--accepted-at", acceptedAt,
			}
			if phase == mpcceremony.Phase2 {
				command = append(command,
					"--phase1-seal", phase1SealPath,
					"--phase1-seal-signature", phase1SealSignaturePath,
				)
			}
			if err := runTestCommand(command...); err != nil {
				return mpcceremony.PhaseTranscriptPaths{}, err
			}
			return mpcceremony.PhaseTranscriptPaths{
				RootDir:            ceremonyRoot,
				ChainPath:          filepath.Join(ceremonyRoot, string(phase), fmt.Sprintf("chain-%04d.json", index)),
				ChainSignaturePath: filepath.Join(ceremonyRoot, string(phase), fmt.Sprintf("chain-%04d.sig", index)),
			}, nil
		}
		if _, err := mpcceremony.CreateContributionCandidate(
			mpcceremony.ContributionFilesOptions{
				Trust:                     trust,
				Circuit:                   circuit,
				Phase:                     phase,
				Transcript:                chainPaths,
				Phase1SealPath:            phase1SealPath,
				Phase1SealSignaturePath:   phase1SealSignaturePath,
				ParticipantID:             participantID,
				ParticipantPrivateKeyPath: participantKeyPaths[index-1],
				Environment:               environment,
				ContributedAt:             contributedAt,
				CandidateDir:              candidateDir,
			},
		); err != nil {
			return mpcceremony.PhaseTranscriptPaths{}, err
		}
		if _, err := mpcceremony.CreateErasureAttestationFiles(
			mpcceremony.CreateErasureAttestationFilesOptions{
				Trust:                     trust,
				ParticipantID:             participantID,
				ParticipantPrivateKeyPath: participantKeyPaths[index-1],
				CandidateDir:              candidateDir,
				DestroyedAt:               destroyedAt,
			},
		); err != nil {
			return mpcceremony.PhaseTranscriptPaths{}, err
		}
		accepted, err := mpcceremony.VerifyAndAcceptContribution(
			mpcceremony.AcceptContributionFilesOptions{
				Trust:                     trust,
				Circuit:                   circuit,
				Phase:                     phase,
				Transcript:                chainPaths,
				Phase1SealPath:            phase1SealPath,
				Phase1SealSignaturePath:   phase1SealSignaturePath,
				CandidateDir:              candidateDir,
				CoordinatorPrivateKeyPath: coordinatorKeyPath,
				AcceptedAt:                acceptedAt,
			},
		)
		if err != nil {
			return mpcceremony.PhaseTranscriptPaths{}, err
		}
		return mpcceremony.PhaseTranscriptPaths{
			RootDir:            ceremonyRoot,
			ChainPath:          accepted.ChainPath,
			ChainSignaturePath: accepted.ChainSignaturePath,
		}, nil
	}

	phase1Paths := mpcceremony.PhaseTranscriptPaths{
		RootDir:            ceremonyRoot,
		ChainPath:          initialized.Phase1ChainPath,
		ChainSignaturePath: initialized.Phase1ChainSignaturePath,
	}
	phase1Paths, err = contributeAndAccept(
		mpcceremony.Phase1,
		1,
		phase1Paths,
		"",
		"",
		"2023-08-23T15:01:00Z",
		"2023-08-23T15:01:01Z",
		"2023-08-23T15:02:00Z",
	)
	if err != nil {
		return fmt.Errorf("Phase 1 participant 1: %w", err)
	}
	checkpointPhase1One := os.Getenv("MPC_WORKFLOW_PHASE1_ONE") == "1"
	if !checkpointPhase1One && !checkpointPhase2One {
		phase1Paths, err = contributeAndAccept(
			mpcceremony.Phase1,
			2,
			phase1Paths,
			"",
			"",
			"2023-08-23T15:03:00Z",
			"2023-08-23T15:03:01Z",
			"2023-08-23T15:04:00Z",
		)
		if err != nil {
			return fmt.Errorf("Phase 1 participant 2: %w", err)
		}
	}
	phase1Chain, err := mpcceremony.LoadReplayPhase1Files(trusted, circuit, phase1Paths)
	if err != nil {
		return fmt.Errorf("replay Phase 1 before historical test closure: %w", err)
	}
	// Historical drand fixtures exercise downstream replay and beacon binding.
	// Production closure timing is tested inside package mpcceremony and is
	// never bypassed by the participant-facing CLI.
	phase1Close, err := writeHistoricalClose(
		mpcceremony.Phase1,
		phase1Chain,
		42,
		"2023-08-23T15:05:00Z",
	)
	if err != nil {
		return fmt.Errorf("close Phase 1: %w", err)
	}
	round42Path := filepath.Join(outputRoot, "quicknet-round-42.json")
	if err := os.WriteFile(round42Path, []byte(quicknetRound42), 0o600); err != nil {
		return err
	}
	var phase1Seal mpcceremony.SealPhase1FilesResult
	var phase1Beacon mpcceremony.RecordBeaconFilesResult
	if (checkpointPhase1One || checkpointPhase2One) && testCommand != "" {
		if err := runTestCommand("phase1", "beacon",
			"--ceremony", trust.DefinitionPath,
			"--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
			"--closure", phase1Close.ClosePath,
			"--closure-signature", phase1Close.SignaturePath,
			"--raw-response", round42Path,
			"--published-at", "2023-08-23T15:11:30Z",
			"--coordinator-signing-key", coordinatorKeyPath,
			"--transcript-dir", ceremonyRoot,
		); err != nil {
			return fmt.Errorf("record checkpoint Phase 1 beacon: %w", err)
		}
		if err := runTestCommand("phase1", "seal",
			"--ceremony", trust.DefinitionPath,
			"--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
			"--transcript-dir", ceremonyRoot,
			"--closure", phase1Close.ClosePath,
			"--closure-signature", phase1Close.SignaturePath,
			"--beacon", filepath.Join(ceremonyRoot, "phase1", "beacon", "record.json"),
			"--beacon-signature", filepath.Join(ceremonyRoot, "phase1", "beacon", "record.sig"),
			"--coordinator-signing-key", coordinatorKeyPath,
			"--out-dir", filepath.Join(ceremonyRoot, "phase1", "sealed"),
		); err != nil {
			return fmt.Errorf("seal checkpoint Phase 1: %w", err)
		}
		if checkpointPhase1One {
			return nil
		}
		sealPath := filepath.Join(ceremonyRoot, "phase1", "sealed", "seal.json")
		sealSignaturePath := filepath.Join(ceremonyRoot, "phase1", "sealed", "seal.sig")
		sealBytes, readErr := os.ReadFile(sealPath)
		if readErr != nil {
			return readErr
		}
		sealSignatureBytes, readErr := os.ReadFile(sealSignaturePath)
		if readErr != nil {
			return readErr
		}
		var seal mpcceremony.SealRecord
		if verifyErr := mpcceremony.VerifySignedRecord(sealBytes, sealSignatureBytes, &seal, coordinator.KeyID, coordinatorPrivate.Public().(ed25519.PublicKey)); verifyErr != nil {
			return fmt.Errorf("verify checkpoint Phase 1 seal record: %w", verifyErr)
		}
		if len(seal.Outputs) != 1 {
			return fmt.Errorf("checkpoint Phase 1 seal has %d outputs", len(seal.Outputs))
		}
		phase1Seal = mpcceremony.SealPhase1FilesResult{
			Seal: seal, CommonsPath: filepath.Join(ceremonyRoot, filepath.FromSlash(seal.Outputs[0].Name)),
			SealPath: sealPath, SignaturePath: sealSignaturePath,
		}
	}
	if !checkpointPhase2One {
		phase1Beacon, err = mpcceremony.RecordBeaconFiles(mpcceremony.RecordBeaconFilesOptions{
			Trust:                     trust,
			TranscriptRoot:            ceremonyRoot,
			Phase:                     mpcceremony.Phase1,
			ClosePath:                 phase1Close.ClosePath,
			CloseSignaturePath:        phase1Close.SignaturePath,
			RawResponsePath:           round42Path,
			PublishedAt:               "2023-08-23T15:11:30Z",
			CoordinatorPrivateKeyPath: coordinatorKeyPath,
		})
		if err != nil {
			return fmt.Errorf("record Phase 1 beacon: %w", err)
		}
		// The seal replays the whole phase and is the longest operation in a K=21
		// ceremony, so its progress callback is wired here and asserted below: a
		// silent multi-hour command is the defect this reports against.
		sealProgress := 0
		phase1Seal, err = mpcceremony.SealPhase1Files(mpcceremony.SealPhase1FilesOptions{
			Trust:                     trust,
			Circuit:                   circuit,
			TranscriptRoot:            ceremonyRoot,
			ClosePath:                 phase1Close.ClosePath,
			CloseSignaturePath:        phase1Close.SignaturePath,
			BeaconPath:                phase1Beacon.BeaconPath,
			BeaconSignaturePath:       phase1Beacon.SignaturePath,
			CoordinatorPrivateKeyPath: coordinatorKeyPath,
			OutputDir:                 filepath.Join(ceremonyRoot, "phase1", "sealed"),
			Progress: func(phase mpcceremony.Phase, index, total int) {
				if phase != mpcceremony.Phase1 || index < 1 || index > total {
					panic(fmt.Sprintf("seal progress reported %s %d/%d", phase, index, total))
				}
				sealProgress++
			},
		})
		if err != nil {
			return fmt.Errorf("seal Phase 1: %w", err)
		}
		if sealProgress == 0 {
			return errors.New("Phase 1 seal replayed without reporting progress")
		}
	}
	// The checkpoint fixture needs one authentic turn through the deterministic
	// historical Phase 1 seal, but not the later Phase 2 and release fixtures.
	if checkpointPhase1One {
		return nil
	}

	// Phase 2 initialization reports stages rather than contributions, because
	// its cost is one monolithic transform rather than a per-contribution
	// replay. Assert every stage arrives, in order.
	var phase2Stages []int
	var phase2Initialized mpcceremony.InitPhase2FilesResult
	if checkpointPhase2One && testCommand != "" {
		if err := runTestCommand("phase2", "init",
			"--ceremony", trust.DefinitionPath, "--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
			"--phase1-transcript-dir", ceremonyRoot, "--phase1-seal", phase1Seal.SealPath,
			"--phase1-seal-signature", phase1Seal.SignaturePath,
			"--coordinator-signing-key", coordinatorKeyPath, "--out-dir", filepath.Join(ceremonyRoot, "phase2")); err != nil {
			return fmt.Errorf("initialize checkpoint Phase 2: %w", err)
		}
		phase2Initialized = mpcceremony.InitPhase2FilesResult{
			GenesisPath:        filepath.Join(ceremonyRoot, "phase2", "genesis.bin"),
			ChainPath:          filepath.Join(ceremonyRoot, "phase2", "chain-0000.json"),
			ChainSignaturePath: filepath.Join(ceremonyRoot, "phase2", "chain-0000.sig"),
		}
	} else {
		phase2Initialized, err = mpcceremony.InitializePhase2Files(mpcceremony.InitPhase2FilesOptions{
			Trust: trust, Circuit: circuit, TranscriptRoot: ceremonyRoot,
			Phase1SealPath: phase1Seal.SealPath, Phase1SealSignaturePath: phase1Seal.SignaturePath,
			CoordinatorPrivateKeyPath: coordinatorKeyPath,
			Progress: func(stage string, index, total int) {
				if stage == "" || index < 1 || index > total {
					panic(fmt.Sprintf("phase 2 stage %q reported %d/%d", stage, index, total))
				}
				phase2Stages = append(phase2Stages, index)
			}, OutputDir: filepath.Join(ceremonyRoot, "phase2"),
		})
		if err != nil {
			return fmt.Errorf("initialize Phase 2: %w", err)
		}
		if !slices.Equal(phase2Stages, []int{1, 2, 3}) {
			return fmt.Errorf("phase 2 initialization reported stages %v, want [1 2 3]", phase2Stages)
		}
	}
	phase2Paths := mpcceremony.PhaseTranscriptPaths{
		RootDir:            ceremonyRoot,
		ChainPath:          phase2Initialized.ChainPath,
		ChainSignaturePath: phase2Initialized.ChainSignaturePath,
	}
	phase2Paths, err = contributeAndAccept(
		mpcceremony.Phase2,
		1,
		phase2Paths,
		phase1Seal.SealPath,
		phase1Seal.SignaturePath,
		"2023-08-23T15:11:30.1Z",
		"2023-08-23T15:11:30.2Z",
		"2023-08-23T15:11:30.3Z",
	)
	if err != nil {
		return fmt.Errorf("Phase 2 participant 1: %w", err)
	}
	if !checkpointPhase2One {
		phase2Paths, err = contributeAndAccept(
			mpcceremony.Phase2,
			2,
			phase2Paths,
			phase1Seal.SealPath,
			phase1Seal.SignaturePath,
			"2023-08-23T15:11:30.4Z",
			"2023-08-23T15:11:30.5Z",
			"2023-08-23T15:11:30.6Z",
		)
		if err != nil {
			return fmt.Errorf("Phase 2 participant 2: %w", err)
		}
	}
	if checkpointPhase2One {
		commons, _, err := mpcceremony.ReadCommonsFile(
			phase1Seal.CommonsPath,
			mpcceremony.CommonsShape{DomainN: circuit.Binding.DomainSize},
		)
		if err != nil {
			return fmt.Errorf("read sealed commons for checkpoint Phase 2 closure: %w", err)
		}
		phase2Chain, err := mpcceremony.LoadReplayPhase2Files(trusted, circuit, commons, phase1Seal.Seal, phase2Paths)
		if err != nil {
			return fmt.Errorf("replay checkpoint Phase 2 before closure: %w", err)
		}
		phase2Close, err := writeHistoricalClose(mpcceremony.Phase2, phase2Chain, 43, "2023-08-23T15:11:30.7Z")
		if err != nil {
			return fmt.Errorf("close checkpoint Phase 2: %w", err)
		}
		round43Path := filepath.Join(outputRoot, "quicknet-round-43.json")
		if err := os.WriteFile(round43Path, []byte(quicknetRound43), 0o600); err != nil {
			return err
		}
		if err := runTestCommand("phase2", "beacon",
			"--ceremony", trust.DefinitionPath,
			"--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
			"--closure", phase2Close.ClosePath,
			"--closure-signature", phase2Close.SignaturePath,
			"--raw-response", round43Path,
			"--published-at", "2023-08-23T15:11:33Z",
			"--coordinator-signing-key", coordinatorKeyPath,
			"--transcript-dir", ceremonyRoot,
		); err != nil {
			return fmt.Errorf("record checkpoint Phase 2 beacon: %w", err)
		}
		replayArgs := []string{
			"--transcript-root", ceremonyRoot,
			"--phase1-chain", phase1Paths.ChainPath, "--phase1-chain-signature", phase1Paths.ChainSignaturePath,
			"--phase1-close", phase1Close.ClosePath, "--phase1-close-signature", phase1Close.SignaturePath,
			"--phase1-beacon", filepath.Join(ceremonyRoot, "phase1", "beacon", "record.json"),
			"--phase1-beacon-signature", filepath.Join(ceremonyRoot, "phase1", "beacon", "record.sig"),
			"--phase1-seal", phase1Seal.SealPath, "--phase1-seal-signature", phase1Seal.SignaturePath,
			"--phase2-chain", phase2Paths.ChainPath, "--phase2-chain-signature", phase2Paths.ChainSignaturePath,
			"--phase2-close", phase2Close.ClosePath, "--phase2-close-signature", phase2Close.SignaturePath,
			"--phase2-beacon", filepath.Join(ceremonyRoot, "phase2", "beacon", "record.json"),
			"--phase2-beacon-signature", filepath.Join(ceremonyRoot, "phase2", "beacon", "record.sig"),
		}
		preliminaryDir := filepath.Join(outputRoot, "checkpoint-preliminary")
		prepareArgs := []string{"finalize", "prepare",
			"--ceremony", trust.DefinitionPath, "--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
		}
		prepareArgs = append(prepareArgs, replayArgs...)
		prepareArgs = append(prepareArgs, "--coordinator-signing-key", coordinatorKeyPath, "--prepared-at", "2023-08-23T15:11:34Z", "--out-dir", preliminaryDir)
		if err := runTestCommand(prepareArgs...); err != nil {
			return fmt.Errorf("prepare checkpoint finalization: %w", err)
		}
		publicEvidencePath := filepath.Join(outputRoot, "checkpoint-public-finalization-evidence.json")
		if err := runTestCommand("finalize", "rehearsal-evidence",
			"--keys-dir", preliminaryDir,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
			"--ceremony-id", trusted.Definition.CeremonyID,
			"--out", publicEvidencePath,
		); err != nil {
			return fmt.Errorf("create checkpoint rehearsal evidence: %w", err)
		}
		candidateDir := filepath.Join(ceremonyRoot, "final", "candidate")
		if err := os.Mkdir(filepath.Dir(candidateDir), 0o700); err != nil {
			return fmt.Errorf("create checkpoint final directory: %w", err)
		}
		completeArgs := []string{"finalize", "complete",
			"--ceremony", trust.DefinitionPath, "--ceremony-signature", trust.DefinitionSignaturePath,
			"--coordinator-public-key-file", trust.CoordinatorPublicKeyPath,
		}
		completeArgs = append(completeArgs, replayArgs...)
		completeArgs = append(completeArgs,
			"--coordinator-signing-key", coordinatorKeyPath,
			"--public-evidence", publicEvidencePath,
			"--finalized-at", "2023-08-23T15:11:35Z",
			"--out-dir", candidateDir,
		)
		if err := runTestCommand(completeArgs...); err != nil {
			return fmt.Errorf("complete checkpoint finalization: %w", err)
		}
		if operationalEvidenceHelper != "" {
			phase1Relays, err := writeRelayFixture(outputRoot, "checkpoint-phase1-relays", []byte(quicknetRound42), "2023-08-23T15:11:30Z")
			if err != nil {
				return err
			}
			phase2Relays, err := writeRelayFixture(outputRoot, "checkpoint-phase2-relays", []byte(quicknetRound43), "2023-08-23T15:11:33Z")
			if err != nil {
				return err
			}
			operationalCommand := exec.Command(operationalEvidenceHelper,
				"--transcript-root", ceremonyRoot, "--keys-dir", keyDir,
				"--coordinator-public-key-file", trustedCoordinatorPath,
				"--phase1-relays", phase1Relays, "--phase2-relays", phase2Relays,
				"--assembled-at", "2023-08-23T15:11:36Z", "--out-dir", filepath.Join(ceremonyRoot, "operational"))
			if output, err := operationalCommand.CombinedOutput(); err != nil {
				return fmt.Errorf("generate checkpoint operational evidence: %w\n%s", err, output)
			}
			releaseDir := filepath.Join(ceremonyRoot, "final", "release")
			releaseArgs := []string{"release", "sign",
				"--ceremony", initialized.DefinitionPath, "--ceremony-signature", initialized.DefinitionSignaturePath,
				"--coordinator-public-key-file", trustedCoordinatorPath,
			}
			releaseArgs = append(releaseArgs, replayArgs...)
			releaseArgs = append(releaseArgs,
				"--candidate-bundle", candidateDir, "--operational-evidence-root", ceremonyRoot,
				"--operational-bundle", filepath.Join(ceremonyRoot, mpcceremony.OperationalEvidenceBundleFile),
				"--operational-bundle-signature", filepath.Join(ceremonyRoot, mpcceremony.OperationalEvidenceSignatureFile),
				"--release-signing-key", releaseKeyPath, "--signature-key-id", releaseSigner.KeyID,
				"--released-at", "2023-08-23T15:11:38Z", "--release-dir", releaseDir,
			)
			if err := runTestCommand(releaseArgs...); err != nil {
				return fmt.Errorf("sign checkpoint release: %w", err)
			}
		}
		return nil
	}
	_, err = mpcceremony.ClosePhaseFiles(mpcceremony.ClosePhaseFilesOptions{
		Trust:                     trust,
		Circuit:                   circuit,
		Phase:                     mpcceremony.Phase2,
		Transcript:                phase2Paths,
		Phase1SealPath:            phase1Seal.SealPath,
		Phase1SealSignaturePath:   phase1Seal.SignaturePath,
		CoordinatorPrivateKeyPath: coordinatorKeyPath,
		BeaconRound:               42,
	})
	if err == nil || !strings.Contains(err.Error(), "reuses the authenticated phase1 beacon round") {
		return fmt.Errorf("reused Phase 1 beacon round error = %v, want distinct-round rejection", err)
	}
	for _, path := range []string{
		filepath.Join(ceremonyRoot, "phase2", "closure"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("rejected reused-round close published %q: %v", path, statErr)
		}
	}
	commons, _, err := mpcceremony.ReadCommonsFile(
		phase1Seal.CommonsPath,
		mpcceremony.CommonsShape{DomainN: circuit.Binding.DomainSize},
	)
	if err != nil {
		return fmt.Errorf("read sealed commons for historical Phase 2 closure: %w", err)
	}
	phase2Chain, err := mpcceremony.LoadReplayPhase2Files(
		trusted,
		circuit,
		commons,
		phase1Seal.Seal,
		phase2Paths,
	)
	if err != nil {
		return fmt.Errorf("replay Phase 2 before historical test closure: %w", err)
	}
	phase2Close, err := writeHistoricalClose(
		mpcceremony.Phase2,
		phase2Chain,
		43,
		"2023-08-23T15:11:30.7Z",
	)
	if err != nil {
		return fmt.Errorf("close Phase 2: %w", err)
	}
	round43Path := filepath.Join(outputRoot, "quicknet-round-43.json")
	if err := os.WriteFile(round43Path, []byte(quicknetRound43), 0o600); err != nil {
		return err
	}
	phase2Beacon, err := mpcceremony.RecordBeaconFiles(mpcceremony.RecordBeaconFilesOptions{
		Trust:                     trust,
		TranscriptRoot:            ceremonyRoot,
		Phase:                     mpcceremony.Phase2,
		ClosePath:                 phase2Close.ClosePath,
		CloseSignaturePath:        phase2Close.SignaturePath,
		RawResponsePath:           round43Path,
		PublishedAt:               "2023-08-23T15:11:33Z",
		CoordinatorPrivateKeyPath: coordinatorKeyPath,
	})
	if err != nil {
		return fmt.Errorf("record Phase 2 beacon: %w", err)
	}
	if operationalEvidenceHelper == "" {
		return nil
	}

	replay := mpcceremony.ReplayPaths{
		TranscriptRoot:            ceremonyRoot,
		CoordinatorPublicKeyHex:   hex.EncodeToString(coordinatorPrivate.Public().(ed25519.PublicKey)),
		DefinitionPath:            initialized.DefinitionPath,
		DefinitionSignaturePath:   initialized.DefinitionSignaturePath,
		Phase1ChainPath:           phase1Paths.ChainPath,
		Phase1ChainSignaturePath:  phase1Paths.ChainSignaturePath,
		Phase1ClosePath:           phase1Close.ClosePath,
		Phase1CloseSignaturePath:  phase1Close.SignaturePath,
		Phase1BeaconPath:          phase1Beacon.BeaconPath,
		Phase1BeaconSignaturePath: phase1Beacon.SignaturePath,
		Phase1SealPath:            phase1Seal.SealPath,
		Phase1SealSignaturePath:   phase1Seal.SignaturePath,
		Phase2ChainPath:           phase2Paths.ChainPath,
		Phase2ChainSignaturePath:  phase2Paths.ChainSignaturePath,
		Phase2ClosePath:           phase2Close.ClosePath,
		Phase2CloseSignaturePath:  phase2Close.SignaturePath,
		Phase2BeaconPath:          phase2Beacon.BeaconPath,
		Phase2BeaconSignaturePath: phase2Beacon.SignaturePath,
	}
	// Both phases are complete, closed, beaconed, and phase 1 is sealed.
	// Exercise the read-only inspection at both depths from inside the same
	// binary that ran init, so the running-software gate verifies a real
	// executable identity exactly as it does for every other command.
	for _, full := range []bool{false, true} {
		inspection, err := mpcceremony.InspectCeremony(mpcceremony.InspectCeremonyOptions{
			Trust: mpcceremony.TrustPaths{
				DefinitionPath:           initialized.DefinitionPath,
				DefinitionSignaturePath:  initialized.DefinitionSignaturePath,
				CoordinatorPublicKeyPath: trustedCoordinatorPath,
			},
			TranscriptRoot: ceremonyRoot,
			Full:           full,
		})
		if err != nil {
			return fmt.Errorf("inspect ceremony (full=%v): %w", full, err)
		}
		if inspection.CeremonyID != initialized.Definition.CeremonyID {
			return fmt.Errorf("inspect ceremony id %q, want %q", inspection.CeremonyID, initialized.Definition.CeremonyID)
		}
		if len(inspection.Phases) != 2 {
			return fmt.Errorf("inspect reported %d phases, want 2", len(inspection.Phases))
		}
		for _, phase := range inspection.Phases {
			if !phase.Started || !phase.ContributionsComplete || !phase.Closed || !phase.BeaconRecorded {
				return fmt.Errorf("inspect %s state = %+v, want complete/closed/beaconed", phase.Phase, phase)
			}
			if phase.AcceptedCount != 2 || phase.ScheduledTotal != 2 {
				return fmt.Errorf("inspect %s accepted %d/%d, want 2/2", phase.Phase, phase.AcceptedCount, phase.ScheduledTotal)
			}
			if phase.NextParticipantID != "" || phase.NextIndex != 0 {
				return fmt.Errorf("inspect %s still schedules %q at %d", phase.Phase, phase.NextParticipantID, phase.NextIndex)
			}
			if len(phase.MissingArtifacts) != 0 {
				return fmt.Errorf("inspect %s reports missing artifacts: %v", phase.Phase, phase.MissingArtifacts)
			}
			if wantSealed := phase.Phase == mpcceremony.Phase1; phase.Sealed != wantSealed {
				return fmt.Errorf("inspect %s sealed = %v, want %v", phase.Phase, phase.Sealed, wantSealed)
			}
		}
	}

	preliminaryDir := filepath.Join(outputRoot, "preliminary")
	if _, err := mpcceremony.PrepareFinalization(mpcceremony.PrepareFinalizationOptions{
		Replay:                replay,
		Circuit:               circuit,
		OutDir:                preliminaryDir,
		CoordinatorSigningKey: coordinatorKeyPath,
		PreparedAt:            mustUTC("2023-08-23T15:11:34Z"),
	}); err != nil {
		return fmt.Errorf("prepare finalization: %w", err)
	}
	if _, err := mpcceremony.VerifyPreliminaryFinalKeys(
		preliminaryDir,
		replay.CoordinatorPublicKeyHex,
	); err != nil {
		return fmt.Errorf("verify preliminary final keys: %w", err)
	}
	publicEvidencePath := filepath.Join(outputRoot, "public-finalization-evidence.json")
	if err := writeTinyPublicEvidence(
		publicEvidencePath,
		initialized.Definition.CeremonyID,
		circuit,
		preliminaryDir,
	); err != nil {
		return fmt.Errorf("generate separate public evidence: %w", err)
	}
	candidateDir := filepath.Join(outputRoot, "candidate")
	if _, err := mpcceremony.Finalize(mpcceremony.FinalizeOptions{
		Replay:                replay,
		Circuit:               circuit,
		OutDir:                candidateDir,
		CoordinatorSigningKey: coordinatorKeyPath,
		PublicEvidencePath:    publicEvidencePath,
		FinalizedAt:           mustUTC("2023-08-23T15:11:35Z"),
	}); err != nil {
		return fmt.Errorf("complete finalization: %w", err)
	}

	if id, err := mpcceremony.ReplayCandidate(replay, circuit, candidateDir); err != nil || id != initialized.Definition.CeremonyID {
		return fmt.Errorf("unsigned public replay failed: %s: %v", id, err)
	}

	candidateSignature := filepath.Join(candidateDir, mpcceremony.CandidateSignatureFile)
	originalSignature, err := os.ReadFile(candidateSignature)
	if err != nil {
		return err
	}
	if err := os.WriteFile(candidateSignature, []byte("tampered"), 0600); err != nil {
		return err
	}
	if _, err := mpcceremony.ReplayCandidate(replay, circuit, candidateDir); err == nil {
		return errors.New("unsigned replay accepted tampered candidate signature")
	}
	if err := os.WriteFile(candidateSignature, originalSignature, 0600); err != nil {
		return err
	}

	auditDir := filepath.Join(outputRoot, "audits")
	audits := make([]mpcceremony.AuditArtifact, 0, 2)
	auditInputs := []struct {
		id      string
		keyPath string
		at      string
	}{
		{id: auditor1.ID, keyPath: auditor1KeyPath, at: "2023-08-23T15:11:36Z"},
		{id: auditor2.ID, keyPath: auditor2KeyPath, at: "2023-08-23T15:11:37Z"},
	}
	if zeroAssurance {
		auditInputs = nil
	}
	if len(auditInputs) > 0 {
		if err := os.Mkdir(auditDir, 0o700); err != nil {
			return err
		}
	}
	for index, input := range auditInputs {
		recordPath := filepath.Join(auditDir, fmt.Sprintf("audit-%02d.json", index+1))
		signaturePath := filepath.Join(auditDir, fmt.Sprintf("audit-%02d.sig", index+1))
		if _, err := mpcceremony.Audit(mpcceremony.AuditOptions{
			Replay:            replay,
			Circuit:           circuit,
			CandidateDir:      candidateDir,
			AuditorID:         input.id,
			AuditorSigningKey: input.keyPath,
			OutPath:           recordPath,
			SignatureOutPath:  signaturePath,
			AuditedAt:         mustUTC(input.at),
		}); err != nil {
			return fmt.Errorf("audit %s: %w", input.id, err)
		}
		audits = append(audits, mpcceremony.AuditArtifact{
			RecordPath:    recordPath,
			SignaturePath: signaturePath,
			LogicalName:   fmt.Sprintf("audit-%02d", index+1),
		})
	}

	phase1Relays, err := writeRelayFixture(
		outputRoot,
		"phase1-relays",
		[]byte(quicknetRound42),
		"2023-08-23T15:11:30Z",
	)
	if err != nil {
		return err
	}
	phase2Relays, err := writeRelayFixture(
		outputRoot,
		"phase2-relays",
		[]byte(quicknetRound43),
		"2023-08-23T15:11:33Z",
	)
	if err != nil {
		return err
	}
	operationalCommand := exec.Command(
		operationalEvidenceHelper,
		"--transcript-root", ceremonyRoot,
		"--keys-dir", keyDir,
		"--coordinator-public-key-file", trustedCoordinatorPath,
		"--phase1-relays", phase1Relays,
		"--phase2-relays", phase2Relays,
		"--assembled-at", "2023-08-23T15:11:35Z",
		"--out-dir", filepath.Join(ceremonyRoot, "operational"),
	)
	if output, err := operationalCommand.CombinedOutput(); err != nil {
		return fmt.Errorf("generate operational evidence: %w\n%s", err, output)
	}

	releaseDir := filepath.Join(outputRoot, "release")
	if checkpointPhase2One {
		releaseDir = filepath.Join(ceremonyRoot, "final", "release")
	}
	if _, err := mpcceremony.SignRelease(mpcceremony.SignReleaseOptions{
		DefinitionPath:           initialized.DefinitionPath,
		DefinitionSignaturePath:  initialized.DefinitionSignaturePath,
		CoordinatorPublicKeyHex:  replay.CoordinatorPublicKeyHex,
		CandidateDir:             candidateDir,
		ReleaseDir:               releaseDir,
		Audits:                   audits,
		OperationalEvidenceRoot:  ceremonyRoot,
		OperationalBundlePath:    filepath.Join(ceremonyRoot, mpcceremony.OperationalEvidenceBundleFile),
		OperationalSignaturePath: filepath.Join(ceremonyRoot, mpcceremony.OperationalEvidenceSignatureFile),
		ReleaseSigningKey:        releaseKeyPath,
		SignatureKeyID:           releaseSigner.KeyID,
		ReleasedAt:               mustUTC("2023-08-23T15:11:38Z"),
		Replay:                   &replay,
		Circuit:                  circuit,
	}); err != nil {
		return fmt.Errorf("sign release: %w", err)
	}
	if _, err := mpcceremony.VerifyRelease(mpcceremony.VerifyReleaseOptions{
		DefinitionPath:          initialized.DefinitionPath,
		DefinitionSignaturePath: initialized.DefinitionSignaturePath,
		CoordinatorPublicKeyHex: replay.CoordinatorPublicKeyHex,
		KeysDir:                 releaseDir,
		TrustedPublicKeyHex:     releaseSigner.Ed25519PublicKeyHex,
		ExpectedSignatureKeyID:  releaseSigner.KeyID,
		RequireProvingKey:       true,
	}); err != nil {
		return fmt.Errorf("verify signed release: %w", err)
	}
	return nil
}

func mustUTC(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed.UTC()
}

func writeTinyPublicEvidence(
	path string,
	ceremonyID string,
	circuit *mpcceremony.CompiledCircuit,
	preliminaryDir string,
) error {
	credential, err := hex.DecodeString(mpcceremony.GoldenPublicCredentialHex)
	if err != nil {
		return err
	}
	destination, err := hex.DecodeString(mpcceremony.GoldenPublicDestinationHex)
	if err != nil {
		return err
	}
	preimage := append([]byte(mpcceremony.DestinationPublicDomain), credential...)
	preimage = append(preimage, destination...)
	digest := blake2b.Sum256(preimage)
	reversed := bytes.Clone(digest[:])
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	scalar := new(big.Int).SetBytes(reversed)
	scalar.Mod(scalar, ecc.BLS12_381.ScalarField())
	var assignment frontend.Circuit = &tinyCommittedCircuit{Public: scalar, Secret: scalar}
	if circuit.Binding.KeyVersion == mpcceremony.KeyVersionRehearsal {
		field := ecc.BLS12_381.ScalarField()
		q := new(big.Int).Sub(field, big.NewInt(1))
		q.Div(q, big.NewInt(3))
		exponent := new(big.Int).ModInverse(big.NewInt(3), q)
		if exponent == nil {
			return errors.New("unexpected rehearsal cube subgroup")
		}
		cubeRoot := new(big.Int).Exp(scalar, exponent, field)
		if new(big.Int).Exp(cubeRoot, big.NewInt(3), field).Cmp(scalar) != 0 {
			return errors.New("rehearsal golden scalar is not a cube")
		}
		assignment = &rehearsal.Circuit{X: cubeRoot, Pub: scalar}
	}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return err
	}
	pk, err := prover.LoadPK(filepath.Join(preliminaryDir, mpcceremony.NativeProvingKeyFile))
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(circuit.R1CS, pk, fullWitness)
	if err != nil {
		return err
	}
	cardanoProof, format, err := prover.SerializeCardanoProof(proof)
	if err != nil {
		return err
	}
	cardanoVK, err := os.ReadFile(filepath.Join(preliminaryDir, mpcceremony.CardanoVKBytesFile))
	if err != nil {
		return err
	}
	evidence := mpcceremony.PublicFinalizationEvidence{
		Schema:                mpcceremony.PublicEvidenceSchema,
		CeremonyID:            ceremonyID,
		Fixture:               mpcceremony.PublicEvidenceFixture,
		CredentialHex:         hex.EncodeToString(credential),
		DestinationHex:        hex.EncodeToString(destination),
		PublicInputDigestHex:  hex.EncodeToString(digest[:]),
		CardanoProofHex:       hex.EncodeToString(cardanoProof),
		CardanoProofFormat:    format,
		CardanoProofRawDigest: mpcceremony.NewDigest(cardanoProof),
		CardanoVerifyingKey: mpcceremony.ArtifactRef{
			Name:   mpcceremony.CardanoVKBytesFile,
			Digest: mpcceremony.NewDigest(cardanoVK),
		},
	}
	canonical, err := mpcceremony.MarshalCanonical(evidence)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(canonical); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeRelayFixture(root, name string, raw []byte, retrievedAt string) (string, error) {
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	rows := []string{
		"relay_id\toperator_id\tendpoint_sha256\tretrieved_at\tfilename",
	}
	// Exercise release verification with the minimum two synthetic operators.
	for index := 1; index <= 2; index++ {
		filename := fmt.Sprintf("relay-%02d.json", index)
		if err := os.WriteFile(filepath.Join(dir, filename), raw, 0o600); err != nil {
			return "", err
		}
		endpoint := "sha256:" + strings.Repeat(fmt.Sprintf("%x", index), 64)
		rows = append(rows, fmt.Sprintf(
			"relay-%02d\toperator-%02d\t%s\t%s\t%s",
			index,
			index,
			endpoint,
			retrievedAt,
			filename,
		))
	}
	if err := os.WriteFile(
		filepath.Join(dir, "relays.tsv"),
		[]byte(strings.Join(rows, "\n")+"\n"),
		0o600,
	); err != nil {
		return "", err
	}
	return dir, nil
}
