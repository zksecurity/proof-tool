// Package mpcrehearsal creates fresh same-host identities and exact canonical
// inputs for a local MPC ceremony rehearsal. It is deliberately not a
// production enrollment tool: production identities must be generated and
// governed independently by their owners.
package mpcrehearsal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"proof-tool/internal/mpcceremony"
)

const (
	minRehearsalParticipants = 3
	maxRehearsalParticipants = 20
	// MinimumBeaconLeadSeconds gives automated rehearsals four Quicknet
	// periods to commit to a round that does not exist yet. Rehearsal outputs
	// are explicitly non-production. Production tooling recommends 24 hours,
	// but the exact signed ceremony policy is configurable.
	MinimumBeaconLeadSeconds = 12
)

type generatedIdentity struct {
	identity   mpcceremony.Identity
	privateKey ed25519.PrivateKey
}

func Generate(outDir string, participantCount int, beaconWitnessLead uint32) (err error) {
	return GenerateWithAssurance(outDir, participantCount, beaconWitnessLead, true)
}

// GenerateWithAssurance exposes both supported rehearsal paths to the real
// command surface. When optionalAssurance is false, the signed policy uses
// explicit zeroes and no auditor is enrolled; drand verification remains on.
func GenerateWithAssurance(outDir string, participantCount int, beaconWitnessLead uint32, optionalAssurance bool) (err error) {
	if participantCount < minRehearsalParticipants ||
		participantCount > maxRehearsalParticipants {
		return fmt.Errorf(
			"participants must be between %d and %d",
			minRehearsalParticipants,
			maxRehearsalParticipants,
		)
	}
	if beaconWitnessLead < MinimumBeaconLeadSeconds {
		return fmt.Errorf(
			"beacon witness lead must be at least %d seconds",
			MinimumBeaconLeadSeconds,
		)
	}
	if err := os.Mkdir(outDir, 0o700); err != nil {
		return fmt.Errorf("create fresh rehearsal config root: %w", err)
	}
	removeRoot := true
	defer func() {
		if err != nil && removeRoot {
			_ = os.RemoveAll(outDir)
		}
	}()
	keyDir := filepath.Join(outDir, "keys")
	configDir := filepath.Join(outDir, "config")
	for _, path := range []string{keyDir, configDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
	}

	newIdentity := func(id, displayName string) (generatedIdentity, error) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return generatedIdentity{}, err
		}
		identity, err := mpcceremony.NewIdentity(
			id,
			displayName,
			id+"-key",
			publicKey,
		)
		if err != nil {
			return generatedIdentity{}, err
		}
		return generatedIdentity{identity: identity, privateKey: privateKey}, nil
	}

	coordinator, err := newIdentity("coordinator", "Local Rehearsal Coordinator")
	if err != nil {
		return err
	}
	releaseSigner, err := newIdentity("release-signer", "Local Rehearsal Release Signer")
	if err != nil {
		return err
	}
	generated := []generatedIdentity{
		coordinator,
		releaseSigner,
	}
	var auditor1, auditor2 generatedIdentity
	if optionalAssurance {
		for _, spec := range []struct{ id, display string }{
			{"auditor-01", "Local Rehearsal Auditor 01"},
			{"auditor-02", "Local Rehearsal Auditor 02"},
			{"witness-01", "Local Rehearsal Public Witness 01"},
			{"witness-02", "Local Rehearsal Public Witness 02"},
			{"mirror-01", "Local Rehearsal Mirror Operator 01"},
			{"mirror-02", "Local Rehearsal Mirror Operator 02"},
		} {
			identity, identityErr := newIdentity(spec.id, spec.display)
			if identityErr != nil {
				return identityErr
			}
			switch spec.id {
			case "auditor-01":
				auditor1 = identity
			case "auditor-02":
				auditor2 = identity
			}
			generated = append(generated, identity)
		}
	}
	participants := make([]mpcceremony.Participant, 0, participantCount)
	participantIDs := make([]string, 0, participantCount)
	for index := 1; index <= participantCount; index++ {
		id := fmt.Sprintf("participant-%02d", index)
		participant, err := newIdentity(id, "Local Rehearsal "+id)
		if err != nil {
			return err
		}
		generated = append(generated, participant)
		participants = append(participants, mpcceremony.Participant{Identity: participant.identity})
		participantIDs = append(participantIDs, id)
	}

	for _, item := range generated {
		seedPath := filepath.Join(keyDir, item.identity.ID+".ed25519.private.hex")
		if err := writeNoReplace(
			seedPath,
			[]byte(hex.EncodeToString(item.privateKey.Seed())+"\n"),
			0o600,
		); err != nil {
			return err
		}
		publicPath := filepath.Join(keyDir, item.identity.ID+".ed25519.public.hex")
		if err := writeNoReplace(
			publicPath,
			[]byte(item.identity.Ed25519PublicKeyHex+"\n"),
			0o600,
		); err != nil {
			return err
		}
	}

	auditors := []mpcceremony.Identity{}
	assurance := &mpcceremony.AssurancePolicy{}
	if optionalAssurance {
		auditors = []mpcceremony.Identity{auditor1.identity, auditor2.identity}
		assurance.PublicWitnessesPerPhase = 1
		assurance.MirrorsPerAcceptedHead = 1
		assurance.PassingCeremonyAudits = 1
	}
	enrollment := mpcceremony.InitParticipants{
		Coordinator:   coordinator.identity,
		ReleaseSigner: releaseSigner.identity,
		Auditors:      auditors,
		Roster:        participants,
	}
	policy := mpcceremony.InitPolicy{
		AssurancePolicy: assurance,
		Phase1Policy: mpcceremony.PhasePolicy{
			Participants: participantIDs,
			Minimum:      uint8(participantCount),
		},
		Phase2Policy: mpcceremony.PhasePolicy{
			Participants: append([]string(nil), participantIDs...),
			Minimum:      uint8(participantCount),
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
			MinimumWitnessLeadSeconds: beaconWitnessLead,
			FutureRoundRequired:       true,
		},
	}
	environment := mpcceremony.ContributionEnvironment{
		OS:                            runtime.GOOS,
		Architecture:                  runtime.GOARCH,
		EntropySource:                 "operating-system-csprng",
		ContributorSwapDisabled:       true,
		ContributorCrashDumpsDisabled: true,
		ContributorTelemetryDisabled:  true,
		EphemeralEnvironment:          true,
		EphemeralCleanupRequired:      true,
		HostRemnantsNotExcluded:       true,
	}
	for name, value := range map[string]any{
		"participants.json": enrollment,
		"policy.json":       policy,
		"environment.json":  environment,
	} {
		data, err := mpcceremony.MarshalCanonical(value)
		if err != nil {
			return err
		}
		if err := writeNoReplace(filepath.Join(configDir, name), data, 0o600); err != nil {
			return err
		}
	}
	if err := writeNoReplace(
		filepath.Join(outDir, "participant-count.txt"),
		[]byte(fmt.Sprintf("%d\n", participantCount)),
		0o600,
	); err != nil {
		return err
	}
	removeRoot = false
	return nil
}

func writeNoReplace(path string, data []byte, mode os.FileMode) error {
	if len(data) == 0 {
		return errors.New("refusing to write empty rehearsal config")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
