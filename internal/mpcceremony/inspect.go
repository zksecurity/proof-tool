// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// InspectDepthMetadata verifies signatures and structure only: the signed
// definition, the highest published chain per phase, and closure, beacon, and
// seal records when present. Artifact presence is checked by name and size;
// no artifact bytes are hashed and nothing is replayed. Seconds at any K.
const InspectDepthMetadata = "metadata"

// InspectDepthFull additionally re-verifies every chain file the way the
// operational commands do: every payload digest, attestation, erasure, and
// coordinator verification record. It does not re-run the gnark replay; that
// remains the job of contribute, verify, and audit.
const InspectDepthFull = "full"

// InspectCeremonyOptions configures the read-only ceremony inspection.
type InspectCeremonyOptions struct {
	Trust          TrustPaths
	TranscriptRoot string
	// Full selects InspectDepthFull. The default is InspectDepthMetadata.
	Full bool
}

// PhaseInspection reports the recovered state of one phase.
type PhaseInspection struct {
	Phase   Phase
	Started bool
	// ChainFile is the transcript-relative chain that was inspected: the
	// highest index for which both the chain and its signature exist. The
	// filename index must equal the record count, so a stale or renamed
	// chain cannot claim another position.
	ChainFile     string
	AcceptedCount int
	// ScheduledTotal is the frozen participant schedule length.
	ScheduledTotal int
	HeadRecordID   string
	HeadPayload    string
	// NextIndex and NextParticipantID name the only contribution the frozen
	// order permits next; both are zero values once every scheduled
	// participant has been accepted.
	NextIndex             int
	NextParticipantID     string
	ContributionsComplete bool
	Closed                bool
	BeaconRecorded        bool
	Sealed                bool
	// MissingArtifacts lists referenced artifacts that are absent or have the
	// wrong size. Empty means every referenced artifact is present.
	MissingArtifacts []string
}

// InspectResult is the full read-only inspection report.
type InspectResult struct {
	CeremonyID string
	Mode       string
	Depth      string
	Phases     []PhaseInspection
}

// InspectCeremony reports ceremony state from already-signed data: ceremony
// identity and mode, per-phase accepted count and head, the next scheduled
// participant, and which referenced artifacts are present. It requires no
// signing key, writes nothing, and never replays contributions.
//
// Unlike every other command, inspect discovers the highest published chain
// file per phase instead of taking explicit chain paths. That discovery is
// safe here and only here because inspection is read-only: its output feeds
// no signing or verification decision, every discovered file is still
// authenticated against the out-of-band trust anchor before being reported,
// and the chain filename index must match the signed record count.
func InspectCeremony(options InspectCeremonyOptions) (InspectResult, error) {
	var result InspectResult
	trusted, err := loadOperationalCeremony(options.Trust)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(options.TranscriptRoot) == "" {
		return result, errors.New("transcript root is required")
	}
	result.CeremonyID = trusted.Definition.CeremonyID
	result.Mode = trusted.Definition.Mode
	result.Depth = InspectDepthMetadata
	if options.Full {
		result.Depth = InspectDepthFull
	}

	var circuit *CompiledCircuit
	if options.Full {
		r1csPath := filepath.Join(
			options.TranscriptRoot,
			filepath.FromSlash(trusted.Definition.Circuit.R1CS.Name),
		)
		circuit, err = ReadR1CSFile(r1csPath, trusted.Definition.Circuit)
		if err != nil {
			return result, fmt.Errorf("full inspection requires the pinned R1CS: %w", err)
		}
	}

	phase1, phase1Seal, err := inspectPhase(trusted, circuit, options, Phase1, nil)
	if err != nil {
		return result, fmt.Errorf("inspect phase1: %w", err)
	}
	result.Phases = append(result.Phases, phase1)

	phase2, _, err := inspectPhase(trusted, circuit, options, Phase2, phase1Seal)
	if err != nil {
		return result, fmt.Errorf("inspect phase2: %w", err)
	}
	result.Phases = append(result.Phases, phase2)
	return result, nil
}

func inspectPhase(
	trusted *TrustedCeremony,
	circuit *CompiledCircuit,
	options InspectCeremonyOptions,
	phase Phase,
	phase1Seal *SealRecord,
) (PhaseInspection, *SealRecord, error) {
	inspection := PhaseInspection{Phase: phase}
	phaseDir := filepath.Join(options.TranscriptRoot, string(phase))
	if _, err := os.Lstat(phaseDir); errors.Is(err, fs.ErrNotExist) {
		return inspection, nil, nil
	} else if err != nil {
		return inspection, nil, fmt.Errorf("inspect phase directory: %w", err)
	}

	chainIndex := -1
	var chainPath, chainSignaturePath string
	for index := 0; index <= MaxParticipants; index++ {
		candidate := filepath.Join(phaseDir, fmt.Sprintf("chain-%04d.json", index))
		signature := DefaultSignaturePath(candidate)
		if fileExists(candidate) && fileExists(signature) {
			chainIndex = index
			chainPath, chainSignaturePath = candidate, signature
		}
	}
	if chainIndex < 0 {
		return inspection, nil, nil
	}
	inspection.Started = true
	inspection.ChainFile = filepath.ToSlash(
		filepath.Join(string(phase), fmt.Sprintf("chain-%04d.json", chainIndex)),
	)

	chain, err := LoadSignedChain(trusted, PhaseTranscriptPaths{
		RootDir:            options.TranscriptRoot,
		ChainPath:          chainPath,
		ChainSignaturePath: chainSignaturePath,
	})
	if err != nil {
		return inspection, nil, fmt.Errorf("chain %s: %w", inspection.ChainFile, err)
	}
	if chain.Phase != phase {
		return inspection, nil, fmt.Errorf("chain %s is for phase %q", inspection.ChainFile, chain.Phase)
	}
	if len(chain.Records) != chainIndex {
		return inspection, nil, fmt.Errorf(
			"chain %s holds %d records; the filename index requires exactly %d",
			inspection.ChainFile, len(chain.Records), chainIndex,
		)
	}

	policy, err := trusted.Definition.PolicyForPhase(phase)
	if err != nil {
		return inspection, nil, err
	}
	inspection.AcceptedCount = len(chain.Records)
	inspection.ScheduledTotal = len(policy.Participants)
	headID, err := chain.HeadRecordID()
	if err != nil {
		return inspection, nil, err
	}
	headPayload, err := chain.HeadPayload()
	if err != nil {
		return inspection, nil, err
	}
	inspection.HeadRecordID = headID
	inspection.HeadPayload = headPayload.Name
	if len(chain.Records) < len(policy.Participants) {
		inspection.NextIndex = len(chain.Records) + 1
		inspection.NextParticipantID = policy.Participants[len(chain.Records)]
	} else {
		inspection.ContributionsComplete = true
	}

	inspection.MissingArtifacts = missingChainArtifacts(options.TranscriptRoot, chain)

	closeRecord, closed, err := inspectCloseRecord(trusted, phaseDir, chain)
	if err != nil {
		return inspection, nil, err
	}
	inspection.Closed = closed

	var beacon BeaconRecord
	if closed {
		beaconRecorded, err := inspectBeaconRecord(trusted, phaseDir, closeRecord, &beacon)
		if err != nil {
			return inspection, nil, err
		}
		inspection.BeaconRecorded = beaconRecorded
	}

	var seal *SealRecord
	if phase == Phase1 && inspection.BeaconRecorded {
		sealed, loadedSeal, err := inspectSealRecord(trusted, options.TranscriptRoot, closeRecord, beacon)
		if err != nil {
			return inspection, nil, err
		}
		inspection.Sealed = sealed
		seal = loadedSeal
	}

	if options.Full {
		if err := inspectFullDepth(trusted, circuit, options.TranscriptRoot, phase, chainPath, chainSignaturePath, phase1Seal); err != nil {
			return inspection, nil, fmt.Errorf("full verification of %s: %w", inspection.ChainFile, err)
		}
	}
	return inspection, seal, nil
}

func inspectCloseRecord(trusted *TrustedCeremony, phaseDir string, chain Chain) (CloseRecord, bool, error) {
	closePath := filepath.Join(phaseDir, closePublicationDirectoryName, closeRecordFilename)
	closeSignature := filepath.Join(phaseDir, closePublicationDirectoryName, closeSignatureFilename)
	if !fileExists(closePath) || !fileExists(closeSignature) {
		return CloseRecord{}, false, nil
	}
	var closeRecord CloseRecord
	if err := loadCoordinatorSignedRecord(trusted, closePath, closeSignature, &closeRecord); err != nil {
		return CloseRecord{}, false, fmt.Errorf("closure record: %w", err)
	}
	if err := ValidateClose(trusted.Definition, chain, closeRecord); err != nil {
		return CloseRecord{}, false, fmt.Errorf("closure record: %w", err)
	}
	return closeRecord, true, nil
}

func inspectBeaconRecord(
	trusted *TrustedCeremony,
	phaseDir string,
	closeRecord CloseRecord,
	beacon *BeaconRecord,
) (bool, error) {
	beaconPath := filepath.Join(phaseDir, "beacon", "record.json")
	beaconSignature := filepath.Join(phaseDir, "beacon", "record.sig")
	if !fileExists(beaconPath) || !fileExists(beaconSignature) {
		return false, nil
	}
	if err := loadCoordinatorSignedRecord(trusted, beaconPath, beaconSignature, beacon); err != nil {
		return false, fmt.Errorf("beacon record: %w", err)
	}
	if err := ValidateBeacon(trusted.Definition, closeRecord, *beacon); err != nil {
		return false, fmt.Errorf("beacon record: %w", err)
	}
	return true, nil
}

func inspectSealRecord(
	trusted *TrustedCeremony,
	transcriptRoot string,
	closeRecord CloseRecord,
	beacon BeaconRecord,
) (bool, *SealRecord, error) {
	sealPath := filepath.Join(transcriptRoot, string(Phase1), "sealed", "seal.json")
	sealSignature := filepath.Join(transcriptRoot, string(Phase1), "sealed", "seal.sig")
	if !fileExists(sealPath) || !fileExists(sealSignature) {
		return false, nil, nil
	}
	var seal SealRecord
	if err := loadCoordinatorSignedRecord(trusted, sealPath, sealSignature, &seal); err != nil {
		return false, nil, fmt.Errorf("seal record: %w", err)
	}
	if err := ValidateSeal(closeRecord, beacon, seal); err != nil {
		return false, nil, fmt.Errorf("seal record: %w", err)
	}
	return true, &seal, nil
}

// missingChainArtifacts reports referenced artifacts that are absent or whose
// size disagrees with the signed reference. Size is a presence check, not an
// integrity check: full depth re-hashes contents, metadata depth does not.
func missingChainArtifacts(root string, chain Chain) []string {
	var missing []string
	references := make([]ArtifactRef, 0, len(chain.Records)+1)
	if chain.Phase == Phase1 {
		references = append(references, chain.Genesis)
	}
	for _, record := range chain.Records {
		references = append(references, record.OutputPayload)
	}
	for _, ref := range references {
		path, err := resolveArtifactPath(root, ref.Name)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s (unresolvable: %v)", ref.Name, err))
			continue
		}
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			missing = append(missing, ref.Name)
		case err != nil:
			missing = append(missing, fmt.Sprintf("%s (unreadable: %v)", ref.Name, err))
		case info.Size() != ref.Digest.Size:
			missing = append(missing, fmt.Sprintf(
				"%s (size %d, signed reference requires %d)",
				ref.Name, info.Size(), ref.Digest.Size,
			))
		}
	}
	return missing
}

func inspectFullDepth(
	trusted *TrustedCeremony,
	circuit *CompiledCircuit,
	transcriptRoot string,
	phase Phase,
	chainPath, chainSignaturePath string,
	phase1Seal *SealRecord,
) error {
	paths := PhaseTranscriptPaths{
		RootDir:            transcriptRoot,
		ChainPath:          chainPath,
		ChainSignaturePath: chainSignaturePath,
	}
	if phase == Phase1 {
		_, err := loadVerifiedPhase1Files(trusted, circuit, paths)
		return err
	}
	if phase1Seal == nil {
		return errors.New("phase2 full verification requires the verified phase1 seal")
	}
	sealPath := filepath.Join(transcriptRoot, string(Phase1), "sealed", "seal.json")
	commons, seal, _, err := loadPhase1CommonsForPhase2(
		trusted,
		circuit,
		transcriptRoot,
		sealPath,
		DefaultSignaturePath(sealPath),
	)
	if err != nil {
		return err
	}
	_, err = loadVerifiedPhase2Files(trusted, circuit, commons, seal, paths)
	return err
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
