package mpcceremony

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// Lifecycle preparation consumes the exact refs in the authenticated previous
// checkpoint. It never discovers an alternate chain/closure from loose files.
func verifyCheckpointLifecycleV4(options CheckpointPreparationV4, trusted *TrustedCeremony, reader *checkpointReaderV4, previous CheckpointV4) error {
	c := options.Proposal
	path := func(ref ArtifactRef) string { return filepath.Join(reader.path, ref.Name) }
	readSigned := func(refs SignedArtifactRefs, out any) error {
		record, sig, err := reader.pair(refs)
		if err != nil {
			return err
		}
		return VerifySignedRecord(record, sig, out, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey)
	}
	switch c.Transition.Kind {
	case CheckpointPhase1Closed, CheckpointPhase2Closed:
		state := previous.Progress.Phase1
		if c.Transition.Kind == CheckpointPhase2Closed {
			state = *previous.Progress.Phase2
		}
		if state.Chain.Record.Name != fmt.Sprintf("%s/chain-%04d.json", state.Phase, state.AcceptedCount) || state.Chain.Signature.Name != fmt.Sprintf("%s/chain-%04d.sig", state.Phase, state.AcceptedCount) {
			return errors.New("closure requires the canonical accepted chain paths")
		}
		if err := requireLifecycleRecordPathV4(*c.Transition.Record, state.Phase, "closure"); err != nil {
			return err
		}
		var chain Chain
		if err := readSigned(state.Chain, &chain); err != nil {
			return err
		}
		if err := verifyV4ChainProjection(chain, state.Chain, state); err != nil {
			return err
		}
		var closure CloseRecord
		if err := readSigned(*c.Transition.Record, &closure); err != nil {
			return err
		}
		if c.Transition.Kind == CheckpointPhase2Closed {
			var priorClose CloseRecord
			var priorBeacon BeaconRecord
			if err := readSigned(*previous.Progress.Phase1Closure, &priorClose); err != nil {
				return err
			}
			if err := readSigned(*previous.Progress.Phase1Beacon, &priorBeacon); err != nil {
				return err
			}
			if err := ValidateBeacon(trusted.Definition, priorClose, priorBeacon); err != nil {
				return err
			}
			if err := validatePhase2CloseBoundaryV4(priorClose, priorBeacon, closure); err != nil {
				return err
			}
		}
		// Full contribution replay happened when accepting each chain; this binds
		// closure to that exact signed chain and enforces its signed policy.
		return ValidateClose(trusted.Definition, chain, closure)
	case CheckpointPhase1BeaconRecorded, CheckpointPhase2BeaconRecorded:
		closureRefs := previous.Progress.Phase1Closure
		phase := Phase1
		if c.Transition.Kind == CheckpointPhase2BeaconRecorded {
			closureRefs = previous.Progress.Phase2Closure
			phase = Phase2
		}
		if err := requireLifecycleRecordPathV4(*closureRefs, phase, "closure"); err != nil {
			return err
		}
		if err := requireLifecycleRecordPathV4(*c.Transition.Record, phase, "beacon"); err != nil {
			return err
		}
		var closure CloseRecord
		if err := readSigned(*closureRefs, &closure); err != nil {
			return err
		}
		var beacon BeaconRecord
		if err := readSigned(*c.Transition.Record, &beacon); err != nil {
			return err
		}
		if beacon.RawResponse != c.Transition.Evidence[0] {
			return errors.New("beacon checkpoint evidence differs from the signed raw response")
		}
		if phase == Phase2 {
			var prior BeaconRecord
			if err := readSigned(*previous.Progress.Phase1Beacon, &prior); err != nil {
				return err
			}
			if beacon.ChallengeSHA256 == prior.ChallengeSHA256 || beacon.Round == prior.Round {
				return errors.New("phase2 must use a distinct beacon round and challenge")
			}
		}
		return VerifyBeaconRecordFiles(trusted, reader.path, closure, beacon)
	case CheckpointPhase1Sealed:
		p := previous.Progress
		seal := c.Transition.Record
		verified, err := VerifyPhase1SealFiles(VerifyPhase1SealFilesOptions{
			Trust: options.Trust, Circuit: options.Circuit, TranscriptRoot: reader.path,
			Phase1ChainPath: path(p.Phase1.Chain.Record), Phase1ChainSignaturePath: path(p.Phase1.Chain.Signature),
			Phase1ClosePath: path(p.Phase1Closure.Record), Phase1CloseSignaturePath: path(p.Phase1Closure.Signature),
			Phase1BeaconPath: path(p.Phase1Beacon.Record), Phase1BeaconSignaturePath: path(p.Phase1Beacon.Signature),
			Phase1SealPath: path(seal.Record), Phase1SealSignaturePath: path(seal.Signature),
		})
		if err != nil {
			return err
		}
		if verified.Commons != c.Transition.Evidence[0] {
			return errors.New("seal checkpoint payload differs from replayed commons")
		}
		return nil
	case CheckpointPhase2Initialized:
		seal := previous.Progress.Phase1Seal
		chain := c.Transition.Record
		verified, err := VerifyPhase2GenesisFiles(VerifyPhase2GenesisFilesOptions{
			Trust: options.Trust, Circuit: options.Circuit, TranscriptRoot: reader.path,
			Phase1SealPath: path(seal.Record), Phase1SealSignaturePath: path(seal.Signature),
			Phase2ChainPath: path(chain.Record), Phase2ChainSignaturePath: path(chain.Signature),
		})
		if err != nil {
			return err
		}
		if verified.Genesis != c.Transition.Evidence[0] {
			return errors.New("phase2 checkpoint payload differs from replayed genesis")
		}
		return verifyV4ChainProjection(verified.Chain, verified.ChainRefs, *c.Progress.Phase2)
	}
	return errors.New("unsupported lifecycle verification")
}

func validatePhase2CloseBoundaryV4(first CloseRecord, beacon BeaconRecord, second CloseRecord) error {
	if second.BeaconRound <= first.BeaconRound {
		return errors.New("phase2 must use a later beacon round than phase1")
	}
	closedAt, err := time.Parse(time.RFC3339Nano, second.ClosedAt)
	if err != nil {
		return err
	}
	publishedAt, err := time.Parse(time.RFC3339Nano, beacon.PublishedAt)
	if err != nil {
		return err
	}
	if !closedAt.After(publishedAt) {
		return errors.New("phase2 closure must follow phase1 beacon publication")
	}
	return nil
}

// Existing replay derives these logical names. Reject misplaced records when
// authoring, rather than accepting a state the next operation cannot consume.
func requireLifecycleRecordPathV4(refs SignedArtifactRefs, phase Phase, directory string) error {
	base := string(phase) + "/" + directory + "/record"
	if refs.Record.Name != base+".json" || refs.Signature.Name != base+".sig" {
		return errors.New("lifecycle record must use its canonical transcript path")
	}
	return nil
}
