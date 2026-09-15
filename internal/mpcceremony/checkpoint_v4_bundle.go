package mpcceremony

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

type OperationalBundlePreparationV4 struct {
	SourceCheckpoint SignedArtifactRefs        `json:"source_checkpoint"`
	Bundle           OperationalEvidenceBundle `json:"bundle"`
}

func (p OperationalBundlePreparationV4) Validate() error {
	if err := p.SourceCheckpoint.Validate(); err != nil {
		return err
	}
	return p.Bundle.Validate()
}

// PrepareOperationalBundleV4 reads only the exact authenticated history. It
// neither discovers loose files nor signs, uploads or replays contributions.
// The eventual signer must rederive against the same exact predecessor.
func PrepareOperationalBundleV4(trust TrustPaths, artifactRoot string, head SignedArtifactRefs, assembledAt time.Time) (OperationalBundlePreparationV4, error) {
	if assembledAt.IsZero() || assembledAt.Location() != time.UTC {
		return OperationalBundlePreparationV4{}, errors.New("assembled_at must be a nonzero UTC time")
	}
	trusted, err := loadOperationalCeremony(trust)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	db, err := MarshalCanonical(trusted.Definition)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	ds, err := readRegularBounded(trust.DefinitionSignaturePath, 4096)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	reader, err := openCheckpointReaderV4(artifactRoot)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	defer reader.root.Close()
	ancestry, err := loadCheckpointAncestryV4(reader, trusted.Definition, db, ds, head)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	bundle, err := deriveOperationalBundleV4(reader, trusted, db, ancestry, assembledAt)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	raw, err := MarshalCanonical(bundle)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	first, err := LoadAuthenticatedCloseEvidence(reader.path, bundle.Phase1.Close)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	second, err := LoadAuthenticatedCloseEvidence(reader.path, bundle.Phase2.Close)
	if err != nil {
		return OperationalBundlePreparationV4{}, err
	}
	if err = VerifyOperationalEvidenceDraft(VerifyOperationalEvidenceOptions{Definition: trusted.Definition, CoordinatorPublicKey: trusted.CoordinatorPublicKey, EvidenceRoot: reader.path, BundleBytes: raw, Phase1Close: first, Phase2Close: second}); err != nil {
		return OperationalBundlePreparationV4{}, fmt.Errorf("derived bundle verification: %w", err)
	}
	return OperationalBundlePreparationV4{SourceCheckpoint: head, Bundle: bundle}, nil
}

func sortedSignedRefsV4(refs []SignedArtifactRefs) []SignedArtifactRefs {
	result := append([]SignedArtifactRefs{}, refs...)
	slices.SortFunc(result, func(a, b SignedArtifactRefs) int { return strings.Compare(a.Record.Name, b.Record.Name) })
	return result
}

func deriveOperationalBundleV4(reader *checkpointReaderV4, trusted *TrustedCeremony, db []byte, a checkpointAncestryV4, at time.Time) (OperationalEvidenceBundle, error) {
	p := a.head.Progress
	d := trusted.Definition
	if p.FinalCandidate == nil || p.FinalRelease != nil {
		return OperationalEvidenceBundle{}, errors.New("bundle preparation requires a frozen candidate before final release")
	}
	enrollments, err := loadCheckpointEnrollmentsV4(reader, d, db, a.enrollments)
	if err != nil {
		return OperationalEvidenceBundle{}, err
	}
	for _, identity := range append([]Identity{d.Coordinator, d.ReleaseSigner}, preparationRoster(d)...) {
		if _, ok := enrollments[identity.ID]; !ok {
			return OperationalEvidenceBundle{}, fmt.Errorf("required proof-of-possession enrollment for %q is missing", identity.ID)
		}
	}
	if _, err = verifyCheckpointMirrorsV4(reader, d, db, a.accepted, enrollments, a.mirrors); err != nil {
		return OperationalEvidenceBundle{}, err
	}
	if _, err = verifyCheckpointWitnessesV4(reader, d, p, enrollments, a.witnesses); err != nil {
		return OperationalEvidenceBundle{}, err
	}
	if _, err = verifyCheckpointBeaconEvidenceV4(reader, d, p, a.beaconEvidence, CheckpointTransitionV4{}); err != nil {
		return OperationalEvidenceBundle{}, err
	}
	read := func(refs SignedArtifactRefs, out any) error {
		rb, _, err := reader.pair(refs)
		if err != nil {
			return err
		}
		return UnmarshalCanonical(rb, out)
	}
	witnesses := map[Phase][]SignedArtifactRefs{}
	mirrors := map[Phase]map[uint8][]SignedArtifactRefs{Phase1: {}, Phase2: {}}
	beacons := map[Phase]SignedArtifactRefs{}
	raws := map[Phase][]ArtifactRef{}
	for _, refs := range a.witnesses {
		var r PublicWitnessReceipt
		if err = read(refs, &r); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		witnesses[r.Phase] = append(witnesses[r.Phase], refs)
	}
	for _, refs := range a.mirrors {
		var r ImmutableMirrorReceipt
		if err = read(refs, &r); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		mirrors[r.Phase][r.Index] = append(mirrors[r.Phase][r.Index], refs)
	}
	for _, refs := range a.beaconEvidence {
		var r MultiRelayBeaconEvidence
		if err = read(refs, &r); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		beacons[r.Phase] = refs
		for _, ob := range r.Observations {
			raws[r.Phase] = append(raws[r.Phase], ob.RawResponse)
		}
	}
	bundle := OperationalEvidenceBundle{Schema: OperationalEvidenceBundleSchema, CeremonyID: d.CeremonyID, AssurancePolicy: cloneAssurancePolicy(d.AssurancePolicy), Enrollments: sortedSignedRefsV4(a.enrollments), GovernanceRecords: []SignedArtifactRefs{}, CoordinatorID: d.Coordinator.ID, CoordinatorKeyID: d.Coordinator.KeyID, AssembledAt: at.Format(time.RFC3339Nano)}
	used := 0
	for _, phase := range []Phase{Phase1, Phase2} {
		state := p.Phase1
		close := p.Phase1Closure
		if phase == Phase2 {
			state = *p.Phase2
			close = p.Phase2Closure
		}
		var chain Chain
		cb, cs, err := reader.pair(state.Chain)
		if err != nil {
			return OperationalEvidenceBundle{}, err
		}
		if err = VerifySignedRecord(cb, cs, &chain, d.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		if err = chain.ValidateAgainstDefinition(d); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		if err = verifyV4ChainProjection(chain, state.Chain, state); err != nil {
			return OperationalEvidenceBundle{}, err
		}
		pe := PhaseOperationalEvidence{Phase: phase, AcceptedChain: state.Chain, Close: *close, AcceptedHeads: []AcceptedHeadOperationalEvidence{}, PublicWitnessQuorum: d.AssurancePolicy.PublicWitnessesPerPhase, PublicWitnessReceipts: sortedSignedRefsV4(witnesses[phase]), MultiRelayBeaconEvidence: beacons[phase], RawBeaconResponses: append([]ArtifactRef{}, raws[phase]...)}
		slices.SortFunc(pe.RawBeaconResponses, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
		for _, record := range chain.Records {
			scope := ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: record.Index, ParticipantID: record.ParticipantID, ParentHeadID: record.PreviousRecordID}
			tx, ok := a.acceptedTransitions[scope]
			if !ok {
				return OperationalEvidenceBundle{}, fmt.Errorf("%s turn %d lacks its accepted checkpoint", phase, record.Index)
			}
			used++
			receipt, ok := a.receipts[scope]
			if !ok {
				return OperationalEvidenceBundle{}, fmt.Errorf("%s turn %d lacks its committed input receipt", phase, record.Index)
			}
			var received TransferReceipt
			if err = read(receipt, &received); err != nil {
				return OperationalEvidenceBundle{}, err
			}
			handoff, ok := a.outbound[received.HandoffSHA256]
			if !ok {
				return OperationalEvidenceBundle{}, errors.New("accepted receipt has no committed original handoff")
			}
			files := map[string]ArtifactRef{}
			for _, r := range tx.Evidence {
				files[r.Name] = r
			}
			dir := path.Dir(record.Attestation.Name)
			returnHandoff := SignedArtifactRefs{Record: files[dir+"/return-handoff.json"], Signature: files[dir+"/return-handoff.sig"]}
			returnReceipt := SignedArtifactRefs{Record: files[dir+"/return-receipt.json"], Signature: files[dir+"/return-receipt.sig"]}
			if err = returnHandoff.Validate(); err != nil {
				return OperationalEvidenceBundle{}, fmt.Errorf("%s turn %d missing committed return handoff: %w", phase, record.Index, err)
			}
			if err = returnReceipt.Validate(); err != nil {
				return OperationalEvidenceBundle{}, fmt.Errorf("%s turn %d missing committed return receipt: %w", phase, record.Index, err)
			}
			pe.AcceptedHeads = append(pe.AcceptedHeads, AcceptedHeadOperationalEvidence{Index: record.Index, PredecessorHeadID: record.PreviousRecordID, AcceptedHeadID: record.RecordID, OutboundHandoff: handoff, OutboundReceipt: receipt, ReturnHandoff: returnHandoff, ReturnReceipt: returnReceipt, AcceptedChainPrefix: *tx.Record, MirrorReceipts: sortedSignedRefsV4(mirrors[phase][record.Index])})
		}
		if phase == Phase1 {
			bundle.Phase1 = pe
		} else {
			bundle.Phase2 = pe
		}
	}
	if used != len(a.acceptedTransitions) {
		return OperationalEvidenceBundle{}, errors.New("accepted checkpoints do not match the final chains one for one")
	}
	return bundle, nil
}
