package mpcceremony

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// NewEnrollmentRecord derives the frozen definition and full-roster bindings;
// callers cannot substitute either digest.
func NewEnrollmentRecord(
	definition CeremonyDefinition,
	definitionBytes []byte,
	identity Identity,
	role EnrollmentRole,
	roleIndex uint16,
	disclosure ArtifactRef,
	enrolledAt string,
) (EnrollmentRecord, error) {
	rosterBytes, err := json.Marshal(definition.Roster)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	record := EnrollmentRecord{
		Schema:                 EnrollmentRecordSchema,
		CeremonyID:             definition.CeremonyID,
		Definition:             NewDigest(definitionBytes),
		FullRosterSHA256:       taggedSHA256(rosterBytes),
		Identity:               identity,
		Role:                   role,
		RoleIndex:              roleIndex,
		IndependenceDisclosure: disclosure,
		EnrolledAt:             enrolledAt,
	}
	if err := record.Validate(); err != nil {
		return EnrollmentRecord{}, err
	}
	if err := verifyEnrollmentBinding(definition, definitionBytes, record); err != nil {
		return EnrollmentRecord{}, err
	}
	return record, nil
}

func NewTransferHandoff(
	definition CeremonyDefinition,
	phase Phase,
	index uint8,
	headID string,
	files []ArtifactRef,
	sender, recipient Identity,
	createdAt, expiresAt string,
) (TransferHandoff, error) {
	record := TransferHandoff{
		Schema:            TransferHandoffSchema,
		CeremonyID:        definition.CeremonyID,
		Phase:             phase,
		Index:             index,
		PredecessorHeadID: headID,
		Source: TransferSourceBinding{
			SourceCommit: definition.Software.SourceCommit,
			ToolBinary:   definition.Software.ToolBinary,
			R1CS:         definition.Circuit.R1CS,
		},
		Files:          append([]ArtifactRef(nil), files...),
		SenderID:       sender.ID,
		SenderKeyID:    sender.KeyID,
		RecipientID:    recipient.ID,
		RecipientKeyID: recipient.KeyID,
		CreatedAt:      createdAt,
		ExpiresAt:      expiresAt,
	}
	if err := record.Validate(); err != nil {
		return TransferHandoff{}, err
	}
	if err := verifyTransferSource(definition, record.Source); err != nil {
		return TransferHandoff{}, err
	}
	if err := verifyTransferParty(definition, record.SenderID, record.SenderKeyID); err != nil {
		return TransferHandoff{}, err
	}
	if err := verifyTransferParty(definition, record.RecipientID, record.RecipientKeyID); err != nil {
		return TransferHandoff{}, err
	}
	return record, nil
}

func NewTransferReceipt(
	handoff TransferHandoff,
	handoffBytes []byte,
	kind TransferReceiptKind,
	receivedAt string,
) (TransferReceipt, error) {
	signerID, signerKeyID := handoff.RecipientID, handoff.RecipientKeyID
	record := TransferReceipt{
		Schema:            TransferReceiptSchema,
		Kind:              kind,
		HandoffSHA256:     taggedSHA256(handoffBytes),
		CeremonyID:        handoff.CeremonyID,
		Phase:             handoff.Phase,
		Index:             handoff.Index,
		PredecessorHeadID: handoff.PredecessorHeadID,
		Source:            handoff.Source,
		Files:             append([]ArtifactRef(nil), handoff.Files...),
		SenderID:          handoff.SenderID,
		SenderKeyID:       handoff.SenderKeyID,
		RecipientID:       handoff.RecipientID,
		RecipientKeyID:    handoff.RecipientKeyID,
		SignerID:          signerID,
		SignerKeyID:       signerKeyID,
		ReceivedAt:        receivedAt,
	}
	if err := VerifyTransferReceipt(handoffBytes, handoff, record); err != nil {
		return TransferReceipt{}, err
	}
	return record, nil
}

func NewImmutableMirrorReceipt(
	ceremonyID string,
	phase Phase,
	index uint8,
	acceptedHeadID string,
	files []ArtifactRef,
	mirror Identity,
	locationSHA256, storedAt string,
) (ImmutableMirrorReceipt, error) {
	record := ImmutableMirrorReceipt{
		Schema:                ImmutableMirrorReceiptSchema,
		CeremonyID:            ceremonyID,
		Phase:                 phase,
		Index:                 index,
		AcceptedHeadID:        acceptedHeadID,
		Files:                 append([]ArtifactRef(nil), files...),
		Mirror:                mirror,
		StorageLocationSHA256: locationSHA256,
		StoredAt:              storedAt,
	}
	return record, record.Validate()
}

// VerifyEnrollmentProofOfPossession authenticates an exact canonical
// enrollment record and its detached signature against the frozen ceremony.
func VerifyEnrollmentProofOfPossession(
	definition CeremonyDefinition,
	definitionBytes, recordBytes, signatureBytes []byte,
) (EnrollmentRecord, error) {
	if err := definition.Validate(); err != nil {
		return EnrollmentRecord{}, err
	}
	canonicalDefinition, err := MarshalCanonical(definition)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if !bytes.Equal(definitionBytes, canonicalDefinition) {
		return EnrollmentRecord{}, errors.New("definition bytes are not the exact canonical definition")
	}
	var record EnrollmentRecord
	if err := UnmarshalCanonical(recordBytes, &record); err != nil {
		return EnrollmentRecord{}, err
	}
	signer, err := VerifyOperationalRecordBinding(definition, definitionBytes, &record)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	publicKey, err := identityPublicKey(signer)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	var signature DetachedSignature
	if err := UnmarshalCanonical(signatureBytes, &signature); err != nil {
		return EnrollmentRecord{}, err
	}
	if err := VerifyExact(recordBytes, signature, signer.KeyID, publicKey); err != nil {
		return EnrollmentRecord{}, err
	}
	return record, nil
}

// MirrorReceiptFiles derives the only artifact set valid for a receipt over an
// accepted chain prefix.
func MirrorReceiptFiles(record ChainRecord, chainPrefix SignedArtifactRefs) ([]ArtifactRef, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	if err := chainPrefix.Validate(); err != nil {
		return nil, err
	}
	files := []ArtifactRef{
		record.Attestation,
		record.AttestationSignature,
		record.Erasure,
		record.ErasureSignature,
		record.OutputPayload,
		record.Verification,
		chainPrefix.Record,
		chainPrefix.Signature,
	}
	slices.SortFunc(files, compareArtifactRefName)
	if err := validateArtifactSet("files", files); err != nil {
		return nil, err
	}
	return files, nil
}

// PrepareImmutableMirrorReceipt replaces every authenticated draft field with
// values derived from the ceremony, exact chain prefix, and signed mirror
// enrollment. Any disagreement is rejected before canonical bytes exist.
func PrepareImmutableMirrorReceipt(
	definition CeremonyDefinition,
	chain Chain,
	chainPrefix SignedArtifactRefs,
	draft MirrorReceiptDraft,
	enrollment EnrollmentRecord,
) (ImmutableMirrorReceipt, []byte, error) {
	if err := definition.Validate(); err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	if err := chain.ValidateAgainstDefinition(definition); err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	if err := draft.Validate(); err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	definitionBytes, err := MarshalCanonical(definition)
	if err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	if _, err := VerifyOperationalRecordBinding(definition, definitionBytes, &enrollment); err != nil {
		return ImmutableMirrorReceipt{}, nil, fmt.Errorf("mirror enrollment binding: %w", err)
	}
	if enrollment.Role != EnrollmentMirrorOperator {
		return ImmutableMirrorReceipt{}, nil, errors.New("receipt enrollment role must be mirror-operator")
	}
	if int(draft.Index) != len(chain.Records) {
		return ImmutableMirrorReceipt{}, nil, fmt.Errorf(
			"receipt index %d must equal authenticated chain prefix length %d",
			draft.Index, len(chain.Records),
		)
	}
	record := chain.Records[len(chain.Records)-1]
	acceptedAt, _ := time.Parse(time.RFC3339Nano, record.AcceptedAt)
	storedAt, _ := time.Parse(time.RFC3339Nano, draft.StoredAt)
	if !storedAt.After(acceptedAt) {
		return ImmutableMirrorReceipt{}, nil, errors.New("mirror receipt stored_at must be after accepted head time")
	}
	expectedFiles, err := MirrorReceiptFiles(record, chainPrefix)
	if err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	if draft.CeremonyID != definition.CeremonyID || draft.CeremonyID != chain.CeremonyID ||
		draft.Phase != chain.Phase || draft.AcceptedHeadID != record.RecordID ||
		!mirrorDraftFilesMatch(draft.Files, expectedFiles) {
		return ImmutableMirrorReceipt{}, nil, errors.New("mirror receipt draft does not bind the exact authenticated accepted-head prefix")
	}
	receipt, err := NewImmutableMirrorReceipt(
		definition.CeremonyID,
		chain.Phase,
		draft.Index,
		record.RecordID,
		expectedFiles,
		enrollment.Identity,
		draft.StorageLocationSHA256,
		draft.StoredAt,
	)
	if err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	canonical, err := MarshalCanonical(receipt)
	if err != nil {
		return ImmutableMirrorReceipt{}, nil, err
	}
	return receipt, canonical, nil
}

func mirrorDraftFilesMatch(draft, expected []ArtifactRef) bool {
	if len(draft) != len(expected) {
		return false
	}
	for index := range draft {
		if draft[index].Name != expected[index].Name ||
			draft[index].Digest.SHA256 != expected[index].Digest.SHA256 ||
			draft[index].Digest.Size != expected[index].Digest.Size ||
			(draft[index].Digest.Blake2b256 != "" &&
				draft[index].Digest.Blake2b256 != expected[index].Digest.Blake2b256) {
			return false
		}
	}
	return true
}

func NewPublicWitnessReceipt(
	definition CeremonyDefinition,
	close CloseRecord,
	closeBytes []byte,
	witness Identity,
	closureName, locationSHA256, observedAt string,
) (PublicWitnessReceipt, error) {
	roundTime, err := QuicknetRoundTime(close.BeaconRound)
	if err != nil {
		return PublicWitnessReceipt{}, err
	}
	record := PublicWitnessReceipt{
		Schema:                 PublicWitnessReceiptSchema,
		CeremonyID:             definition.CeremonyID,
		Phase:                  close.Phase,
		CloseID:                close.CloseID,
		ChainHeadID:            close.ChainHeadID,
		Closure:                ArtifactRef{Name: closureName, Digest: NewDigest(closeBytes)},
		BeaconRound:            close.BeaconRound,
		BeaconScheduledAt:      roundTime.Format("2006-01-02T15:04:05Z"),
		PublicationLocationSHA: locationSHA256,
		Witness:                witness,
		ObservedAt:             observedAt,
	}
	if err := ValidatePublicWitnessReceipt(definition, close, closeBytes, record); err != nil {
		return PublicWitnessReceipt{}, err
	}
	return record, nil
}

// PreparePublicWitnessReceipt derives canonical receipt bytes from an
// authenticated public-witness enrollment and a human's publication claim.
// It hashes the location before record construction and never signs anything.
func PreparePublicWitnessReceipt(
	definition CeremonyDefinition,
	close CloseRecord,
	closeBytes []byte,
	enrollment EnrollmentRecord,
	closureName, publicationLocation, observedAt string,
) (PublicWitnessReceipt, []byte, error) {
	definitionBytes, err := MarshalCanonical(definition)
	if err != nil {
		return PublicWitnessReceipt{}, nil, err
	}
	if _, err := VerifyOperationalRecordBinding(definition, definitionBytes, &enrollment); err != nil {
		return PublicWitnessReceipt{}, nil, fmt.Errorf("witness enrollment binding: %w", err)
	}
	if enrollment.Role != EnrollmentPublicWitness {
		return PublicWitnessReceipt{}, nil, errors.New("receipt enrollment role must be public-witness")
	}
	receipt, err := NewPublicWitnessReceipt(
		definition,
		close,
		closeBytes,
		enrollment.Identity,
		closureName,
		taggedSHA256([]byte(publicationLocation)),
		observedAt,
	)
	if err != nil {
		return PublicWitnessReceipt{}, nil, err
	}
	canonical, err := MarshalCanonical(receipt)
	if err != nil {
		return PublicWitnessReceipt{}, nil, err
	}
	return receipt, canonical, nil
}

func NewMultiRelayBeaconEvidence(
	definition CeremonyDefinition,
	close CloseRecord,
	observations []RelayObservation,
	rawResponses map[string][]byte,
	recordedAt string,
) (MultiRelayBeaconEvidence, error) {
	record := MultiRelayBeaconEvidence{
		Schema:           MultiRelayBeaconEvidenceSchema,
		CeremonyID:       definition.CeremonyID,
		Phase:            close.Phase,
		CloseID:          close.CloseID,
		BeaconRound:      close.BeaconRound,
		Provider:         definition.BeaconPolicy.Provider,
		Network:          definition.BeaconPolicy.Network,
		Observations:     append([]RelayObservation(nil), observations...),
		CoordinatorID:    definition.Coordinator.ID,
		CoordinatorKeyID: definition.Coordinator.KeyID,
		RecordedAt:       recordedAt,
	}
	if err := ValidateMultiRelayBeaconEvidence(definition, close, record, rawResponses); err != nil {
		return MultiRelayBeaconEvidence{}, fmt.Errorf("multi-relay evidence: %w", err)
	}
	return record, nil
}
