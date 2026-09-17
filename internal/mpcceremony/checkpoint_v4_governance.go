package mpcceremony

import (
	"errors"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"
)

func governanceKindV4(kind CheckpointTransitionKind) GovernanceKind {
	switch kind {
	case CheckpointIncidentRecorded:
		return GovernanceIncident
	case CheckpointAborted:
		return GovernanceAbort
	case CheckpointRestarted:
		return GovernanceRestart
	default:
		return ""
	}
}

func isGovernanceTransitionV4(kind CheckpointTransitionKind) bool {
	return governanceKindV4(kind) != ""
}

// The signed checkpoint is the authorization against its exact predecessor.
// The legacy record is a reviewed factual statement; its time is not freshness.
func verifyCheckpointGovernanceV4(reader *checkpointReaderV4, d CeremonyDefinition, previous CheckpointV4, t CheckpointTransitionV4) error {
	for _, ref := range previous.AcceptedArtifacts {
		if ref.Digest == t.Record.Record.Digest {
			return errors.New("governance record is already committed")
		}
	}
	record, err := verifyGovernanceRecordV4(reader, d, t)
	if err != nil {
		return err
	}
	state := previous.Progress.Phase1
	if previous.Progress.Phase2 != nil {
		state = *previous.Progress.Phase2
	}
	index := state.AcceptedCount
	if index == 0 {
		index = 1
	} // Legacy one-based phase position, not a contribution count.
	if record.Phase != state.Phase || record.Index != index || record.HeadID != state.HeadRecordID {
		return errors.New("governance does not name the exact current phase and head")
	}
	return nil
}

func verifyGovernanceRecordV4(reader *checkpointReaderV4, d CeremonyDefinition, t CheckpointTransitionV4) (GovernanceRecord, error) {
	var record GovernanceRecord
	if !isGovernanceTransitionV4(t.Kind) {
		return record, errors.New("not a V4 governance edge")
	}
	if err := t.Validate(); err != nil {
		return record, err
	}
	raw, sig, err := reader.pair(*t.Record)
	if err != nil {
		return record, err
	}
	key, err := identityPublicKey(d.Coordinator)
	if err != nil {
		return record, err
	}
	if err = VerifySignedRecord(raw, sig, &record, d.Coordinator.KeyID, key); err != nil {
		return record, err
	}
	if record.Kind != governanceKindV4(t.Kind) || record.CeremonyID != d.CeremonyID || record.SignerID != d.Coordinator.ID || record.SignerKeyID != d.Coordinator.KeyID {
		return GovernanceRecord{}, errors.New("V4 governance requires this ceremony's coordinator and exact action")
	}
	if !slices.Equal(record.Evidence, t.Evidence) {
		return GovernanceRecord{}, errors.New("governance evidence differs from the checkpoint")
	}
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	at, _ := time.Parse(time.RFC3339Nano, record.RecordedAt)
	if at.Before(created) {
		return GovernanceRecord{}, errors.New("governance statement predates the definition")
	}
	statements := 0
	statementDigests := 0
	for _, ref := range t.Evidence {
		if ref.Digest.SHA256 == record.StatementSHA256 {
			statementDigests++
		}
		if t.RestartDefinition != nil && (ref == t.RestartDefinition.Record || ref == t.RestartDefinition.Signature) {
			continue
		}
		statements++
		if ref.Digest.SHA256 != record.StatementSHA256 {
			return GovernanceRecord{}, errors.New("public statement digest does not match governance")
		}
		content, err := reader.read(ref, 1<<20, true)
		if err != nil {
			return GovernanceRecord{}, err
		}
		if !utf8.Valid(content) {
			return GovernanceRecord{}, errors.New("public governance statement must be UTF-8 text")
		}
	}
	if statements != 1 || statementDigests != 1 {
		return GovernanceRecord{}, errors.New("governance requires exactly one public statement")
	}
	if t.RestartDefinition != nil {
		var next CeremonyDefinition
		db, ds, err := reader.pair(*t.RestartDefinition)
		if err != nil {
			return GovernanceRecord{}, err
		}
		if err = UnmarshalCanonical(db, &next); err != nil {
			return GovernanceRecord{}, err
		}
		if next.Schema != DefinitionSchemaV4 {
			return GovernanceRecord{}, errors.New("V4 restart requires a new V4 definition")
		}
		newKey, err := identityPublicKey(next.Coordinator)
		if err != nil {
			return GovernanceRecord{}, err
		}
		var verified CeremonyDefinition
		if err = VerifySignedRecord(db, ds, &verified, next.Coordinator.KeyID, newKey); err != nil {
			return GovernanceRecord{}, err
		}
		if !reflect.DeepEqual(next, verified) {
			return GovernanceRecord{}, errors.New("restart definition differs from authenticated bytes")
		}
		if err = ValidateRestartRecord(d, next, record); err != nil {
			return GovernanceRecord{}, err
		}
		newTime, _ := time.Parse(time.RFC3339Nano, next.CreatedAt)
		if newTime.After(at) {
			return GovernanceRecord{}, errors.New("restart statement predates the new definition")
		}
	}
	return record, nil
}
