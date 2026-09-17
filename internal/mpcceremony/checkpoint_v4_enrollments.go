package mpcceremony

import "errors"

func readCheckpointEnrollmentV4(reader *checkpointReaderV4, d CeremonyDefinition, db []byte, refs SignedArtifactRefs) (EnrollmentRecord, error) {
	rb, sb, err := reader.pair(refs)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	var record EnrollmentRecord
	if err = UnmarshalCanonical(rb, &record); err != nil {
		return record, err
	}
	if err = record.Validate(); err != nil {
		return record, err
	}
	if (record.Role == EnrollmentPublicWitness || record.Role == EnrollmentMirrorOperator) && record.RoleIndex > MaxAuditors {
		return record, errors.New("observer assignment exceeds the supported role limit")
	}
	signer, err := VerifyOperationalRecordBinding(d, db, &record)
	if err != nil {
		return record, err
	}
	key, err := identityPublicKey(signer)
	if err != nil {
		return record, err
	}
	if err = VerifySignedRecord(rb, sb, &record, signer.KeyID, key); err != nil {
		return record, err
	}
	if _, err = reader.read(record.IndependenceDisclosure, maxEnrollmentDisclosureBytes, false); err != nil {
		return record, err
	}
	return record, nil
}

func addCheckpointEnrollmentV4(records map[string]EnrollmentRecord, record EnrollmentRecord) error {
	for _, previous := range records {
		if previous.Identity.ID == record.Identity.ID || previous.Identity.KeyID == record.Identity.KeyID || previous.Identity.PublicKeyFingerprint == record.Identity.PublicKeyFingerprint || (previous.Role == record.Role && previous.RoleIndex == record.RoleIndex) {
			return errors.New("enrollment duplicates an already committed identity, key or role assignment")
		}
	}
	if len(records) >= 128 {
		return errors.New("enrollment collection exceeds bundle capacity")
	}
	records[record.Identity.ID] = record
	return nil
}

func loadCheckpointEnrollmentsV4(reader *checkpointReaderV4, d CeremonyDefinition, db []byte, refs []SignedArtifactRefs) (map[string]EnrollmentRecord, error) {
	records := map[string]EnrollmentRecord{}
	for _, ref := range refs {
		record, err := readCheckpointEnrollmentV4(reader, d, db, ref)
		if err != nil {
			return nil, err
		}
		if err = addCheckpointEnrollmentV4(records, record); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func verifyNewCheckpointEnrollmentV4(reader *checkpointReaderV4, d CeremonyDefinition, db []byte, tx CheckpointTransitionV4, records map[string]EnrollmentRecord) error {
	record, err := readCheckpointEnrollmentV4(reader, d, db, *tx.Record)
	if err != nil {
		return err
	}
	if len(tx.Evidence) != 1 || tx.Evidence[0] != record.IndependenceDisclosure {
		return errors.New("enrollment evidence differs from its signed disclosure")
	}
	return addCheckpointEnrollmentV4(records, record)
}
