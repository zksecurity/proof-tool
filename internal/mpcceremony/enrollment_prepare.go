package mpcceremony

import (
	"bytes"
	"encoding/json"
	"errors"
)

// PrepareEnrollment derives frozen ceremony bindings; it does not claim that
// the identity belongs to an independent human or that its owner consented.
func PrepareEnrollment(definition CeremonyDefinition, definitionBytes []byte, identity Identity, role EnrollmentRole, externalIndex uint16, disclosure ArtifactRef, enrolledAt string) (EnrollmentRecord, error) {
	if err := definition.Validate(); err != nil {
		return EnrollmentRecord{}, err
	}
	canonical, err := MarshalCanonical(definition)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if !bytes.Equal(canonical, definitionBytes) {
		return EnrollmentRecord{}, errors.New("definition bytes do not match the validated definition")
	}
	roster, err := json.Marshal(definition.Roster)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	index := externalIndex
	if _, _, position, ok := definitionRoleAt(definition, identity.ID); ok {
		index = position
	}
	record := EnrollmentRecord{EnrollmentRecordSchema, definition.CeremonyID, NewDigest(definitionBytes), taggedSHA256(roster), identity, role, index, disclosure, enrolledAt}
	if err := record.Validate(); err != nil {
		return EnrollmentRecord{}, err
	}
	if err := verifyEnrollmentBinding(definition, definitionBytes, record); err != nil {
		return EnrollmentRecord{}, err
	}
	return record, nil
}
