package mpcceremony

import (
	"errors"
	"slices"
	"time"
)

// Receipt counts are reconstructed from authenticated evidence; one signature
// never satisfies another head or a second mirror identity.
func verifyCheckpointMirrorsV4(reader *checkpointReaderV4, d CeremonyDefinition, db []byte, accepted map[ContributionScope]SignedArtifactRefs, enrollments map[string]EnrollmentRecord, refs []SignedArtifactRefs) (map[ContributionScope]map[string]bool, error) {
	result := map[ContributionScope]map[string]bool{}
	if d.AssurancePolicy.MirrorsPerAcceptedHead == 0 && len(refs) > 0 {
		return nil, errors.New("mirror evidence is disabled by signed policy")
	}
	for _, pair := range refs {
		rb, sb, err := reader.pair(pair)
		if err != nil {
			return nil, err
		}
		var receipt ImmutableMirrorReceipt
		if err = UnmarshalCanonical(rb, &receipt); err != nil {
			return nil, err
		}
		signer, err := VerifyOperationalRecordBinding(d, db, &receipt)
		if err != nil {
			return nil, err
		}
		key, err := identityPublicKey(signer)
		if err != nil {
			return nil, err
		}
		if err = VerifySignedRecord(rb, sb, &receipt, signer.KeyID, key); err != nil {
			return nil, err
		}
		enrollment, ok := enrollments[receipt.Mirror.ID]
		if !ok || enrollment.Role != EnrollmentMirrorOperator || enrollment.Identity != receipt.Mirror {
			return nil, errors.New("mirror has no matching committed enrollment")
		}
		found := false
		for scope, chainRefs := range accepted {
			if scope.Phase != receipt.Phase || scope.Index != receipt.Index {
				continue
			}
			cb, cs, err := reader.pair(chainRefs)
			if err != nil {
				return nil, err
			}
			var chain Chain
			coordinatorKey, err := identityPublicKey(d.Coordinator)
			if err != nil {
				return nil, err
			}
			if err = VerifySignedRecord(cb, cs, &chain, d.Coordinator.KeyID, coordinatorKey); err != nil {
				return nil, err
			}
			if err = chain.ValidateAgainstDefinition(d); err != nil {
				return nil, err
			}
			if len(chain.Records) != int(scope.Index) {
				return nil, errors.New("mirror chain does not match accepted turn")
			}
			record := chain.Records[len(chain.Records)-1]
			files, err := MirrorReceiptFiles(record, chainRefs)
			if err != nil {
				return nil, err
			}
			if receipt.AcceptedHeadID != record.RecordID || !slices.Equal(receipt.Files, files) {
				return nil, errors.New("mirror receipt does not cover the exact accepted head files")
			}
			stored, _ := time.Parse(time.RFC3339Nano, receipt.StoredAt)
			acceptedAt, _ := time.Parse(time.RFC3339Nano, record.AcceptedAt)
			if !stored.After(acceptedAt) {
				return nil, errors.New("mirror receipt predates acceptance")
			}
			if result[scope] == nil {
				result[scope] = map[string]bool{}
			}
			if result[scope][receipt.Mirror.PublicKeyFingerprint] {
				return nil, errors.New("duplicate mirror receipt for this head")
			}
			result[scope][receipt.Mirror.PublicKeyFingerprint] = true
			found = true
			break
		}
		if !found {
			return nil, errors.New("mirror receipt names no committed accepted head")
		}
	}
	return result, nil
}
