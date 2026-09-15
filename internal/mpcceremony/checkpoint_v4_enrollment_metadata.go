package mpcceremony

import "errors"

// EnrollmentMetadataV4 verifies identities and proof of possession for the
// complete checkpoint-committed enrollment set, not disclosure file contents
// or completeness against the required ceremony roster.
type EnrollmentMetadataV4 struct {
	CeremonyID  string                          `json:"ceremony_id"`
	Checkpoint  SignedArtifactRefs              `json:"checkpoint"`
	Enrollments []CommittedEnrollmentMetadataV4 `json:"enrollments"`
}

type CommittedEnrollmentMetadataV4 struct {
	Refs       SignedArtifactRefs `json:"refs"`
	Enrollment EnrollmentRecord   `json:"enrollment"`
}

func InspectCheckpointEnrollmentsV4(trust TrustPaths, artifactRoot string, head SignedArtifactRefs) (EnrollmentMetadataV4, error) {
	_, _, metadata, err := InspectCheckpointGuidanceV4(trust, artifactRoot, head)
	return metadata, err
}

// InspectCheckpointGuidanceV4 authenticates ancestry once and returns two
// distinct results: structural commitments and verified enrollment metadata.
func InspectCheckpointGuidanceV4(trust TrustPaths, artifactRoot string, head SignedArtifactRefs) (CheckpointV4, CheckpointCommitmentsV4, EnrollmentMetadataV4, error) {
	c, err := openStoredCheckpointV4(trust, artifactRoot, head)
	if err != nil {
		return CheckpointV4{}, CheckpointCommitmentsV4{}, EnrollmentMetadataV4{}, err
	}
	defer c.reader.root.Close()
	index, err := checkpointCommitmentsV4(c.ancestry)
	if err != nil {
		return CheckpointV4{}, CheckpointCommitmentsV4{}, EnrollmentMetadataV4{}, err
	}
	metadata, err := checkpointEnrollmentMetadataV4(c, head)
	if err != nil {
		return CheckpointV4{}, CheckpointCommitmentsV4{}, EnrollmentMetadataV4{}, err
	}
	return c.ancestry.head, index, metadata, nil
}

func checkpointEnrollmentMetadataV4(c *storedCheckpointContextV4, head SignedArtifactRefs) (EnrollmentMetadataV4, error) {
	if len(c.ancestry.enrollments) > 128 {
		return EnrollmentMetadataV4{}, errors.New("checkpoint enrollment set exceeds protocol capacity")
	}
	r := EnrollmentMetadataV4{CeremonyID: c.trusted.Definition.CeremonyID, Checkpoint: head, Enrollments: []CommittedEnrollmentMetadataV4{}}
	seen := map[string]EnrollmentRecord{}
	disclosures := map[SignedArtifactRefs]ArtifactRef{}
	for _, tx := range c.ancestry.enrollmentTransitions {
		if len(tx.Evidence) != 1 {
			return EnrollmentMetadataV4{}, errors.New("invalid committed enrollment disclosure reference")
		}
		disclosures[*tx.Record] = tx.Evidence[0]
	}
	for _, pair := range sortedSignedRefsV4(c.ancestry.enrollments) {
		raw, sig, err := c.reader.pair(pair)
		if err != nil {
			return EnrollmentMetadataV4{}, err
		}
		record, err := VerifyEnrollmentProofOfPossession(c.trusted.Definition, c.definitionBytes, raw, sig)
		if err != nil {
			return EnrollmentMetadataV4{}, err
		}
		if record.IndependenceDisclosure != disclosures[pair] {
			return EnrollmentMetadataV4{}, errors.New("enrollment disclosure reference differs from committed evidence")
		}
		if (record.Role == EnrollmentPublicWitness || record.Role == EnrollmentMirrorOperator) && record.RoleIndex > MaxAuditors {
			return EnrollmentMetadataV4{}, errors.New("observer assignment exceeds protocol capacity")
		}
		if err := addCheckpointEnrollmentV4(seen, record); err != nil {
			return EnrollmentMetadataV4{}, err
		}
		r.Enrollments = append(r.Enrollments, CommittedEnrollmentMetadataV4{Refs: pair, Enrollment: record})
	}
	return r, nil
}
