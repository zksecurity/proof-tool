package mpcceremony

import (
	"errors"
	"io"
	"os"
	"time"
)

// ContributionInventoryInspectionV4 describes authenticated local bytes, not
// valid contribution mathematics, actual erasure, acceptance or backend freshness.
// Uploaders must check these digests again: this inspection cannot freeze paths.
type ContributionInventoryInspectionV4 struct {
	Scope               ContributionScope   `json:"scope"`
	Predecessor         SignedArtifactRefs  `json:"predecessor"`
	Computed            CandidateInventory  `json:"computed"`
	ComputedCandidateID string              `json:"computed_candidate_id"`
	Complete            *CandidateInventory `json:"complete,omitempty"`
	CandidateResultID   string              `json:"candidate_result_id,omitempty"`
}

// InspectContributionInventoryV4 reconstructs the fixed five-file candidate.
// expected must come from
// the caller's authenticated turn (or the exact retained operation on recovery).
// Extra local files are ignored, never added to either returned inventory.
func InspectContributionInventoryV4(trust TrustPaths, predecessor PhaseTranscriptPaths, expected ContributionScope, candidateDir string) (ContributionInventoryInspectionV4, error) {
	trusted, err := LoadSignedDefinition(trust)
	if err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	d := trusted.Definition
	if d.Schema != DefinitionSchemaV4 {
		return ContributionInventoryInspectionV4{}, errors.New("contribution inventory inspection requires definition v4")
	}
	if err := expected.ValidateAssignment(d); err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	chain, refs, err := LoadSignedChainExact(trusted, predecessor)
	if err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	head, err := chain.HeadRecordID()
	if err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	if chain.Phase != expected.Phase || len(chain.Records)+1 != int(expected.Index) || head != expected.ParentHeadID {
		return ContributionInventoryInspectionV4{}, errors.New("signed predecessor differs from the exact expected turn")
	}
	reader, err := openCheckpointReaderV4(candidateDir)
	if err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	defer func() { _ = reader.root.Close() }()
	result, err := inspectContributionInventoryV4(reader, d, chain, expected)
	if err != nil {
		return ContributionInventoryInspectionV4{}, err
	}
	result.Predecessor = refs
	return result, nil
}

func inspectContributionInventoryV4(r *checkpointReaderV4, d CeremonyDefinition, chain Chain, scope ContributionScope) (ContributionInventoryInspectionV4, error) {
	var zero ContributionInventoryInspectionV4
	generated, attestation, err := inspectComputationOutputV4(r, d, chain, scope)
	if err != nil {
		return zero, err
	}
	names := []string{"erasure.json", "erasure.sig"}
	data := map[string][]byte{}
	for _, name := range names {
		limit := int64(maxSignedRecordBytes)
		if name == "attestation.sig" || name == "erasure.sig" {
			limit = 4096
		}
		b, err := readLocalInventoryRecordV4(r, name, limit)
		if err != nil {
			return zero, err
		}
		data[name] = b
	}
	participant, ok := d.ParticipantByID(scope.ParticipantID)
	if !ok {
		return zero, errors.New("candidate participant is not scheduled")
	}
	key, err := identityPublicKey(participant.Identity)
	if err != nil {
		return zero, err
	}
	var erasure ErasureAttestation
	if err := VerifySignedRecord(data["erasure.json"], data["erasure.sig"], &erasure, participant.Identity.KeyID, key); err != nil {
		return zero, candidateInvalid(err)
	}
	if err := ValidateErasureForContribution(attestation, erasure); err != nil {
		return zero, candidateInvalid(err)
	}
	computed := CandidateInventory{Schema: CandidateInventorySchemaV1, Scope: scope, Files: append(append([]ArtifactRef{}, generated.Files...),
		ArtifactRef{Name: "erasure.json", Digest: NewDigest(data["erasure.json"])},
		ArtifactRef{Name: "erasure.sig", Digest: NewDigest(data["erasure.sig"])})}
	id, err := computed.ID()
	if err != nil {
		return zero, err
	}
	return ContributionInventoryInspectionV4{Scope: scope, Computed: computed, ComputedCandidateID: id, Complete: &computed, CandidateResultID: id}, nil
}

// Only fixed basenames reach this helper. os.Root confines resolution, and
// descriptor identity/metadata checks reject substitution during the read.
func readLocalInventoryRecordV4(r *checkpointReaderV4, name string, limit int64) ([]byte, error) {
	before, err := r.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return nil, errors.New("inventory record must be a bounded regular file")
	}
	f, err := r.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return nil, errors.New("inventory record changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("inventory record changed while reading")
	}
	return b, nil
}

func validateAttestationSoftwareBinding(d CeremonyDefinition, a ContributionAttestation) error {
	if !d.Software.AllowsToolBinary(a.ToolBinary) || d.Software.SourceCommit != a.SourceCommit || d.Software.GnarkVersion != a.GnarkVersion || d.Software.GnarkCryptoVersion != a.GnarkCryptoVersion || d.Software.DrandVersion != a.DrandVersion {
		return errors.New("attestation software binding does not match definition")
	}
	return nil
}

func validateContributionChronology(d CeremonyDefinition, chain Chain, a ContributionAttestation) error {
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	contributed, _ := time.Parse(time.RFC3339Nano, a.ContributedAt)
	if !contributed.After(created) {
		return errors.New("contributed_at must be strictly after the ceremony definition")
	}
	if len(chain.Records) > 0 {
		previous, _ := time.Parse(time.RFC3339Nano, chain.Records[len(chain.Records)-1].AcceptedAt)
		if !contributed.After(previous) {
			return errors.New("contributed_at must be strictly after the previous acceptance")
		}
	}
	return nil
}
