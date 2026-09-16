package mpcceremony

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"proof-tool/internal/keybundle"
)

const FinalReleasePackagePrefixV4 = "final/release/"

// FinalReleaseInventoryV4 keeps package-relative names distinct from ceremony
// storage locations. It describes a verified private package, not publication.
type FinalReleaseInventoryV4 struct {
	prefix    string
	artifacts []ArtifactRef
	members   map[string]ArtifactRef
}

func (i FinalReleaseInventoryV4) PackagePrefix() string { return i.prefix }

// Artifacts returns a copy; callers cannot change the verified membership.
func (i FinalReleaseInventoryV4) Artifacts() []ArtifactRef { return slices.Clone(i.artifacts) }

// ValidateFinalReleaseInventoryArtifactsV4 checks a package-relative inventory's
// shape only. It does not authenticate any files or turn a report into authority.
func ValidateFinalReleaseInventoryArtifactsV4(artifacts []ArtifactRef) error {
	if len(artifacts) == 0 {
		return errors.New("final release inventory must not be empty")
	}
	if err := validateV4ArtifactSet(artifacts, maxReleaseReviewArtifactsV4+5); err != nil {
		return err
	}
	for _, ref := range artifacts {
		if err := validatePortableStorageName(ref.Name); err != nil {
			return err
		}
		if strings.HasPrefix(ref.Name, FinalReleasePackagePrefixV4) {
			return errors.New("release inventory must use package-relative artifact names")
		}
	}
	return nil
}

// Location returns the ceremony-relative location only for an exact inventory
// member. The transport must additionally enforce its own object-key limit.
func (i FinalReleaseInventoryV4) Location(ref ArtifactRef) (string, error) {
	if i.prefix != FinalReleasePackagePrefixV4 || i.members[ref.Name] != ref {
		return "", errors.New("artifact is not in the final release package inventory")
	}
	if err := ref.Validate(); err != nil {
		return "", err
	}
	if err := validatePortableStorageName(ref.Name); err != nil {
		return "", err
	}
	if strings.HasPrefix(ref.Name, FinalReleasePackagePrefixV4) {
		return "", errors.New("release artifact name already contains the package prefix")
	}
	return i.prefix + ref.Name, nil
}

func validateFinalReleaseTransitionV4(t CheckpointTransitionV4) error {
	if t.Record == nil || t.Record.Record.Name != FinalReleasePackagePrefixV4+keybundle.ManifestFile || t.Record.Signature.Name != FinalReleasePackagePrefixV4+keybundle.ManifestSignatureFile || len(t.Evidence) != 3 {
		return errors.New("final release requires the exact manifest pair and three package bootstrap references")
	}
	names := []string{FinalReleasePackagePrefixV4 + FinalTranscriptFile, FinalReleasePackagePrefixV4 + ReleaseChecksumsFile, FinalReleasePackagePrefixV4 + keybundle.ManifestPublicKeyFile}
	slices.Sort(names)
	for j, name := range names {
		if t.Evidence[j].Name != name {
			return errors.New("final release evidence must name its transcript, checksums and public key")
		}
	}
	return nil
}

func finalReleaseArtifactLimitV4(ref ArtifactRef) int64 {
	switch ref.Name {
	case FinalReleasePackagePrefixV4 + FinalTranscriptFile:
		return maxFinalTranscriptV3Bytes
	case FinalReleasePackagePrefixV4 + ReleaseChecksumsFile:
		return maxReleaseChecksumsV4Bytes
	default:
		if strings.HasSuffix(ref.Name, ".sig") {
			return 4096
		}
		return maxSignedRecordBytes
	}
}

func requireReleaseReviewPredecessorV4(review ReleaseReviewV4, c CheckpointV4) error {
	if c.PreviousCheckpoint == nil || review.ReviewCheckpoint != *c.PreviousCheckpoint {
		return errors.New("release package was reviewed against a different checkpoint predecessor")
	}
	return nil
}

// finalReleaseDownloadArtifactsV4 derives the complete closed package set from
// the authenticated review and final transition. It reads no package member
// bytes, so a fresh client can download exactly this set before full release
// verification. The names and digests are already bound by the signed ancestry.
func finalReleaseDownloadArtifactsV4(reader *checkpointReaderV4, a checkpointAncestryV4) ([]ArtifactRef, error) {
	c := a.head
	if c.Transition.Kind != CheckpointFinalReleaseRecorded {
		return []ArtifactRef{}, nil
	}
	if err := validateFinalReleaseTransitionV4(c.Transition); err != nil {
		return nil, err
	}
	if c.Progress.ReleaseReview == nil {
		return nil, errors.New("final release lacks its authenticated review")
	}
	var transcriptRef ArtifactRef
	for _, ref := range c.Transition.Evidence {
		if ref.Name == FinalReleasePackagePrefixV4+FinalTranscriptFile {
			transcriptRef = ref
		}
	}
	if transcriptRef.Name == "" {
		return nil, errors.New("final release lacks its exact setup transcript")
	}
	record, err := reader.read(transcriptRef, maxFinalTranscriptV3Bytes, true)
	if err != nil {
		return nil, err
	}
	var transcript FinalTranscript
	if err := UnmarshalCanonical(record, &transcript); err != nil {
		return nil, err
	}
	if err := transcript.Validate(); err != nil {
		return nil, err
	}
	if transcript.Schema != FinalTranscriptSchemaV3 || transcript.CeremonyID != c.CeremonyID || transcript.ReleaseReview == nil {
		return nil, errors.New("final release setup transcript does not bind this V4 ceremony and review")
	}
	review := *transcript.ReleaseReview
	if review.OperationalBundle != *c.Progress.ReleaseReview {
		return nil, errors.New("final release setup transcript names a different operational review")
	}
	if err := requireReleaseReviewPredecessorV4(review, c); err != nil {
		return nil, err
	}
	names, err := releaseDependencyNamesV4(review.RequiredArtifacts)
	if err != nil {
		return nil, err
	}
	refs := make([]ArtifactRef, 0, len(names)+5)
	for _, ref := range review.RequiredArtifacts {
		name, err := releasePhysicalNameV4(ref.Name)
		if err != nil {
			return nil, err
		}
		ref.Name = FinalReleasePackagePrefixV4 + name
		refs = append(refs, ref)
	}
	refs = append(refs, signedArtifacts(c.Transition.Record)...)
	refs = append(refs, c.Transition.Evidence...)
	slices.SortFunc(refs, compareArtifactRefName)
	if len(refs) != len(names)+len(releaseGeneratedNamesV4()) {
		return nil, errors.New("final release package inventory is incomplete")
	}
	if err := validateV4ArtifactSet(refs, maxReleaseReviewArtifactsV4+5); err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, FinalReleasePackagePrefixV4) {
			return nil, errors.New("final release package inventory escaped its closed namespace")
		}
	}
	return refs, nil
}

// VerifyFinalReleaseCheckpointV4 authenticates the ancestry and all package
// bytes. It does not replay contribution mathematics, authorize production use,
// publish files, or establish that the supplied checkpoint is globally current.
func VerifyFinalReleaseCheckpointV4(trust TrustPaths, root string, head SignedArtifactRefs) (*VerifyReleaseResult, FinalReleaseInventoryV4, error) {
	c, err := VerifyStoredCheckpointV4(trust, root, head)
	if err != nil {
		return nil, FinalReleaseInventoryV4{}, err
	}
	return verifyFinalReleasePackageV4(trust, root, c)
}

func verifyFinalReleasePackageV4(trust TrustPaths, root string, c CheckpointV4) (*VerifyReleaseResult, FinalReleaseInventoryV4, error) {
	empty := FinalReleaseInventoryV4{}
	if c.Transition.Kind != CheckpointFinalReleaseRecorded || c.PreviousCheckpoint == nil {
		return nil, empty, errors.New("final release checkpoint with an exact predecessor is required")
	}
	if err := validateFinalReleaseTransitionV4(c.Transition); err != nil {
		return nil, empty, err
	}
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		return nil, empty, err
	}
	defer func() { _ = reader.root.Close() }()
	bootstrap := append(signedArtifacts(c.Transition.Record), c.Transition.Evidence...)
	for _, ref := range bootstrap {
		if _, err := reader.read(ref, finalReleaseArtifactLimitV4(ref), false); err != nil {
			return nil, empty, err
		}
	}
	trusted, err := LoadSignedDefinition(trust)
	if err != nil {
		return nil, empty, err
	}
	d := trusted.Definition
	dir := filepath.Join(root, filepath.FromSlash(FinalReleasePackagePrefixV4))
	result, err := VerifyReleaseV4(VerifyReleaseV4Options{Trust: trust, KeysDir: dir, TrustedPublicKeyHex: d.ReleaseSigner.Ed25519PublicKeyHex, ExpectedSignatureKeyID: d.ReleaseSigner.KeyID})
	if err != nil {
		return nil, empty, err
	}
	review := result.Transcript.ReleaseReview
	if err := requireReleaseReviewPredecessorV4(*review, c); err != nil {
		return nil, empty, err
	}
	names, err := releaseDependencyNamesV4(review.RequiredArtifacts)
	if err != nil {
		return nil, empty, err
	}
	names = append(names, releaseGeneratedNamesV4()...)
	slices.Sort(names)
	expected := make(map[string]ArtifactRef, len(names))
	for _, ref := range review.RequiredArtifacts {
		name, err := releasePhysicalNameV4(ref.Name)
		if err != nil {
			return nil, empty, err
		}
		ref.Name = name
		expected[name] = ref
	}
	for _, ref := range bootstrap {
		ref.Name = strings.TrimPrefix(ref.Name, FinalReleasePackagePrefixV4)
		expected[ref.Name] = ref
	}
	inventory := FinalReleaseInventoryV4{prefix: FinalReleasePackagePrefixV4, artifacts: make([]ArtifactRef, 0, len(names)), members: make(map[string]ArtifactRef, len(names))}
	for _, name := range names {
		ref, err := artifactRefForFile(name, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return nil, empty, err
		}
		if ref != expected[name] {
			return nil, empty, errors.New("release file changed after verification")
		}
		inventory.artifacts = append(inventory.artifacts, ref)
		inventory.members[ref.Name] = ref
		if _, err := inventory.Location(ref); err != nil {
			return nil, empty, err
		}
	}
	// Recheck committed bootstrap bytes after package verification/inventory.
	for _, ref := range bootstrap {
		if _, err := reader.read(ref, finalReleaseArtifactLimitV4(ref), false); err != nil {
			return nil, empty, err
		}
	}
	if err := verifyExactReleaseFiles(dir, names, true); err != nil {
		return nil, empty, err
	}
	if err := ValidateFinalReleaseInventoryArtifactsV4(inventory.artifacts); err != nil {
		return nil, empty, err
	}
	return result, inventory, nil
}
