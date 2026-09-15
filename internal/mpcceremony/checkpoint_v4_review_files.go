package mpcceremony

import (
	"fmt"
	"slices"
	"strings"
)

// Checkpoint files are additional to their accepted artifact inventories.
// The small allowance covers the definition and signed operational bundle.
const maxReleaseReviewArtifactsV4 = MaxCheckpointArtifacts + 2*(MaxCheckpointSequenceV4+1) + 16

// This is a verification dependency set, not a full independent-replay archive.
// Historical contribution payloads are not read by this review and are omitted.
func releaseReviewDependenciesV4(reader *checkpointReaderV4, a checkpointAncestryV4, candidate []ArtifactRef, bundle SignedArtifactRefs, operational []ArtifactRef, audits []SignedArtifactRefs) ([]ArtifactRef, error) {
	refs := append([]ArtifactRef{}, candidate...)
	refs = append(refs, operational...)
	pairs := append([]SignedArtifactRefs{a.head.Definition, bundle}, a.checkpoints...)
	pairs = append(pairs, audits...)
	p := a.head.Progress
	pairs = append(pairs, p.Phase1.Chain, *p.Phase1Closure, *p.Phase1Beacon, *p.Phase1Seal, p.Phase2.Chain, *p.Phase2Closure, *p.Phase2Beacon)
	for _, pair := range pairs {
		refs = append(refs, pair.Record, pair.Signature)
	}
	for _, pair := range []SignedArtifactRefs{*p.Phase1Beacon, *p.Phase2Beacon} {
		raw, _, err := reader.pair(pair)
		if err != nil {
			return nil, err
		}
		var beacon BeaconRecord
		if err := UnmarshalCanonical(raw, &beacon); err != nil {
			return nil, err
		}
		refs = append(refs, beacon.RawResponse)
	}
	return uniqueReleaseReviewArtifactsV4(refs)
}

func uniqueReleaseReviewArtifactsV4(refs []ArtifactRef) ([]ArtifactRef, error) {
	refs = slices.Clone(refs)
	slices.SortFunc(refs, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	unique := refs[:0]
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return nil, err
		}
		if err := validatePortableStorageName(ref.Name); err != nil {
			return nil, err
		}
		if len(unique) > 0 && unique[len(unique)-1].Name == ref.Name {
			if unique[len(unique)-1] != ref {
				return nil, fmt.Errorf("review dependency %q has conflicting digests", ref.Name)
			}
			continue
		}
		unique = append(unique, ref)
	}
	if err := validateV4ArtifactSet(unique, maxReleaseReviewArtifactsV4); err != nil {
		return nil, err
	}
	return unique, nil
}
