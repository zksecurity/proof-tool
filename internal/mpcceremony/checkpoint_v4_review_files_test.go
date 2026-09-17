package mpcceremony

import (
	"slices"
	"testing"
)

func TestReleaseReviewDependenciesV4Unique(t *testing.T) {
	a := ArtifactRef{Name: "a.json", Digest: NewDigest([]byte("a"))}
	b := ArtifactRef{Name: "b.json", Digest: NewDigest([]byte("b"))}
	got, err := uniqueReleaseReviewArtifactsV4([]ArtifactRef{b, a, b})
	if err != nil || !slices.Equal(got, []ArtifactRef{a, b}) {
		t.Fatalf("deterministic unique union: %v, %v", got, err)
	}
	changed := a
	changed.Digest = b.Digest
	if _, err := uniqueReleaseReviewArtifactsV4([]ArtifactRef{a, changed}); err == nil {
		t.Fatal("conflicting artifact accepted")
	}
	invalid := a
	invalid.Name = "../outside.json"
	if _, err := uniqueReleaseReviewArtifactsV4([]ArtifactRef{invalid}); err == nil {
		t.Fatal("escaping artifact accepted")
	}
}
