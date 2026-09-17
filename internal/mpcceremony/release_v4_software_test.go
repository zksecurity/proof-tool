package mpcceremony

import (
	"strings"
	"testing"
)

func TestReleaseV4SigningDefinitionBindsReviewAndRunningSoftware(t *testing.T) {
	d := trustedCoordinatorDefinition(t)
	if err := validateReleaseSigningDefinitionV4(d, ReleaseReviewV4{CeremonyID: "different"}); err == nil || !strings.Contains(err.Error(), "changed after release review") {
		t.Fatalf("review binding: %v", err)
	}
	// This fixture names placeholder software, not the running executable.
	if err := validateReleaseSigningDefinitionV4(d, ReleaseReviewV4{CeremonyID: d.CeremonyID}); err == nil || !strings.Contains(err.Error(), "release signing software") {
		t.Fatalf("unapproved signer executable: %v", err)
	}
}
