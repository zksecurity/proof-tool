package mpcceremony

import (
	"strings"
	"testing"
	"time"
)

func TestOperationalBundleV4RequiresUnreleasedFrozenCandidate(t *testing.T) {
	for name, progress := range map[string]CheckpointProgressV4{
		"no candidate":     {},
		"already released": {FinalCandidate: &SignedArtifactRefs{}, FinalRelease: &SignedArtifactRefs{}},
	} {
		t.Run(name, func(t *testing.T) {
			// The gate must run before attempting any artifact access.
			bundle, err := deriveOperationalBundleV4(nil, &TrustedCeremony{}, nil,
				checkpointAncestryV4{head: CheckpointV4{Progress: progress}}, time.Now().UTC())
			if err == nil || !strings.Contains(err.Error(), "frozen candidate before final release") || bundle.Schema != "" {
				t.Fatalf("invalid state produced bundle: %+v, %v", bundle, err)
			}
		})
	}
}
