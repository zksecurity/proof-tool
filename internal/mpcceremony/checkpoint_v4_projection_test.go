package mpcceremony

import "testing"

func TestAcceptedProjectionRequiresExactAllocatedPosition(t *testing.T) {
	for _, phase := range []Phase{Phase1, Phase2} {
		scope := ContributionScope{Phase: phase, Index: 2}
		if err := validateAcceptedProjectionChainV4(Chain{Phase: phase, Records: make([]ChainRecord, 2)}, scope); err != nil {
			t.Fatal(err)
		}
		for _, count := range []int{0, 1, 3, 256} {
			if err := validateAcceptedProjectionChainV4(Chain{Phase: phase, Records: make([]ChainRecord, count)}, scope); err == nil {
				t.Fatalf("%s scope index 2 accepted %d records", phase, count)
			}
		}
		other := Phase1
		if phase == Phase1 {
			other = Phase2
		}
		if err := validateAcceptedProjectionChainV4(Chain{Phase: other, Records: make([]ChainRecord, 2)}, scope); err == nil {
			t.Fatal("different phase accepted")
		}
	}
	if err := validateAcceptedProjectionChainV4(Chain{Phase: "unknown", Records: make([]ChainRecord, 1)}, ContributionScope{Phase: "unknown", Index: 1}); err == nil {
		t.Fatal("unsupported phase accepted")
	}
}
