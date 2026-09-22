package mpcceremony

import (
	"runtime"
	"testing"
)

func TestPhase2GenesisVerificationRetainsArtifactAndChainChecks(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("signed workflow fixture requires Linux executable identity")
	}
	// Run authoring APIs in the actual executable bound by the signed fixture.
	t.Setenv("MPC_WORKFLOW_CHECK_GENESIS", "1")
	_ = newDirectAcceptanceFixture(t)
}
