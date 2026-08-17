package main

import (
	"encoding/hex"
	"testing"

	"proof-tool/internal/circuit/ownership"
	"proof-tool/internal/circuit/ownershipdest"
	"proof-tool/internal/mpcceremony"
)

// TestGeneratedVectorMatchesPinnedGolden pins the relationship this command
// depends on and that nothing else checked.
//
// The generator derives a credential from a hardcoded master key at a hardcoded
// path, while PublicFinalizationEvidence.Validate accepts only the credential
// pinned in mpcceremony.GoldenPublicCredentialHex. Those are two independent
// constants that must agree. They did not: the generator derived at account 3,
// role 2 while the pinned credential is account 0, role 0, so every attempt to
// finalize a ceremony failed with "public evidence does not use the exact
// repository golden public vector" — after the multi-hour replay that produces
// the keys, which is the only point at which it is reachable.
func TestGeneratedVectorMatchesPinnedGolden(t *testing.T) {
	master, err := ownership.DecodeMasterXPrvHex(goldenMasterXPrvHex)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := ownership.DeriveCredential(master, goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(credential[:]); got != mpcceremony.GoldenPublicCredentialHex {
		t.Fatalf("derived credential %s, pinned golden %s", got, mpcceremony.GoldenPublicCredentialHex)
	}

	destination, err := ownershipdest.DecodeDestinationAddressV1Hex(goldenDestinationHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(destination); got != mpcceremony.GoldenPublicDestinationHex {
		t.Fatalf("destination %s, pinned golden %s", got, mpcceremony.GoldenPublicDestinationHex)
	}
}
