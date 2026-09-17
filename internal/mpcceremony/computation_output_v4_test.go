package mpcceremony

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestComputationOutputV4BeforeCleanup(t *testing.T) {
	for _, phase := range []Phase{Phase1, Phase2} {
		t.Run(string(phase), func(t *testing.T) {
			f := localInventoryFixtureV4(t, phase)
			for _, name := range []string{"erasure.json", "erasure.sig"} {
				if err := os.Remove(filepath.Join(f.dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := InspectComputationOutputV4(f.trust, f.paths, f.scope, f.dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.Scope != f.scope || len(got.Files) != 3 || got.Files[0].Name != "attestation.json" || got.Files[1].Name != "attestation.sig" || got.Files[2].Name != "contribution.bin" || got.Predecessor.Record.Name == "" {
				t.Fatalf("wrong preliminary result: %+v", got)
			}
			if _, err := f.inspect(); err == nil {
				t.Fatal("three files became a cleanup-complete inventory")
			}
			// This command deliberately ignores later-stage artifacts, and never
			// makes a cleanup claim even if malformed cleanup bytes are present.
			putCheckpointTestFileV4(t, f.dir, "erasure.json", []byte("partial cleanup"))
			again, err := InspectComputationOutputV4(f.trust, f.paths, f.scope, f.dir)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("later-stage files affected preliminary inspection", err)
			}
		})
	}
}

func TestComputationOutputV4RejectsChangedFilesAndScope(t *testing.T) {
	for _, mutation := range []string{"payload", "signature", "scope", "predecessor", "software", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			f := localInventoryFixtureV4(t, Phase1)
			switch mutation {
			case "payload":
				putCheckpointTestFileV4(t, f.dir, "contribution.bin", []byte("different payload"))
			case "signature":
				putCheckpointTestFileV4(t, f.dir, "attestation.sig", []byte("bad signature"))
			case "scope":
				f.scope.Index++
			case "predecessor":
				f.scope.ParentHeadID = NewDigest([]byte("wrong parent")).SHA256
			case "software":
				a := f.a
				a.SourceCommit = strings.Repeat("e", 40)
				f.sign(t, a)
			case "symlink":
				path := filepath.Join(f.dir, "contribution.bin")
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			}
			got, err := InspectComputationOutputV4(f.trust, f.paths, f.scope, f.dir)
			if err == nil || !reflect.DeepEqual(got, ComputationOutputInspectionV4{}) {
				t.Fatal("accepted invalid output or exposed partial facts", err)
			}
		})
	}
}
