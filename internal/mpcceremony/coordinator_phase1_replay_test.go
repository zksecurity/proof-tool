package mpcceremony

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCoordinatorPhase1CloseAndSealReplayLanes(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("signed workflow fixture requires Linux executable identity")
	}
	fixture := newDirectAcceptanceFixture(t)
	paths := fixture.phase1Chain1
	paths.ChainPath = filepath.Join(fixture.ceremonyRoot, "phase1", "chain-0002.json")
	paths.ChainSignaturePath = DefaultSignaturePath(paths.ChainPath)
	var beacon BeaconRecord
	if err := loadCoordinatorSignedRecord(fixture.trusted, filepath.Join(fixture.ceremonyRoot, "phase1/beacon/record.json"), filepath.Join(fixture.ceremonyRoot, "phase1/beacon/record.sig"), &beacon); err != nil {
		t.Fatal(err)
	}
	challenge, err := hex.DecodeString(beacon.ChallengeHex)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(fixture.ceremonyRoot, "phase1/contributions/0002/contribution.bin")
	archived, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	expectedCommons, err := os.ReadFile(filepath.Join(fixture.ceremonyRoot, "phase1/sealed/commons.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fullReplay := range []bool{false, true} {
		t.Run(fmt.Sprintf("full_replay_%t", fullReplay), func(t *testing.T) {
			var loads []int
			paths.Progress = func(phase Phase, index, total int) {
				if phase != Phase1 || total != 2 {
					t.Fatalf("unexpected progress %s %d/%d", phase, index, total)
				}
				loads = append(loads, index)
			}
			closeOptions := ClosePhaseFilesOptions{Circuit: fixture.circuit, Phase: Phase1, Transcript: paths, CoordinatorPrivateKeyPath: fixture.coordinatorKeyPath, BeaconRound: beacon.Round, FullReplay: fullReplay}
			// A completed closure retry keeps its original record and does not need
			// a live beacon or current clock, but still verifies the accepted chain.
			_, err := closePhaseFilesAuthenticated(closeOptions, fixture.trusted, func() time.Time { panic("completed closure must not sample clock") })
			if err != nil {
				t.Fatal(err)
			}
			var wantClose []int
			if fullReplay {
				wantClose = []int{1, 2}
			}
			if !reflect.DeepEqual(loads, wantClose) {
				t.Fatalf("close loads = %v, want %v", loads, wantClose)
			}
			loads = nil
			_, head, err := loadCoordinatorPhase1SealHead(fixture.trusted, fixture.circuit, paths, fullReplay)
			if err != nil {
				t.Fatal(err)
			}
			wantSeal := []int{2}
			if fullReplay {
				wantSeal = []int{1, 2}
			}
			if !reflect.DeepEqual(loads, wantSeal) {
				t.Fatalf("seal loads = %v, want %v", loads, wantSeal)
			}
			commons, err := sealReplayedPhase1Head(fixture.circuit.Binding.DomainSize, challenge, head)
			if err != nil {
				t.Fatal(err)
			}
			encoded := adversarialSerialize(t, commons)
			if !bytes.Equal(encoded, expectedCommons) {
				t.Fatal("structural and full replay seal outputs differ")
			}
			after, err := os.ReadFile(archivePath)
			if err != nil || !bytes.Equal(after, archived) {
				t.Fatalf("sealing changed archived head: %v", err)
			}
		})
	}
	paths.Progress = nil
	for _, name := range []string{"contribution.bin", "attestation.sig", "erasure.sig", "verification.json"} {
		t.Run("reject_changed_earlier_"+name, func(t *testing.T) {
			path := filepath.Join(fixture.ceremonyRoot, "phase1/contributions/0001", name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}()
			changed := bytes.Clone(original)
			changed[len(changed)/2] ^= 1
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fullReplay := range []bool{false, true} {
				if _, _, err := loadCoordinatorPhase1SealHead(fixture.trusted, fixture.circuit, paths, fullReplay); err == nil {
					t.Fatalf("seal accepted corrupted evidence with full replay %t", fullReplay)
				}
				if _, err := closePhaseFilesAuthenticated(ClosePhaseFilesOptions{Circuit: fixture.circuit, Phase: Phase1, Transcript: paths, CoordinatorPrivateKeyPath: fixture.coordinatorKeyPath, BeaconRound: beacon.Round, FullReplay: fullReplay}, fixture.trusted, func() time.Time { panic("must fail before publication") }); err == nil {
					t.Fatalf("close accepted corrupted evidence with full replay %t", fullReplay)
				}
			}
		})
	}
	t.Run("head replacement after structural verification", func(t *testing.T) {
		first, err := os.ReadFile(filepath.Join(fixture.ceremonyRoot, "phase1/contributions/0001/contribution.bin"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(archivePath, archived, 0600); err != nil {
				t.Fatal(err)
			}
		}()
		paths.Progress = func(_ Phase, _, _ int) {
			if err := os.WriteFile(archivePath, first, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := loadCoordinatorPhase1SealHead(fixture.trusted, fixture.circuit, paths, false); err == nil || !strings.Contains(err.Error(), "digest differs from signed chain") {
			t.Fatalf("head replacement error = %v", err)
		}
	})
	t.Run("empty accepted chain", func(t *testing.T) {
		empty := paths
		empty.Progress = nil
		empty.ChainPath = filepath.Join(fixture.ceremonyRoot, "phase1/chain-0000.json")
		empty.ChainSignaturePath = DefaultSignaturePath(empty.ChainPath)
		if _, _, err := loadCoordinatorPhase1SealHead(fixture.trusted, fixture.circuit, empty, false); err == nil || !strings.Contains(err.Error(), "at least one contribution") {
			t.Fatalf("empty chain error = %v", err)
		}
	})
}
