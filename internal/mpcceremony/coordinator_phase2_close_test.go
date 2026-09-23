package mpcceremony

import (
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestCoordinatorPhase2ClosureAcceptanceAndDiagnosticReplay(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("signed V5 workflow fixture requires Linux executable identity")
	}
	t.Setenv("MPC_WORKFLOW_CHECKPOINT_V4", "1")
	fixture := newDirectAcceptanceFixture(t)
	if fixture.trusted.Definition.Schema != DefinitionSchemaV5 {
		t.Fatalf("signed fixture definition schema = %s", fixture.trusted.Definition.Schema)
	}
	circuit, err := CompileForKeyVersion(fixture.trusted.Definition.Circuit.KeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCircuitBinding(circuit, fixture.trusted.Definition.Circuit); err != nil {
		t.Fatal(err)
	}
	fixture.circuit = circuit
	for _, fullReplay := range []bool{false, true} {
		var loads []int
		paths := fixture.phase2Chain1
		paths.Progress = func(phase Phase, index, total int) {
			if phase != Phase2 || total != 1 {
				t.Fatalf("unexpected replay progress %s %d/%d", phase, index, total)
			}
			loads = append(loads, index)
		}
		result, err := closePhaseFilesAuthenticated(ClosePhaseFilesOptions{
			Circuit: fixture.circuit, Phase: Phase2, Transcript: paths,
			Phase1SealPath: fixture.phase1SealPath, Phase1SealSignaturePath: fixture.phase1SealSignature,
			CoordinatorPrivateKeyPath: fixture.coordinatorKeyPath, BeaconRound: 43, FullReplay: fullReplay,
		}, fixture.trusted, func() time.Time { panic("exact closure retry must not sample the clock") })
		if err != nil {
			t.Fatalf("Phase 2 close with full replay %t: %v", fullReplay, err)
		}
		if result.Close.Phase != Phase2 {
			t.Fatal("wrong phase in exact closure retry")
		}
		var want []int
		if fullReplay {
			want = []int{1}
		}
		if !reflect.DeepEqual(loads, want) {
			t.Fatalf("Phase 2 replay loads with full replay %t = %v, want %v", fullReplay, loads, want)
		}
	}
}
