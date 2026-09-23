package mpcceremony

import (
	"strings"
	"testing"
)

func TestCoordinatorCheckpointFullReplayAllowlist(t *testing.T) {
	for _, kind := range []CheckpointTransitionKind{
		CheckpointPhase1BeaconRecorded,
		CheckpointPhase2BeaconRecorded,
		CheckpointAuditRecorded,
		CheckpointFinalCandidateRecorded,
	} {
		_, err := PrepareCoordinatorRecordedCheckpointV4(RecordedCheckpointV4Options{Kind: kind}, "coordinator.key", true)
		if err == nil || !strings.Contains(err.Error(), "--full-replay is not supported for this checkpoint transition") {
			t.Fatalf("%s: expected unsupported diagnostic error, got %v", kind, err)
		}
	}
	for _, kind := range []CheckpointTransitionKind{
		CheckpointPhase1Closed,
		CheckpointPhase1Sealed,
		CheckpointPhase2Initialized,
		CheckpointPhase2Closed,
	} {
		_, err := PrepareCoordinatorRecordedCheckpointV4(RecordedCheckpointV4Options{Kind: kind}, "coordinator.key", true)
		if err == nil || strings.Contains(err.Error(), "--full-replay is not supported") {
			t.Fatalf("%s: allowlisted diagnostic stopped at flag validation: %v", kind, err)
		}
	}
}
