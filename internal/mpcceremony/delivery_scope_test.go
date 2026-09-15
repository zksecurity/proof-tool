package mpcceremony

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func inventoryTestRef(name string, value []byte) ArtifactRef {
	return ArtifactRef{Name: name, Digest: NewDigest(value)}
}

func candidateInventoryFixture(t *testing.T) (CeremonyDefinition, CandidateInventory) {
	t.Helper()
	d := trustedCoordinatorDefinition(t)
	c := CandidateInventory{Schema: CandidateInventorySchemaV1,
		Scope: ContributionScope{CeremonyID: d.CeremonyID, Phase: Phase1, Index: 1,
			ParticipantID: d.Phase1Policy.Participants[0], ParentHeadID: NewDigest([]byte("genesis record")).SHA256}}
	for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"} {
		c.Files = append(c.Files, inventoryTestRef(name, []byte("synthetic bytes for "+name)))
	}
	return d, c
}

func TestContributionResultIDBindsCompleteScopedInventory(t *testing.T) {
	d, original := candidateInventoryFixture(t)
	if err := original.Scope.ValidateAssignment(d); err != nil {
		t.Fatal(err)
	}
	want, err := original.ID()
	if err != nil {
		t.Fatal(err)
	}
	for i := range original.Files {
		changed := original
		changed.Files = append([]ArtifactRef{}, original.Files...)
		changed.Files[i].Digest = NewDigest([]byte("changed exact bytes"))
		got, err := changed.ID()
		if err != nil || got == want {
			t.Fatalf("file %s not bound: %s %v", original.Files[i].Name, got, err)
		}
	}
	for name, change := range map[string]func(*CandidateInventory){
		"ceremony":    func(c *CandidateInventory) { c.Scope.CeremonyID = NewDigest([]byte("another ceremony")).SHA256 },
		"phase":       func(c *CandidateInventory) { c.Scope.Phase = Phase2 },
		"index":       func(c *CandidateInventory) { c.Scope.Index = 2 },
		"participant": func(c *CandidateInventory) { c.Scope.ParticipantID = "another-participant" },
		"head":        func(c *CandidateInventory) { c.Scope.ParentHeadID = NewDigest([]byte("another head")).SHA256 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			change(&changed)
			got, err := changed.ID()
			if err != nil || got == want {
				t.Fatalf("scope not bound: %s %v", got, err)
			}
		})
	}
	withReturn := original
	withReturn.Files = append(append([]ArtifactRef{}, original.Files...),
		inventoryTestRef("return-handoff.json", []byte("return record")), inventoryTestRef("return-handoff.sig", []byte("return signature")))
	if got, err := withReturn.ID(); err != nil || got == want {
		t.Fatalf("return custody not bound: %s %v", got, err)
	}
	// Delivery metadata cannot become part of the semantic identity.
	for _, attempt := range []string{strings.Repeat("1", 32), strings.Repeat("2", 32)} {
		slot := DeliverySlotV2{Scope: original.Scope, Kind: CheckpointSubmissionCandidate,
			AttemptID: attempt, Status: DeliveryAllocated}
		if err := slot.Validate(); err != nil {
			t.Fatal(err)
		}
		got, err := original.ID()
		if err != nil || got != want {
			t.Fatal("redelivery changed result identity")
		}
	}
}

func TestContributionInventoryRejectsOpenOrPathBasedSets(t *testing.T) {
	_, original := candidateInventoryFixture(t)
	for name, change := range map[string]func(*CandidateInventory){
		"missing file": func(c *CandidateInventory) { c.Files = c.Files[:4] },
		"extra file":   func(c *CandidateInventory) { c.Files = append(c.Files, inventoryTestRef("manifest.json", []byte("x"))) },
		"attempt path": func(c *CandidateInventory) { c.Files[0].Name = "attempt-1/attestation.json" },
		"duplicate":    func(c *CandidateInventory) { c.Files[1] = c.Files[0] },
		"permuted":     func(c *CandidateInventory) { c.Files[0], c.Files[1] = c.Files[1], c.Files[0] },
		"unpaired return": func(c *CandidateInventory) {
			c.Files = append(c.Files, inventoryTestRef("return-handoff.json", []byte("x")))
		},
		"signature bound":    func(c *CandidateInventory) { c.Files[1].Digest.Size = 4097 },
		"empty contribution": func(c *CandidateInventory) { c.Files[2].Digest.Size = 0 },
		"unknown schema":     func(c *CandidateInventory) { c.Schema = "future" },
		"zero turn":          func(c *CandidateInventory) { c.Scope.Index = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.Files = append([]ArtifactRef{}, original.Files...)
			change(&changed)
			if _, err := changed.ID(); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	encoded, err := MarshalCanonical(original)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	raw["attempt_id"] = json.RawMessage(`"11111111111111111111111111111111"`)
	encoded, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var parsed CandidateInventory
	if err := UnmarshalCanonical(encoded, &parsed); err == nil {
		t.Fatal("attempt-dependent inventory accepted")
	}
}

func TestDeliveryDispositionCannotConfuseRetirementAndRejection(t *testing.T) {
	_, c := candidateInventoryFixture(t)
	id, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []CheckpointSubmissionKind{CheckpointSubmissionReceipt, CheckpointSubmissionCandidate} {
		for _, status := range []DeliveryStatus{DeliveryAllocated, DeliveryRetired, DeliveryAccepted, DeliveryRejected, "unknown"} {
			for _, result := range []string{"", id} {
				slot := DeliverySlotV2{Scope: c.Scope, Kind: kind, AttemptID: strings.Repeat("1", 32), Status: status, ContributionResultID: result}
				valid := (status == DeliveryAllocated || status == DeliveryRetired) && result == "" ||
					status == DeliveryAccepted && ((kind == CheckpointSubmissionReceipt && result == "") || (kind == CheckpointSubmissionCandidate && result == id)) ||
					status == DeliveryRejected && kind == CheckpointSubmissionCandidate && result == id
				if got := slot.Validate(); (got == nil) != valid {
					t.Fatalf("kind=%s status=%s result=%q: %v", kind, status, result, got)
				}
			}
		}
	}
}

func TestDeliveryRetirementAllowsRedeliveryButRejectionPersists(t *testing.T) {
	_, c := candidateInventoryFixture(t)
	first := strings.Repeat("1", 32)
	second := strings.Repeat("2", 32)
	for _, disposition := range []DeliveryStatus{DeliveryRetired, DeliveryRejected} {
		t.Run(string(disposition), func(t *testing.T) {
			slots, err := AllocateDeliveryV2([]DeliverySlotV2{}, c.Scope, CheckpointSubmissionCandidate, first)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, second); err == nil {
				t.Fatal("parallel active allocation accepted")
			}
			var inventory *CandidateInventory
			if disposition == DeliveryRejected {
				inventory = &c
			}
			slots, err = AdvanceDeliveryV2(slots, first, disposition, inventory)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AdvanceDeliveryV2(slots, first, DeliveryAccepted, &c); err == nil {
				t.Fatal("terminal disposition rewritten")
			}
			if _, err := AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, first); err == nil {
				t.Fatal("attempt ID reused")
			}
			slots, err = AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, second)
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := AdvanceDeliveryV2(slots, second, DeliveryAccepted, &c)
			if disposition == DeliveryRejected {
				if err == nil {
					t.Fatal("rejected bytes accepted by redelivery")
				}
				corrected := c
				corrected.Files = append([]ArtifactRef{}, c.Files...)
				corrected.Files[0].Digest = NewDigest([]byte("different complete candidate"))
				accepted, err = AdvanceDeliveryV2(slots, second, DeliveryAccepted, &corrected)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AllocateDeliveryV2(accepted, c.Scope, CheckpointSubmissionCandidate, strings.Repeat("3", 32)); err == nil {
				t.Fatal("accepted submission reopened")
			}
			if slots[1].Status != DeliveryAllocated {
				t.Fatal("input history mutated")
			}
		})
	}
}

func TestDeliveryHistoryBoundsAndScope(t *testing.T) {
	_, c := candidateInventoryFixture(t)
	var err error
	slots := []DeliverySlotV2{}
	for i := 0; i < MaxDeliveryAttemptsPerSubmissionV2; i++ {
		id := fmt.Sprintf("%032x", i)
		slots, err = AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, id)
		if err != nil {
			t.Fatal(err)
		}
		slots, err = AdvanceDeliveryV2(slots, id, DeliveryRetired, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, strings.Repeat("f", 32)); err == nil {
		t.Fatal("unbounded retry accepted")
	}
	if err := ValidateDeliveryHistoryV2(nil); err == nil {
		t.Fatal("missing history accepted")
	}
	if err := ValidateDeliveryHistoryV2(make([]DeliverySlotV2, MaxDeliverySlotsV2+1)); err == nil {
		t.Fatal("unbounded history accepted")
	}
	slots = slots[:1]
	wrong := c.Scope
	wrong.ParentHeadID = NewDigest([]byte("other predecessor")).SHA256
	if _, err := AllocateDeliveryV2(slots, wrong, CheckpointSubmissionCandidate, strings.Repeat("f", 32)); err == nil {
		t.Fatal("replacement changed predecessor")
	}
	slots, err = AllocateDeliveryV2(slots, c.Scope, CheckpointSubmissionCandidate, strings.Repeat("f", 32))
	if err != nil {
		t.Fatal(err)
	}
	changed := c
	changed.Scope = wrong
	if _, err := AdvanceDeliveryV2(slots, strings.Repeat("f", 32), DeliveryRejected, &changed); err == nil {
		t.Fatal("rejection bound another scope")
	}
}

func TestGlobalDeliveryBudgetStillPermitsTerminalRetirement(t *testing.T) {
	_, c := candidateInventoryFixture(t)
	slots := make([]DeliverySlotV2, MaxDeliverySlotsV2)
	for i := range slots {
		scope := c.Scope
		scope.ParticipantID = fmt.Sprintf("participant-%d", i/MaxDeliveryAttemptsPerSubmissionV2)
		slots[i] = DeliverySlotV2{Scope: scope, Kind: CheckpointSubmissionReceipt, AttemptID: fmt.Sprintf("%032x", i), Status: DeliveryRetired}
	}
	last := len(slots) - 1
	slots[last].Status = DeliveryAllocated
	if err := ValidateDeliveryHistoryV2(slots); err != nil {
		t.Fatal(err)
	}
	done, err := AdvanceDeliveryV2(slots, slots[last].AttemptID, DeliveryRetired, nil)
	if err != nil {
		t.Fatal(err)
	}
	if done[last].Status != DeliveryRetired {
		t.Fatal("last slot cannot retire")
	}
	if _, err := AllocateDeliveryV2(done, c.Scope, CheckpointSubmissionCandidate, strings.Repeat("f", 32)); err == nil {
		t.Fatal("global budget exceeded")
	}
}
