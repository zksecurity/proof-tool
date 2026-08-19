// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package mpcceremony

import (
	"fmt"
	"strings"
	"testing"
)

// TestDefinitionBoundsAuditorsToTranscriptCapacity pins the M2 gate sweep
// fix: the final transcript records audits in a list capped at MaxAuditors,
// so enrollment must reject what the transcript cannot record instead of
// letting release sign discover it after every audit has been performed.
func TestDefinitionBoundsAuditorsToTranscriptCapacity(t *testing.T) {
	definition := adversarialDefinition(t)
	definition.CeremonyID = ""
	for index := len(definition.Auditors); index < MaxAuditors+1; index++ {
		definition.Auditors = append(definition.Auditors, adversarialIdentity(
			t,
			fmt.Sprintf("auditor-%02d", index+1),
			byte(0x40+index),
		))
	}
	if _, err := FinalizeCeremonyDefinition(definition); err == nil ||
		!strings.Contains(err.Error(), "exceed maximum") {
		t.Fatalf("definition with %d auditors error = %v, want transcript-capacity rejection", MaxAuditors+1, err)
	}
	definition.Auditors = definition.Auditors[:MaxAuditors]
	if _, err := FinalizeCeremonyDefinition(definition); err != nil {
		t.Fatalf("definition with exactly %d auditors rejected: %v", MaxAuditors, err)
	}
}
