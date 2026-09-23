package mpcceremony

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointV4AuditCollectionPreservesQuorumAndBinding(t *testing.T) {
	d := adversarialDefinition(t)
	d.Schema = DefinitionSchemaV5
	d.ReleaseVerification = CoordinatorReplayReleaseV1
	d.AssurancePolicy = &AssurancePolicy{PassingCeremonyAudits: 2}
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	c := adversarialCandidate(t, d)
	cb, err := MarshalCanonical(c)
	if err != nil {
		t.Fatal(err)
	}
	outputs := candidateAuditOutputs(c, ArtifactRef{Name: CandidateMetadataFile, Digest: NewDigest(cb)})
	inputs := []signedAuditInput{}
	for i := 0; i < 2; i++ {
		a := adversarialSignedAudit(t, d, c, i, "2026-07-23T14:00:00Z", outputs)
		rb, err := os.ReadFile(a.RecordPath)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := os.ReadFile(a.SignaturePath)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, signedAuditInput{record: rb, signature: sb, name: filepath.Base(a.RecordPath)})
	}
	if _, _, err = verifyAuditCollection(d, c, inputs[:1], false); err != nil {
		t.Fatal(err)
	}
	if _, _, err = verifyAuditCollection(d, c, inputs[:1], true); err == nil {
		t.Fatal("partial collection passed release minimum")
	}
	if _, _, err = verifyAuditCollection(d, c, inputs, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err = verifyAuditCollection(d, c, []signedAuditInput{inputs[0], inputs[0]}, false); err == nil {
		t.Fatal("duplicate auditor accepted")
	}
	wrong := c
	wrong.FinalizedAt = "2026-07-23T13:00:01Z"
	if _, _, err = verifyAuditCollection(d, wrong, inputs, false); err == nil {
		t.Fatal("audit accepted for a different candidate")
	}
	disabled := d
	disabled.AssurancePolicy = &AssurancePolicy{}
	if _, _, err = verifyAuditCollection(disabled, c, inputs[:1], false); err == nil {
		t.Fatal("disabled audits accepted during collection")
	}
	broken := append([]signedAuditInput{}, inputs...)
	broken[0].signature = []byte("invalid")
	if _, _, err = verifyAuditCollection(d, c, broken, false); err == nil {
		t.Fatal("invalid signature accepted during collection")
	}
}
