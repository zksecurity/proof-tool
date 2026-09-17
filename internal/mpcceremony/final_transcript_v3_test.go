package mpcceremony

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func transcriptFixtureV3(t *testing.T) (CeremonyDefinition, CandidateMetadata, ReleaseReviewV4) {
	t.Helper()
	d := trustedCoordinatorDefinition(t)
	d.Auditors = nil
	d.AssurancePolicy = &AssurancePolicy{}
	var err error
	d, err = FinalizeCeremonyDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	c := adversarialCandidate(t, d)
	ref := func(name string) ArtifactRef { return ArtifactRef{Name: name, Digest: NewDigest([]byte(name))} }
	pair := func(name string) SignedArtifactRefs {
		return SignedArtifactRefs{Record: ref(name + ".json"), Signature: ref(name + ".sig")}
	}
	r := ReleaseReviewV4{CeremonyID: d.CeremonyID, ReviewCheckpoint: pair("checkpoints/review"), FinalCandidateCheckpoint: pair("checkpoints/candidate"), OperationalBundle: pair("operational/evidence-bundle"), Audits: []SignedArtifactRefs{}, ReplayVerification: CheckpointReplayVerificationV4{Method: CoordinatorReplayReleaseV1, ToolBinary: d.Software.ToolBinary}, ReleasedAt: "2026-07-23T16:00:00Z"}
	for _, f := range []ArtifactRef{c.ProvingKey, c.VerifyingKey, c.CardanoVerifyingKey} {
		f.Name = "final/candidate/" + f.Name
		r.CandidateArtifacts = append(r.CandidateArtifacts, f)
	}
	slices.SortFunc(r.CandidateArtifacts, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	r.RequiredArtifacts, err = uniqueReleaseReviewArtifactsV4(append(slices.Clone(r.CandidateArtifacts), c.Definition))
	if err != nil {
		t.Fatal(err)
	}
	return d, c, r
}

func TestFinalTranscriptV3VersionAndBindings(t *testing.T) {
	d, c, r := transcriptFixtureV3(t)
	tx, err := newFinalTranscriptV3(d, c, r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCanonical(tx)
	if err != nil {
		t.Fatal(err)
	}
	var decoded FinalTranscript
	if err := UnmarshalCanonical(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{FinalTranscriptSchemaV1, FinalTranscriptSchema} {
		changed := tx
		changed.Schema = schema
		if _, err := NewFinalTranscript(changed); err == nil {
			t.Fatal("old schema accepted V4 review")
		}
	}
	for name, change := range map[string]func(*FinalTranscript){
		"missing review": func(v *FinalTranscript) { v.ReleaseReview = nil },
		"time":           func(v *FinalTranscript) { v.FinalizedAt = "2026-07-23T16:01:00Z" },
		"key":            func(v *FinalTranscript) { v.ProvingKey.Digest = NewDigest([]byte("wrong")) },
		"definition":     func(v *FinalTranscript) { v.Definition.Digest = NewDigest([]byte("wrong")) },
		"audit":          func(v *FinalTranscript) { v.Audits = []ArtifactRef{c.Definition} },
	} {
		t.Run(name, func(t *testing.T) {
			v := tx
			change(&v)
			if _, err := NewFinalTranscript(v); err == nil {
				t.Fatal("inconsistent review accepted")
			}
		})
	}
	legacy := tx
	legacy.Schema = FinalTranscriptSchema
	legacy.ReleaseReview = nil
	legacy, err = NewFinalTranscript(legacy)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := MarshalCanonical(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(lb, []byte("release_review")) {
		t.Fatal("legacy bytes gained review field")
	}
	for _, suffix := range []string{`,"release_review":null}`, `,"release_review":{}}`} {
		bad := append(bytes.Clone(lb[:len(lb)-1]), []byte(suffix)...)
		if err := UnmarshalCanonical(bad, &decoded); err == nil {
			t.Fatal("legacy canonical bytes accepted new field")
		}
	}
}

func TestFinalTranscriptV3MaximumDependencySize(t *testing.T) {
	d, c, r := transcriptFixtureV3(t)
	for len(r.RequiredArtifacts) < maxReleaseReviewArtifactsV4 {
		prefix := fmt.Sprintf("z/%08d/", len(r.RequiredArtifacts))
		name := prefix + strings.Repeat("a", 250) + "/"
		name += strings.Repeat("b", 512-len(name))
		r.RequiredArtifacts = append(r.RequiredArtifacts, ArtifactRef{Name: name, Digest: NewDigest([]byte("maximum-name fixture"))})
	}
	tx, err := newFinalTranscriptV3(d, c, r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCanonical(tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxSignedRecordBytes || len(raw) > maxFinalTranscriptV3Bytes {
		t.Fatalf("maximum inventory size %d outside dedicated bound", len(raw))
	}
	p := filepath.Join(t.TempDir(), FinalTranscriptFile)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readRegularBounded(p, maxFinalTranscriptV3Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var result FinalTranscript
	if err := UnmarshalCanonical(loaded, &result); err != nil {
		t.Fatal(err)
	}
	if result.TranscriptID != tx.TranscriptID {
		t.Fatal("large transcript changed")
	}
	if _, err := readRegularBounded(p, maxSignedRecordBytes); err == nil {
		t.Fatal("ordinary JSON bound was widened")
	}
	if err := os.Truncate(p, maxFinalTranscriptV3Bytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(p, maxFinalTranscriptV3Bytes); err == nil {
		t.Fatal("oversized V3 transcript accepted")
	}
}
