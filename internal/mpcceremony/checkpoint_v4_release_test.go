package mpcceremony

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"proof-tool/internal/keybundle"
)

func releaseTransitionFixtureV4() CheckpointTransitionV4 {
	pair := SignedArtifactRefs{Record: checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestFile, "manifest"), Signature: checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestSignatureFile, "signature")}
	return CheckpointTransitionV4{Kind: CheckpointFinalReleaseRecorded, Record: &pair, Evidence: checkpointArtifacts(checkpointArtifact(FinalReleasePackagePrefixV4+FinalTranscriptFile, "transcript"), checkpointArtifact(FinalReleasePackagePrefixV4+ReleaseChecksumsFile, "checksums"), checkpointArtifact(FinalReleasePackagePrefixV4+keybundle.ManifestPublicKeyFile, "public key"))}
}

func TestFinalReleaseV4DerivesClosedDownloadInventory(t *testing.T) {
	reader, head := finalReleaseDownloadFixtureV4(t)
	defer func() {
		if err := reader.root.Close(); err != nil {
			t.Errorf("close checkpoint reader: %v", err)
		}
	}()
	refs, err := finalReleaseDownloadArtifactsV4(reader, checkpointAncestryV4{head: head})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"final/release/cardano-vk.bin", "final/release/ceremony.json", "final/release/checksums.sha256",
		"final/release/manifest-public-key.hex", "final/release/manifest.json", "final/release/manifest.sig",
		"final/release/ownership.pk", "final/release/ownership.vk", "final/release/setup-transcript.json",
	}
	names := make([]string, len(refs))
	for i, ref := range refs {
		names[i] = ref.Name
		if filepath.ToSlash(ref.Name) != ref.Name {
			t.Fatalf("non-portable inventory name %q", ref.Name)
		}
	}
	if !slices.Equal(names, want) {
		t.Fatalf("inventory names = %v, want %v", names, want)
	}
}

func TestFinalReleaseV4GuidanceIncludesClosedDownloadInventory(t *testing.T) {
	reader, head := finalReleaseDownloadFixtureV4(t)
	defer func() { _ = reader.root.Close() }()
	index, err := checkpointGuidanceCommitmentsV4(reader, checkpointAncestryV4{head: head})
	if err != nil {
		t.Fatal(err)
	}
	if len(index.FinalReleaseArtifacts) != 9 {
		t.Fatalf("final release guidance inventory has %d artifacts, want 9", len(index.FinalReleaseArtifacts))
	}
}

// finalReleaseDownloadFixtureV4 models the real layout: Progress.ReleaseReview
// is the signed operational-bundle pair, while the ReleaseReviewV4 lives inside
// the signed final/release/setup-transcript.json. Keeping those two record
// types distinct prevents a final checkpoint from treating an evidence bundle
// as a release review merely because both are canonical JSON.
func finalReleaseDownloadFixtureV4(t *testing.T) (*checkpointReaderV4, CheckpointV4) {
	t.Helper()
	root := t.TempDir()
	d, candidate, review := transcriptFixtureV3(t)
	transcript, err := newFinalTranscriptV3(d, candidate, review)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCanonical(transcript)
	if err != nil {
		t.Fatal(err)
	}
	tx := releaseTransitionFixtureV4()
	for n := range tx.Evidence {
		if tx.Evidence[n].Name == FinalReleasePackagePrefixV4+FinalTranscriptFile {
			tx.Evidence[n].Digest = NewDigest(raw)
			writeFixtureFile(t, root, tx.Evidence[n].Name, raw)
		}
	}
	reader, err := openCheckpointReaderV4(root)
	if err != nil {
		t.Fatal(err)
	}
	head := CheckpointV4{CeremonyID: d.CeremonyID, PreviousCheckpoint: &review.ReviewCheckpoint, Transition: tx, Progress: CheckpointProgressV4{ReleaseReview: &review.OperationalBundle, FinalRelease: tx.Record}}
	return reader, head
}

func TestFinalReleaseV4InventoryRejectsUnboundTranscript(t *testing.T) {
	for name, change := range map[string]func(*CheckpointV4){
		"missing setup transcript": func(head *CheckpointV4) {
			filtered := head.Transition.Evidence[:0]
			for _, ref := range head.Transition.Evidence {
				if ref.Name != FinalReleasePackagePrefixV4+FinalTranscriptFile {
					filtered = append(filtered, ref)
				}
			}
			head.Transition.Evidence = filtered
		},
		"different operational bundle": func(head *CheckpointV4) {
			pair := checkpointSigned("operational/different-bundle")
			head.Progress.ReleaseReview = &pair
		},
		"different review predecessor": func(head *CheckpointV4) {
			pair := checkpointSigned("checkpoints/different-review")
			head.PreviousCheckpoint = &pair
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader, head := finalReleaseDownloadFixtureV4(t)
			defer func() { _ = reader.root.Close() }()
			change(&head)
			if _, err := finalReleaseDownloadArtifactsV4(reader, checkpointAncestryV4{head: head}); err == nil {
				t.Fatal("unbound final transcript inventory accepted")
			}
		})
	}
}

func TestFinalReleaseV4CanonicalBootstrap(t *testing.T) {
	tx := releaseTransitionFixtureV4()
	if err := tx.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CheckpointTransitionV4){
		func(x *CheckpointTransitionV4) { x.Record.Record.Name = "other/manifest.json" },
		func(x *CheckpointTransitionV4) { x.Record.Signature.Name = "other/manifest.sig" },
		func(x *CheckpointTransitionV4) { x.Evidence = x.Evidence[:2] },
		func(x *CheckpointTransitionV4) {
			x.Evidence = appendCheckpointArtifacts(x.Evidence, checkpointArtifact("final/release/extra.txt", "extra"))
		},
		func(x *CheckpointTransitionV4) { x.Evidence[0].Name = "final/release/other.json" },
	} {
		bad := releaseTransitionFixtureV4()
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("incorrect bootstrap accepted")
		}
	}
}

func TestFinalReleaseV4ExactReviewPredecessor(t *testing.T) {
	pair := checkpointSigned("checkpoints/review")
	review := ReleaseReviewV4{ReviewCheckpoint: pair}
	c := CheckpointV4{PreviousCheckpoint: &pair}
	if err := requireReleaseReviewPredecessorV4(review, c); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SignedArtifactRefs){
		func(p *SignedArtifactRefs) { p.Record.Name = "checkpoints/older.json" },
		func(p *SignedArtifactRefs) { p.Record.Digest = NewDigest([]byte("older head")) },
		func(p *SignedArtifactRefs) { p.Signature.Digest = NewDigest([]byte("another signature")) },
		func(p *SignedArtifactRefs) { p.Signature.Name = "checkpoints/another.sig" },
	} {
		wrong := pair
		change(&wrong)
		c.PreviousCheckpoint = &wrong
		if err := requireReleaseReviewPredecessorV4(review, c); err == nil {
			t.Fatal("different predecessor accepted")
		}
	}
	c.PreviousCheckpoint = nil
	if err := requireReleaseReviewPredecessorV4(review, c); err == nil {
		t.Fatal("missing predecessor accepted")
	}
}

func TestFinalReleaseV4InventoryLocations(t *testing.T) {
	r := checkpointArtifact(strings.Repeat("a", 512), "payload")
	i := FinalReleaseInventoryV4{prefix: FinalReleasePackagePrefixV4, artifacts: []ArtifactRef{r}, members: map[string]ArtifactRef{r.Name: r}}
	if got, err := i.Location(r); err != nil || got != FinalReleasePackagePrefixV4+r.Name {
		t.Fatalf("maximum name: %s %v", got, err)
	}
	wrong := r
	wrong.Digest = NewDigest([]byte("different"))
	copy := i.Artifacts()
	copy[0] = wrong
	if i.Artifacts()[0] != r {
		t.Fatal("accessor exposed mutable membership")
	}
	if _, err := i.Location(wrong); err == nil {
		t.Fatal("wrong digest accepted")
	}
	r.Name = FinalReleasePackagePrefixV4 + "manifest.json"
	i.artifacts = []ArtifactRef{r}
	i.members = map[string]ArtifactRef{r.Name: r}
	if _, err := i.Location(r); err == nil {
		t.Fatal("double prefix accepted")
	}
	i.prefix = "other/"
	if _, err := i.Location(r); err == nil {
		t.Fatal("wrong prefix accepted")
	}
	if _, err := (FinalReleaseInventoryV4{}).Location(r); err == nil {
		t.Fatal("unverified zero inventory accepted")
	}
}

func TestFinalReleaseV4ReadLimits(t *testing.T) {
	if got := finalReleaseArtifactLimitV4(checkpointArtifact(FinalReleasePackagePrefixV4+FinalTranscriptFile, "x")); got != maxFinalTranscriptV3Bytes {
		t.Fatal(got)
	}
	if got := finalReleaseArtifactLimitV4(checkpointArtifact("other/"+FinalTranscriptFile, "x")); got != maxSignedRecordBytes {
		t.Fatal("unrelated JSON limit widened")
	}
	if got := finalReleaseArtifactLimitV4(checkpointArtifact(FinalReleasePackagePrefixV4+ReleaseChecksumsFile, "x")); got != maxReleaseChecksumsV4Bytes {
		t.Fatal(got)
	}
}

func TestFinalReleaseV4SequenceCapacity(t *testing.T) {
	// Non-delivery edges consume at least a fresh signed pair. Governance
	// authoring rejects a previously committed record, too. A delivery slot
	// can be allocated once and become terminal once; counting both separately
	// overestimates combined receipt/retire-and-reallocate transitions.
	// Initial state is sequence zero. Reserve one further final release edge.
	upper := (MaxCheckpointArtifacts-5)/2 + 2*MaxDeliverySlotsV2 + 1
	if upper >= MaxCheckpointSequenceV4 {
		t.Fatalf("legal evidence/delivery bounds can exhaust release sequence capacity: %d", upper)
	}
}

// Synthetic capacity boundary; the real fixture separately checks semantic
// authoring. Extra references here stand for previously accepted evidence.
func TestFinalReleaseV4InventoryCapacity(t *testing.T) {
	_, c, _, _ := checkpointFixtureV4(t)
	c.Sequence = 1
	previous := checkpointSigned("checkpoints/previous")
	c.PreviousCheckpoint = &previous
	for _, dst := range []**SignedArtifactRefs{&c.Progress.Phase1Closure, &c.Progress.Phase1Beacon, &c.Progress.Phase1Seal, &c.Progress.Phase2Closure, &c.Progress.Phase2Beacon, &c.Progress.FinalCandidate, &c.Progress.ReleaseReview} {
		pair := checkpointSigned(fmt.Sprintf("stages/%d", len(c.AcceptedArtifacts)))
		*dst = &pair
		c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, pair.Record, pair.Signature)
	}
	p2 := checkpointSigned("phase2/chain")
	payload := checkpointArtifact("phase2/payload.bin", "payload")
	c.Progress.Phase2 = &CheckpointPhaseState{Phase: Phase2, HeadRecordID: NewDigest([]byte("p2")).SHA256, HeadPayload: payload, Chain: p2}
	c.AcceptedArtifacts = appendCheckpointArtifacts(c.AcceptedArtifacts, p2.Record, p2.Signature, payload)
	c.Transition = CheckpointTransitionV4{Kind: CheckpointReleaseReviewRecorded, Record: c.Progress.ReleaseReview, Evidence: []ArtifactRef{}}
	for len(c.AcceptedArtifacts) < MaxCheckpointArtifacts {
		c.AcceptedArtifacts = append(c.AcceptedArtifacts, checkpointArtifact(fmt.Sprintf("padding/%05d", len(c.AcceptedArtifacts)), "evidence"))
	}
	c.AcceptedArtifacts = checkpointArtifacts(c.AcceptedArtifacts...)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := cloneCheckpointV4(t, c)
	bad.AcceptedArtifacts = appendCheckpointArtifacts(bad.AcceptedArtifacts, checkpointArtifact("padding/overflow", "x"))
	if err := bad.Validate(); err == nil {
		t.Fatal("pre-release capacity widened")
	}
	tx := releaseTransitionFixtureV4()
	next := nextCheckpointV4(t, c, tx)
	next.Progress.FinalRelease = tx.Record
	if len(next.AcceptedArtifacts) != MaxCheckpointArtifacts+5 {
		t.Fatal("incorrect test inventory")
	}
	if err := ValidateCheckpointTransitionV4(c, next); err != nil {
		t.Fatal(err)
	}
	bad = cloneCheckpointV4(t, next)
	bad.AcceptedArtifacts = appendCheckpointArtifacts(bad.AcceptedArtifacts, checkpointArtifact("padding/sixth", "x"))
	if err := ValidateCheckpointTransitionV4(c, bad); err == nil {
		t.Fatal("sixth final reference accepted")
	}
}
