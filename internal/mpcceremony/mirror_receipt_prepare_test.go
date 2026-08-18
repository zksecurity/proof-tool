package mpcceremony

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPrepareImmutableMirrorReceiptAuthenticatesDraftChainAndEnrollment(t *testing.T) {
	fixture := newOperationalBundleFixture(t)
	definitionBytes, err := MarshalCanonical(fixture.definition)
	if err != nil {
		t.Fatal(err)
	}
	head := fixture.bundle.Phase1.AcceptedHeads[0]
	chainBytes, err := verifyArtifactBytes(fixture.root, head.AcceptedChainPrefix.Record, maxSignedRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	var chain Chain
	if err := UnmarshalCanonical(chainBytes, &chain); err != nil {
		t.Fatal(err)
	}

	var enrollment EnrollmentRecord
	var enrollmentBytes, enrollmentSignatureBytes []byte
	for _, pair := range fixture.bundle.Enrollments {
		recordBytes, err := verifyArtifactBytes(fixture.root, pair.Record, maxSignedRecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		var candidate EnrollmentRecord
		if err := UnmarshalCanonical(recordBytes, &candidate); err != nil {
			t.Fatal(err)
		}
		if candidate.Role != EnrollmentMirrorOperator {
			continue
		}
		signatureBytes, err := verifyArtifactBytes(fixture.root, pair.Signature, maxSignedRecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err = VerifyEnrollmentProofOfPossession(
			fixture.definition, definitionBytes, recordBytes, signatureBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		enrollmentBytes, enrollmentSignatureBytes = recordBytes, signatureBytes
		break
	}
	if enrollment.Role != EnrollmentMirrorOperator {
		t.Fatal("fixture has no mirror enrollment")
	}

	files, err := MirrorReceiptFiles(chain.Records[0], head.AcceptedChainPrefix)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt, _ := time.Parse(time.RFC3339Nano, chain.Records[0].AcceptedAt)
	draft := MirrorReceiptDraft{
		CeremonyID:            fixture.definition.CeremonyID,
		Phase:                 Phase1,
		Index:                 1,
		AcceptedHeadID:        chain.Records[0].RecordID,
		Files:                 append([]ArtifactRef(nil), files...),
		StorageLocationSHA256: taggedSHA256([]byte("immutable://mirror-operator-01")),
		StoredAt:              acceptedAt.Add(time.Minute).Format(time.RFC3339),
	}
	// Relay intentionally has only a SHA-256 transport digest for the two
	// coordinator-signed prefix files. Preparation recomputes their full
	// ceremony digests from the exact authenticated bytes.
	for index := range draft.Files {
		if draft.Files[index].Name == head.AcceptedChainPrefix.Record.Name ||
			draft.Files[index].Name == head.AcceptedChainPrefix.Signature.Name {
			draft.Files[index].Digest.Blake2b256 = ""
		}
	}
	prettyDraft, err := json.MarshalIndent(draft, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMirrorReceiptDraft(prettyDraft)
	if err != nil {
		t.Fatal(err)
	}
	receipt, canonical, err := PrepareImmutableMirrorReceipt(
		fixture.definition, chain, head.AcceptedChainPrefix, parsed, enrollment,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Mirror != enrollment.Identity || !slices.Equal(receipt.Files, files) {
		t.Fatal("prepared receipt did not derive mirror identity and exact files")
	}
	for _, file := range receipt.Files {
		if file.Digest.Blake2b256 == "" {
			t.Fatalf("canonical receipt retained missing BLAKE2b digest for %q", file.Name)
		}
	}
	var decoded ImmutableMirrorReceipt
	if err := UnmarshalCanonical(canonical, &decoded); err != nil {
		t.Fatalf("prepared bytes are not canonical: %v", err)
	}
	if !reflect.DeepEqual(decoded, receipt) {
		t.Fatal("canonical receipt differs from prepared receipt")
	}

	tampered := parsed
	tampered.Files = append([]ArtifactRef(nil), parsed.Files...)
	tampered.Files[0].Digest = NewDigest([]byte("substituted mirror bytes"))
	if _, _, err := PrepareImmutableMirrorReceipt(
		fixture.definition, chain, head.AcceptedChainPrefix, tampered, enrollment,
	); err == nil {
		t.Fatal("draft with substituted artifact unexpectedly accepted")
	}

	if _, err := VerifyEnrollmentProofOfPossession(
		fixture.definition,
		definitionBytes,
		enrollmentBytes,
		append([]byte(nil), enrollmentSignatureBytes[:len(enrollmentSignatureBytes)-1]...),
	); err == nil {
		t.Fatal("truncated mirror enrollment signature unexpectedly accepted")
	}
}

func TestParseMirrorReceiptDraftRejectsUnknownAndDuplicateFields(t *testing.T) {
	base := `{"ceremony_id":"sha256:` + strings.Repeat("11", 32) + `","phase":"phase1","index":1,"accepted_head_id":"sha256:` + strings.Repeat("22", 32) + `","files":[{"name":"phase1/file","digest":{"sha256":"` + strings.Repeat("33", 32) + `","blake2b256":"` + strings.Repeat("44", 32) + `","size":1}}],"storage_location_sha256":"sha256:` + strings.Repeat("55", 32) + `","stored_at":"2026-08-18T00:00:00Z"}`
	if _, err := ParseMirrorReceiptDraft([]byte(strings.Replace(base, `"phase":"phase1"`, `"phase":"phase1","phase":"phase1"`, 1))); err == nil {
		t.Fatal("duplicate draft field unexpectedly accepted")
	}
	if _, err := ParseMirrorReceiptDraft([]byte(strings.TrimSuffix(base, "}") + `,"mirror":{}}`)); err == nil {
		t.Fatal("operator-supplied mirror identity unexpectedly accepted")
	}
}
