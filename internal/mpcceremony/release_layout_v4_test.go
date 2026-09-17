package mpcceremony

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseLayoutV4AliasesAndCollisions(t *testing.T) {
	for _, name := range append(candidateChecksumNames(), CandidateChecksumsFile) {
		got, err := releasePhysicalNameV4("final/candidate/" + name)
		if err != nil || got != name {
			t.Fatalf("candidate alias %s: %s %v", name, got, err)
		}
	}
	for _, name := range []string{"final/candidate/unknown", "final/candidate/nested/ownership.pk", "../outside", "final/candidate/../ownership.pk"} {
		if _, err := releasePhysicalNameV4(name); err == nil {
			t.Fatalf("bad alias accepted: %s", name)
		}
	}
	ref := func(name string) ArtifactRef { return ArtifactRef{Name: name, Digest: NewDigest([]byte("same"))} }
	for _, refs := range [][]ArtifactRef{
		{ref("final/candidate/" + NativeProvingKeyFile), ref(NativeProvingKeyFile)},
		{ref(FinalTranscriptFile)},
		{ref("files"), ref("files/child")},
		{ref(FinalTranscriptFile + "/child")},
	} {
		if _, err := releaseDependencyNamesV4(refs); err == nil {
			t.Fatal("release collision accepted")
		}
	}
}

func TestV4ReleaseTreeRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	name := "file.json"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("public bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactReleaseFiles(dir, []string{name}, true); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "outside-link")
	if err := os.Link(p, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactReleaseFiles(dir, []string{name}, true); err == nil {
		t.Fatal("external hardlink accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", p); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactReleaseFiles(dir, []string{name}, true); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestReleaseDestinationV4Disjoint(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(source, "final", "candidate")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{source, filepath.Join(source, "release"), filepath.Join(nested, "release"), base, ""} {
		if err := validateReleaseDestinationV4(source, destination); err == nil {
			t.Fatalf("overlapping destination accepted: %s", destination)
		}
	}
	if err := validateReleaseDestinationV4(source, filepath.Join(base, "release")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "source-alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateReleaseDestinationV4(source, filepath.Join(alias, "release")); err == nil {
		t.Fatal("symlink parent bypassed source separation")
	}
}
