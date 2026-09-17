package mpcceremony

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"proof-tool/internal/keybundle"
)

// One SHA-256, two spaces, a maximum-length logical name and a newline per
// dependency/generated file. This V4 bound does not widen legacy checksums.
const maxReleaseChecksumsV4Bytes = (maxReleaseReviewArtifactsV4 + 5) * (64 + 2 + 512 + 1)

func releasePhysicalNameV4(logical string) (string, error) {
	if err := validateArtifactName(logical); err != nil {
		return "", err
	}
	if err := validatePortableStorageName(logical); err != nil {
		return "", err
	}
	const prefix = "final/candidate/"
	if !strings.HasPrefix(logical, prefix) {
		return logical, nil
	}
	name := strings.TrimPrefix(logical, prefix)
	if !slices.Contains(append(candidateChecksumNames(), CandidateChecksumsFile), name) {
		return "", errors.New("unsupported V4 candidate alias")
	}
	return name, nil
}

func releaseGeneratedNamesV4() []string {
	return []string{FinalTranscriptFile, keybundle.ManifestFile, keybundle.ManifestSignatureFile, keybundle.ManifestPublicKeyFile, ReleaseChecksumsFile}
}

func validateReleaseDestinationV4(source, destination string) error {
	if strings.TrimSpace(source) == "" || strings.TrimSpace(destination) == "" {
		return errors.New("V4 release source and destination directories are required")
	}
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return err
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	within := func(a, b string) bool {
		rel, err := filepath.Rel(a, b)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if within(source, destination) || within(destination, source) {
		return errors.New("V4 release directory must be separate from the source tree, not inside or above it")
	}
	return nil
}

// The exact union rejects collisions even when two logical names have the same
// digest. Generated release files are not part of their own dependency set.
func releaseDependencyNamesV4(refs []ArtifactRef) ([]string, error) {
	seen := map[string]bool{}
	for _, name := range releaseGeneratedNamesV4() {
		seen[name] = true
	}
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		name, err := releasePhysicalNameV4(ref.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("V4 release path collision at %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	// A filename must not also be the parent directory of another file.
	for name := range seen {
		for parent := filepath.ToSlash(filepath.Dir(name)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			if seen[parent] {
				return nil, fmt.Errorf("V4 release file/directory collision at %q", parent)
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

// Used only inside V4 release verification, which independently checks the
// complete package tree. Legacy closed-tree checks are not relaxed.
func verifyCandidateSubsetV4(d CeremonyDefinition, definition ArtifactRef, dir string, candidate CandidateMetadata, candidateRef ArtifactRef) (CandidateMetadata, []ArtifactRef, error) {
	refs := make([]ArtifactRef, 0, len(candidateChecksumNames())+1)
	for _, name := range append(candidateChecksumNames(), CandidateChecksumsFile) {
		ref, err := artifactRefForFile(name, filepath.Join(dir, name))
		if err != nil {
			return CandidateMetadata{}, nil, err
		}
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	if !slices.Contains(refs, candidateRef) {
		return CandidateMetadata{}, nil, errors.New("V4 candidate metadata changed during verification")
	}
	again, ref, err := verifyCandidate(d, definition, dir)
	if err != nil {
		return CandidateMetadata{}, nil, err
	}
	if ref != candidateRef || !reflect.DeepEqual(again, candidate) {
		return CandidateMetadata{}, nil, errors.New("V4 candidate changed during verification")
	}
	return candidate, refs, nil
}
