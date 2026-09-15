package main

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"proof-tool/internal/keybundle"
	m "proof-tool/internal/mpcceremony"
)

// This is a terminal fixture branch, separate from the later abort negatives.
func runFinalReleaseCheckpointV4(root, packageDir string, trust m.TrustPaths, d m.CeremonyDefinition, previous m.CheckpointV4, previousRefs m.SignedArtifactRefs, coordinator ed25519.PrivateKey) error {
	destination := filepath.Join(root, m.FinalReleasePackagePrefixV4)
	if err := filepath.WalkDir(packageDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(packageDir, path)
		if err != nil {
			return err
		}
		out := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(out, 0700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0600)
	}); err != nil {
		return err
	}
	ref := func(name string) (m.ArtifactRef, error) {
		raw, err := os.ReadFile(filepath.Join(root, name))
		return m.ArtifactRef{Name: name, Digest: m.NewDigest(raw)}, err
	}
	r, err := ref(m.FinalReleasePackagePrefixV4 + keybundle.ManifestFile)
	if err != nil {
		return err
	}
	s, err := ref(m.FinalReleasePackagePrefixV4 + keybundle.ManifestSignatureFile)
	if err != nil {
		return err
	}
	pair := m.SignedArtifactRefs{Record: r, Signature: s}
	evidence := []m.ArtifactRef{}
	for _, name := range []string{m.FinalTranscriptFile, m.ReleaseChecksumsFile, keybundle.ManifestPublicKeyFile} {
		a, err := ref(m.FinalReleasePackagePrefixV4 + name)
		if err != nil {
			return err
		}
		evidence = append(evidence, a)
	}
	slices.SortFunc(evidence, func(a, b m.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	c := previous
	c.Sequence++
	c.PreviousCheckpoint = &previousRefs
	c.Transition = m.CheckpointTransitionV4{Kind: m.CheckpointFinalReleaseRecorded, Record: &pair, Evidence: evidence}
	c.Progress.FinalRelease = &pair
	c.AcceptedArtifacts = append(append(append([]m.ArtifactRef{}, previous.AcceptedArtifacts...), r, s), evidence...)
	slices.SortFunc(c.AcceptedArtifacts, func(a, b m.ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
	prepare := m.CheckpointPreparationV4{Trust: trust, ArtifactRoot: root, Proposal: c}
	if _, err := m.PrepareCheckpointV4(prepare); err != nil {
		return fmt.Errorf("prepare final release checkpoint: %w", err)
	}
	raw, sig, err := m.SignRecord(c, d.Coordinator.KeyID, coordinator)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("checkpoints/%04d-release", c.Sequence)
	if err := os.WriteFile(filepath.Join(root, name+".json"), raw, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, name+".sig"), sig, 0600); err != nil {
		return err
	}
	head := m.SignedArtifactRefs{Record: m.ArtifactRef{Name: name + ".json", Digest: m.NewDigest(raw)}, Signature: m.ArtifactRef{Name: name + ".sig", Digest: m.NewDigest(sig)}}
	_, inventory, err := m.VerifyFinalReleaseCheckpointV4(trust, root, head)
	if err != nil {
		return fmt.Errorf("verify final release checkpoint: %w", err)
	}
	if len(inventory.Artifacts()) <= 5 {
		return fmt.Errorf("release inventory confused bootstrap with whole package")
	}
	for _, a := range inventory.Artifacts() {
		location, err := inventory.Location(a)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(root, location))
		if err != nil || m.NewDigest(data) != a.Digest {
			return fmt.Errorf("wrong release inventory location %s: %v", location, err)
		}
	}
	// The exact signed release is still rejected if its committed bytes change.
	file := filepath.Join(destination, m.NativeVerifyingKeyFile)
	original, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	changed := slices.Clone(original)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(file, changed, 0600); err != nil {
		return err
	}
	_, _, bad := m.VerifyFinalReleaseCheckpointV4(trust, root, head)
	if _, err := m.VerifyStoredCheckpointV4(trust, root, head); err != nil {
		return fmt.Errorf("structural verification incorrectly depends on package payload: %w", err)
	}
	if err := os.WriteFile(file, original, 0600); err != nil {
		return err
	}
	if bad == nil {
		return fmt.Errorf("changed recorded release accepted")
	}
	fmt.Println("V4 final release checkpoint passed: private package, exact predecessor, full typed inventory")
	return nil
}
