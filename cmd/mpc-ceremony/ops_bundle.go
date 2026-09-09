package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proof-tool/internal/mpcceremony"
)

type OpsPrepareBundleOptions struct {
	CeremonyPath, CeremonySignaturePath, CoordinatorPublicKeyFile string
	EvidenceRoot, OutDir                                          string
	WitnessQuorum                                                 uint
}

func parseOpsPrepareBundle(args []string) (OpsPrepareBundleOptions, error) {
	var o OpsPrepareBundleOptions
	f := commandFlagSet("ops prepare-bundle")
	addCeremonyTrustFlags(f, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	f.StringVar(&o.EvidenceRoot, "evidence-root", "", "public-only evidence directory; never a keys or credentials directory")
	f.StringVar(&o.OutDir, "out-dir", "", "evidence-root/operational; existing evidence is preserved, bundle outputs must be fresh")
	f.UintVar(&o.WitnessQuorum, "witness-quorum", 2, "agreed minimum public witnesses per phase (2-32)")
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	if o.WitnessQuorum < 2 || o.WitnessQuorum > 32 {
		return o, errors.New("witness quorum must be between 2 and 32")
	}
	return o, requireValues(pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--evidence-root", o.EvidenceRoot), pathValue("--out-dir", o.OutDir))
}

func executeOpsPrepareBundle(o OpsPrepareBundleOptions) (CommandResult, error) {
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: o.CeremonyPath, DefinitionSignaturePath: o.CeremonySignaturePath, CoordinatorPublicKeyPath: o.CoordinatorPublicKeyFile})
	if err != nil {
		return CommandResult{}, err
	}
	if o.WitnessQuorum < 2 || o.WitnessQuorum > 32 {
		return CommandResult{}, errors.New("witness quorum must be between 2 and 32")
	}
	prepared, err := mpcceremony.PrepareOperationalEvidence(trusted.Definition, o.EvidenceRoot, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return CommandResult{}, err
	}
	for index, phase := range []*mpcceremony.PhaseOperationalEvidence{&prepared.Bundle.Phase1, &prepared.Bundle.Phase2} {
		phase.PublicWitnessQuorum = uint8(o.WitnessQuorum)
		if o.WitnessQuorum > 2 && len(phase.PublicWitnessReceipts) < int(o.WitnessQuorum) {
			prepared.Missing = append(prepared.Missing, fmt.Sprintf("phase%d: agreed witness quorum is %d, found %d records", index+1, o.WitnessQuorum, len(phase.PublicWitnessReceipts)))
		}
	}
	if len(prepared.Missing) > 0 {
		return CommandResult{}, fmt.Errorf("evidence preparation incomplete (discovery is not verification):\n- %s\nCollect the original public records and signatures from their owners, retaining referenced relative paths, then retry. Do not invent or backdate evidence", strings.Join(prepared.Missing, "\n- "))
	}
	raw, err := mpcceremony.MarshalCanonical(prepared.Bundle)
	if err != nil {
		return CommandResult{}, err
	}
	if err := verifyBundleDraft(trusted, o.EvidenceRoot, raw, prepared.Bundle); err != nil {
		return CommandResult{}, fmt.Errorf("evidence found but verification failed; no bundle was exported: %w", err)
	}
	request, err := mpcceremony.NewOperationalSigningRequest(mpcceremony.RecordEvidenceBundle, raw)
	if err != nil {
		return CommandResult{}, err
	}
	requestBytes, err := mpcceremony.MarshalCanonical(request)
	if err != nil {
		return CommandResult{}, err
	}
	canonical, path, err := writeEvidenceBundleExport(o.EvidenceRoot, o.OutDir, raw, requestBytes)
	if err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: trusted.Definition.CeremonyID, Summary: "assembled and verified the referenced operational evidence; the exported bundle is UNSIGNED and cannot authorize release", Outputs: map[string]string{"canonical": canonical, "signing_request": path}}, nil
}

// Only this export may reuse an evidence directory. Other signing exports keep
// their fresh-directory contract. Root-relative operations prevent path escape.
func writeEvidenceBundleExport(evidenceRoot, outDir string, canonical, request []byte) (bundlePath, requestPath string, err error) {
	rootAbs, err := filepath.Abs(evidenceRoot)
	if err != nil {
		return "", "", err
	}
	outAbs, err := filepath.Abs(outDir)
	if err != nil || outAbs != filepath.Join(rootAbs, "operational") {
		return "", "", errors.New("bundle output must be evidence-root/operational, as required by release verification")
	}
	if len(canonical) == 0 || len(request) == 0 {
		return "", "", errors.New("refuse empty bundle export")
	}
	root, err := os.OpenRoot(rootAbs)
	if err != nil {
		return "", "", err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := root.Mkdir("operational", 0700); err != nil && !os.IsExist(err) {
		return "", "", err
	}
	info, err := root.Lstat("operational")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("operational output must be a real directory, not a symlink")
	}
	dir, err := root.OpenRoot("operational")
	if err != nil {
		return "", "", err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for _, name := range []string{"evidence-bundle.json", "evidence-bundle.sig", "signing-request.json"} {
		if _, err := dir.Lstat(name); !os.IsNotExist(err) {
			return "", "", fmt.Errorf("bundle output %s already exists or cannot be inspected; preserve and inspect it before retrying", name)
		}
	}
	// Reserve the request first with O_EXCL; concurrent preparations cannot both
	// proceed. On interruption retain partial outputs for explicit inspection.
	for _, output := range []struct {
		name string
		data []byte
	}{{"signing-request.json", request}, {"evidence-bundle.json", canonical}} {
		file, err := dir.OpenFile(output.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", "", err
		}
		_, writeErr := file.Write(output.data)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return "", "", fmt.Errorf("partial bundle export retained; inspect before retry: %w", err)
		}
	}
	directory, err := dir.Open(".")
	if err != nil {
		return "", "", err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return "", "", err
	}
	return filepath.Join(outDir, "evidence-bundle.json"), filepath.Join(outDir, "signing-request.json"), nil
}

func verifyBundleDraft(trusted *mpcceremony.TrustedCeremony, root string, raw []byte, bundle mpcceremony.OperationalEvidenceBundle) error {
	if root == "" {
		return errors.New("bundle preparation/signing requires --evidence-root")
	}
	p1, err := mpcceremony.LoadAuthenticatedCloseEvidence(root, bundle.Phase1.Close)
	if err != nil {
		return err
	}
	p2, err := mpcceremony.LoadAuthenticatedCloseEvidence(root, bundle.Phase2.Close)
	if err != nil {
		return err
	}
	return mpcceremony.VerifyOperationalEvidenceDraft(mpcceremony.VerifyOperationalEvidenceOptions{Definition: trusted.Definition, CoordinatorPublicKey: trusted.CoordinatorPublicKey, EvidenceRoot: root, BundleBytes: raw, Phase1Close: p1, Phase2Close: p2})
}
