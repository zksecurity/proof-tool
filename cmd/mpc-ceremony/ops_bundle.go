package main

import (
	"errors"
	"fmt"
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
	f.StringVar(&o.OutDir, "out-dir", "", "fresh unsigned bundle export directory")
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
	_, path, err := writeOperationalSigningExport(o.OutDir, raw, requestBytes)
	if err != nil {
		return CommandResult{}, err
	}
	canonical := filepath.Join(o.OutDir, "evidence-bundle.json")
	if err := writeFreshOperationalFile(canonical, raw, 0600); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: trusted.Definition.CeremonyID, Summary: "assembled and verified the referenced operational evidence; the exported bundle is UNSIGNED and cannot authorize release", Outputs: map[string]string{"canonical": canonical, "signing_request": path}}, nil
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
