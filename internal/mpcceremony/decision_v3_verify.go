package mpcceremony

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type VerifyProductionDecisionEvidenceV4Options struct {
	Trust         TrustPaths
	ArtifactRoot  string
	DecisionBytes []byte
}

type VerifyProductionDecisionV4Options struct {
	VerifyProductionDecisionEvidenceV4Options
	SignatureBytes [][]byte
}

type VerifiedProductionDecisionV4 struct {
	Decision                  ProductionDecisionV3
	DecisionDigest            Digest
	VerifiedSigners           []string
	VerifiedExternalArtifacts []ArtifactRef
	ReleaseInventory          FinalReleaseInventoryV4
}

func validateProductionDecisionBindingV4(d CeremonyDefinition, decision ProductionDecisionV3) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if !d.UsesCoordinatorReplay() {
		return errors.New("decision v3 requires definition v4")
	}
	if d.Schema == DefinitionSchemaV5 {
		if decision.Schema != ProductionDecisionSchemaV4 {
			return errors.New("decision production requirements differ from signed definition")
		}
	} else if decision.Schema != ProductionDecisionSchemaV3 {
		return errors.New("historical definition requires historical decision requirements")
	}
	if d.Mode != ModeProduction {
		return errors.New("production decisions require a production-mode signed definition")
	}
	if err := decision.Validate(); err != nil {
		return err
	}
	if d.CeremonyID != decision.CeremonyID || *d.AssurancePolicy != *decision.AssurancePolicy {
		return errors.New("decision differs from signed ceremony and assurance policy")
	}
	if d.Software.SourceCommit != decision.SourceRelease.SourceCommit {
		return errors.New("decision source commit differs from ceremony")
	}
	if !equalCircuitBinding(d.Circuit, decision.K21Rehearsal.Circuit) {
		return errors.New("K21 rehearsal does not bind the exact ceremony circuit")
	}
	for _, a := range decision.Auditors {
		identity, ok := auditorByID(d, a.AuditorID)
		if !ok || identity.KeyID != a.AuditorKeyID {
			return errors.New("decision auditor is not in signed ceremony roster")
		}
	}
	for _, a := range decision.ExternalAudits {
		fingerprint := a.Auditor.PublicKeyFingerprint
		if fingerprint == d.Coordinator.PublicKeyFingerprint || fingerprint == d.ReleaseSigner.PublicKeyFingerprint {
			return errors.New("external auditor key must differ from coordinator and release signer")
		}
		for _, enrolled := range d.Auditors {
			if fingerprint == enrolled.PublicKeyFingerprint {
				return errors.New("external auditor key must differ from ceremony auditors")
			}
		}
	}
	return nil
}

// This binds reviewed report bytes, not a claim that this program contacted
// GitHub, tested infrastructure, established independence or measured erasure.
// It verifies the complete package without a circuit or replay callback.
func VerifyProductionDecisionEvidenceV4(o VerifyProductionDecisionEvidenceV4Options) (VerifiedProductionDecisionV4, error) {
	empty := VerifiedProductionDecisionV4{}
	trusted, err := LoadSignedDefinition(o.Trust)
	if err != nil {
		return empty, err
	}
	d := trusted.Definition
	var decision ProductionDecisionV3
	if len(o.DecisionBytes) > maxSignedRecordBytes {
		return empty, errors.New("decision exceeds record size limit")
	}
	if err := UnmarshalCanonical(o.DecisionBytes, &decision); err != nil {
		return empty, err
	}
	if err := validateProductionDecisionBindingV4(d, decision); err != nil {
		return empty, err
	}
	release, inventory, err := VerifyFinalReleaseCheckpointV4(o.Trust, o.ArtifactRoot, decision.Release.FinalReleaseCheckpoint)
	if err != nil {
		return empty, fmt.Errorf("final release package: %w", err)
	}
	if err := validateDecisionPackageBindingV4(d, decision, release); err != nil {
		return empty, err
	}
	packageReader, err := openCheckpointReaderV4(filepath.Join(o.ArtifactRoot, FinalReleasePackagePrefixV4))
	if err != nil {
		return empty, err
	}
	defer func() { _ = packageReader.root.Close() }()
	auditors := make([]DecisionAuditorV3, 0, len(release.Transcript.ReleaseReview.Audits))
	for _, pair := range release.Transcript.ReleaseReview.Audits {
		raw, _, err := packageReader.pair(pair)
		if err != nil {
			return empty, err
		}
		var audit AuditRecord
		if err := UnmarshalCanonical(raw, &audit); err != nil {
			return empty, err
		}
		auditors = append(auditors, DecisionAuditorV3{AuditorID: audit.AuditorID, AuditorKeyID: audit.AuditorKeyID})
	}
	slices.SortFunc(auditors, func(a, b DecisionAuditorV3) int { return strings.Compare(a.AuditorID, b.AuditorID) })
	if !slices.Equal(auditors, decision.Auditors) {
		return empty, errors.New("decision auditor list differs from exact package audits")
	}
	reader, err := openCheckpointReaderV4(o.ArtifactRoot)
	if err != nil {
		return empty, err
	}
	defer func() { _ = reader.root.Close() }()
	refs, err := verifyDecisionExternalEvidenceV3(reader, decision)
	if err != nil {
		return empty, err
	}
	return VerifiedProductionDecisionV4{Decision: decision, DecisionDigest: NewDigest(o.DecisionBytes), VerifiedSigners: []string{}, VerifiedExternalArtifacts: refs, ReleaseInventory: inventory}, nil
}

func validateDecisionPackageBindingV4(d CeremonyDefinition, decision ProductionDecisionV3, release *VerifyReleaseResult) error {
	if release == nil || release.Candidate.CandidateID != decision.Release.CandidateID {
		return errors.New("decision candidate differs from verified release package")
	}
	definitionBytes, err := MarshalCanonical(d)
	if err != nil {
		return err
	}
	if release.Candidate.CeremonyID != d.CeremonyID || release.Candidate.Definition.Digest != NewDigest(definitionBytes) || release.Transcript.CeremonyID != d.CeremonyID || release.Transcript.Definition != release.Candidate.Definition {
		return errors.New("verified release package differs from the initially authenticated ceremony definition")
	}
	at, err := time.Parse(time.RFC3339Nano, decision.DecidedAt)
	if err != nil {
		return err
	}
	released, err := time.Parse(time.RFC3339Nano, release.Transcript.FinalizedAt)
	if err != nil {
		return err
	}
	if at.Before(released) {
		return errors.New("decision predates signed release package")
	}
	return nil
}

func verifyDecisionExternalEvidenceV3(reader *checkpointReaderV4, decision ProductionDecisionV3) ([]ArtifactRef, error) {
	refs, err := decisionExternalArtifactsV3(decision)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if _, err := reader.read(ref, maxSignedRecordBytes, false); err != nil {
			return nil, err
		}
	}
	for _, a := range decision.ExternalAudits {
		report, err := reader.read(a.Report, maxSignedRecordBytes, true)
		if err != nil {
			return nil, err
		}
		raw, err := reader.read(a.Signoff, 4096, true)
		if err != nil {
			return nil, err
		}
		var signature DetachedSignature
		if err := UnmarshalCanonical(raw, &signature); err != nil {
			return nil, err
		}
		key, err := identityPublicKey(a.Auditor)
		if err != nil {
			return nil, err
		}
		if err := VerifyExact(report, signature, a.Auditor.KeyID, key); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func decisionSignerIdentityV4(d CeremonyDefinition, decision ProductionDecisionV3, role DecisionSignerRole, id string) (Identity, error) {
	switch role {
	case DecisionSignerCoordinator:
		if id == d.Coordinator.ID {
			return d.Coordinator, nil
		}
	case DecisionSignerRelease:
		if id == d.ReleaseSigner.ID {
			return d.ReleaseSigner, nil
		}
	case DecisionSignerAuditor:
		for _, a := range decision.Auditors {
			if a.AuditorID == id {
				identity, ok := auditorByID(d, id)
				if ok && identity.KeyID == a.AuditorKeyID {
					return identity, nil
				}
			}
		}
	}
	return Identity{}, errors.New("decision signature is outside the exact required signer set")
}

func requiredDecisionSignersV4(d CeremonyDefinition, decision ProductionDecisionV3) []string {
	ids := []string{string(DecisionSignerCoordinator) + "\x00" + d.Coordinator.ID, string(DecisionSignerRelease) + "\x00" + d.ReleaseSigner.ID}
	for _, a := range decision.Auditors {
		ids = append(ids, string(DecisionSignerAuditor)+"\x00"+a.AuditorID)
	}
	slices.Sort(ids)
	return ids
}

func SignProductionDecisionV4(o VerifyProductionDecisionEvidenceV4Options, role DecisionSignerRole, id string, key ed25519.PrivateKey) ([]byte, error) {
	verified, err := VerifyProductionDecisionEvidenceV4(o)
	if err != nil {
		return nil, err
	}
	trusted, err := LoadSignedDefinition(o.Trust)
	if err != nil {
		return nil, err
	}
	if err := validateProductionDecisionBindingV4(trusted.Definition, verified.Decision); err != nil {
		return nil, err
	}
	identity, err := decisionSignerIdentityV4(trusted.Definition, verified.Decision, role, id)
	if err != nil {
		return nil, err
	}
	public, err := identityPublicKey(identity)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[ed25519.SeedSize:], public) {
		return nil, errors.New("decision signing key differs from required identity")
	}
	sig, err := SignExact(o.DecisionBytes, identity.KeyID, key)
	if err != nil {
		return nil, err
	}
	return MarshalCanonical(ProductionDecisionSignature{Schema: ProductionDecisionSignatureSchema, Role: role, SignerID: id, Signature: sig})
}

func VerifyProductionDecisionV4(o VerifyProductionDecisionV4Options) (VerifiedProductionDecisionV4, error) {
	empty := VerifiedProductionDecisionV4{}
	verified, err := VerifyProductionDecisionEvidenceV4(o.VerifyProductionDecisionEvidenceV4Options)
	if err != nil {
		return empty, err
	}
	trusted, err := LoadSignedDefinition(o.Trust)
	if err != nil {
		return empty, err
	}
	if err := validateProductionDecisionBindingV4(trusted.Definition, verified.Decision); err != nil {
		return empty, err
	}
	verified.VerifiedSigners, err = verifyDecisionSignaturesV4(trusted.Definition, verified.Decision, o.DecisionBytes, o.SignatureBytes)
	if err != nil {
		return empty, err
	}
	return verified, nil
}

func verifyDecisionSignaturesV4(d CeremonyDefinition, decision ProductionDecisionV3, record []byte, signatures [][]byte) ([]string, error) {
	verified := []string{}
	seen := map[string]bool{}
	for _, raw := range signatures {
		if len(raw) > 4096 {
			return nil, errors.New("decision signature exceeds size limit")
		}
		var s ProductionDecisionSignature
		if err := UnmarshalCanonical(raw, &s); err != nil {
			return nil, err
		}
		identity, err := decisionSignerIdentityV4(d, decision, s.Role, s.SignerID)
		if err != nil {
			return nil, err
		}
		id := string(s.Role) + "\x00" + s.SignerID
		if seen[id] {
			return nil, errors.New("duplicate decision signer")
		}
		seen[id] = true
		public, err := identityPublicKey(identity)
		if err != nil {
			return nil, err
		}
		if err := VerifyExact(record, s.Signature, identity.KeyID, public); err != nil {
			return nil, err
		}
		verified = append(verified, id)
	}
	if len(seen) == 0 {
		return nil, errors.New("decision requires at least one authorized signature")
	}
	slices.Sort(verified)
	if decision.Decision == DecisionGO && !slices.Equal(verified, requiredDecisionSignersV4(d, decision)) {
		return nil, errors.New("GO requires coordinator, release signer and every package auditor")
	}
	return verified, nil
}
