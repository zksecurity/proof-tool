package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

type OpsPrepareEnrollmentOptions struct {
	CeremonyPath, CeremonySignaturePath, CoordinatorPublicKeyFile string
	IdentityPath, Role, DisclosurePath, EnrolledAt, OutDir        string
	RoleIndex                                                     uint
}
type OpsSignOptions struct {
	OpsExportSigningOptions
	SigningKey, OutPath string
	ReviewedSHA256      string
	Reviewed            bool
}

func parseOpsPrepareEnrollment(args []string) (OpsPrepareEnrollmentOptions, error) {
	var o OpsPrepareEnrollmentOptions
	f := commandFlagSet("ops prepare-enrollment")
	addCeremonyTrustFlags(f, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	f.StringVar(&o.IdentityPath, "identity", "", "owner's public identity JSON")
	f.StringVar(&o.Role, "role", "", "enrollment role")
	f.UintVar(&o.RoleIndex, "role-index", 1, "coordinator-assigned one-based index for external witnesses/mirrors")
	f.StringVar(&o.DisclosurePath, "disclosure", "", "owner-authored public independence disclosure text file")
	f.StringVar(&o.EnrolledAt, "enrolled-at", "", "actual enrollment timestamp")
	f.StringVar(&o.OutDir, "out-dir", "", "fresh public enrollment directory")
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	if o.RoleIndex < 1 || o.RoleIndex > 65535 {
		return o, errors.New("role index must be between 1 and 65535")
	}
	return o, requireValues(pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--identity", o.IdentityPath), value("--role", o.Role), pathValue("--disclosure", o.DisclosurePath), value("--enrolled-at", o.EnrolledAt), pathValue("--out-dir", o.OutDir))
}
func parseOpsSign(args []string) (OpsSignOptions, error) {
	var o OpsSignOptions
	f := commandFlagSet("ops sign")
	addOpsRecordFlags(f, &o.RecordType, &o.RecordPath)
	addCeremonyTrustFlags(f, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	f.StringVar(&o.SigningKey, "signing-key", "", "owner's existing private key file")
	f.StringVar(&o.OutPath, "out", "", "fresh detached signature JSON")
	f.BoolVar(&o.Reviewed, "reviewed", false, "owner reviewed exact record and confirms its claims")
	f.StringVar(&o.ReviewedSHA256, "reviewed-sha256", "", "optional SHA-256 of the exact bytes shown during interactive review")
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	return o, requireValues(value("--record-type", o.RecordType), pathValue("--record", o.RecordPath), pathValue("--ceremony", o.CeremonyPath), pathValue("--ceremony-signature", o.CeremonySignaturePath), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), pathValue("--signing-key", o.SigningKey), pathValue("--out", o.OutPath))
}
func executeOpsPrepareEnrollment(o OpsPrepareEnrollmentOptions) (CommandResult, error) {
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: o.CeremonyPath, DefinitionSignaturePath: o.CeremonySignaturePath, CoordinatorPublicKeyPath: o.CoordinatorPublicKeyFile})
	if err != nil {
		return CommandResult{}, err
	}
	raw, err := readRegularOperationalFile(o.IdentityPath, 16384)
	if err != nil {
		return CommandResult{}, err
	}
	var id mpcceremony.Identity
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&id); err != nil {
		return CommandResult{}, err
	}
	canonicalID, err := json.Marshal(id)
	if err != nil {
		return CommandResult{}, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || !bytes.Equal(compact.Bytes(), canonicalID) {
		return CommandResult{}, errors.New("use the original canonical public identity JSON")
	}
	if err := id.Validate(); err != nil {
		return CommandResult{}, err
	}
	disclosure, err := readRegularOperationalFile(o.DisclosurePath, 65536)
	if err != nil {
		return CommandResult{}, err
	}
	if !utf8.Valid(disclosure) || strings.TrimSpace(string(disclosure)) == "" {
		return CommandResult{}, errors.New("public disclosure must be nonempty UTF-8 text")
	}
	definitionBytes, err := canonicalDefinition(trusted)
	if err != nil {
		return CommandResult{}, err
	}
	ref := mpcceremony.ArtifactRef{Name: "enrollments/" + id.ID + "/disclosure.txt", Digest: mpcceremony.NewDigest(disclosure)}
	r, err := mpcceremony.PrepareEnrollment(trusted.Definition, definitionBytes, id, mpcceremony.EnrollmentRole(o.Role), uint16(o.RoleIndex), ref, o.EnrolledAt)
	if err != nil {
		return CommandResult{}, err
	}
	canonical, err := mpcceremony.MarshalCanonical(r)
	if err != nil {
		return CommandResult{}, err
	}
	request, err := mpcceremony.NewOperationalSigningRequest(mpcceremony.RecordEnrollment, canonical)
	if err != nil {
		return CommandResult{}, err
	}
	requestBytes, err := mpcceremony.MarshalCanonical(request)
	if err != nil {
		return CommandResult{}, err
	}
	path, requestPath, err := writeOperationalSigningExport(o.OutDir, canonical, requestBytes)
	if err != nil {
		return CommandResult{}, err
	}
	disclosurePath := filepath.Join(o.OutDir, filepath.FromSlash(ref.Name))
	if err := os.MkdirAll(filepath.Dir(disclosurePath), 0700); err != nil {
		return CommandResult{}, err
	}
	if err := writeFreshOperationalFile(disclosurePath, disclosure, 0600); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: trusted.Definition.CeremonyID, Summary: "prepared unsigned enrollment; owner review and signature are still required, independence is not verified", Outputs: map[string]string{"canonical": path, "signing_request": requestPath, "disclosure": disclosurePath}}, nil
}
func executeOpsSign(o OpsSignOptions) (CommandResult, error) {
	if !o.Reviewed {
		return CommandResult{}, errors.New("owner must review the exact record and explicitly supply --reviewed")
	}
	kind := mpcceremony.OperationalRecordType(o.RecordType)
	if kind != mpcceremony.RecordEnrollment && kind != mpcceremony.RecordPublicWitness && kind != mpcceremony.RecordMirrorReceipt {
		return CommandResult{}, errors.New("ops sign is restricted to enrollment, public-witness and mirror-receipt records")
	}
	canonical, record, trusted, err := loadBoundOperationalRecord(kind, o.RecordPath, o.CeremonyPath, o.CeremonySignaturePath, o.CoordinatorPublicKeyFile)
	if err != nil {
		return CommandResult{}, err
	}
	if o.ReviewedSHA256 != "" && o.ReviewedSHA256 != fmt.Sprintf("%x", sha256.Sum256(canonical)) {
		return CommandResult{}, errors.New("record changed since owner review")
	}
	definitionBytes, err := canonicalDefinition(trusted)
	if err != nil {
		return CommandResult{}, err
	}
	owner, err := mpcceremony.VerifyOperationalRecordBinding(trusted.Definition, definitionBytes, record)
	if err != nil {
		return CommandResult{}, err
	}
	if enrollment, ok := record.(*mpcceremony.EnrollmentRecord); ok {
		// The public export carries its disclosure tree. Never sign a disclosure
		// hash whose accompanying bytes are missing or have changed.
		disclosure, err := readRegularOperationalFile(filepath.Join(filepath.Dir(o.RecordPath), filepath.FromSlash(enrollment.IndependenceDisclosure.Name)), 65536)
		if err != nil {
			return CommandResult{}, err
		}
		if mpcceremony.NewDigest(disclosure) != enrollment.IndependenceDisclosure.Digest {
			return CommandResult{}, errors.New("enrollment disclosure does not match the reviewed record")
		}
	}
	if _, err := os.Lstat(o.OutPath); !errors.Is(err, os.ErrNotExist) {
		return CommandResult{}, errors.New("signature output already exists or cannot be inspected")
	}
	key, public, err := keybundle.LoadExistingPrivateKey(o.SigningKey)
	if err != nil {
		return CommandResult{}, err
	}
	if hex.EncodeToString(public) != owner.Ed25519PublicKeyHex {
		return CommandResult{}, errors.New("signing key does not belong to the record owner")
	}
	sig, err := mpcceremony.ImportOperationalSignature(canonical, owner.KeyID, public, ed25519.Sign(key, canonical))
	if err != nil {
		return CommandResult{}, err
	}
	encoded, err := mpcceremony.MarshalCanonical(sig)
	if err != nil {
		return CommandResult{}, err
	}
	if err := writeFreshOperationalFile(o.OutPath, encoded, 0600); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: trusted.Definition.CeremonyID, Summary: fmt.Sprintf("signed reviewed %s claim as %s; this authenticates the owner, not physical independence or an observation by this program", kind, owner.ID), Outputs: map[string]string{"record": o.RecordPath, "signature": o.OutPath}}, nil
}
