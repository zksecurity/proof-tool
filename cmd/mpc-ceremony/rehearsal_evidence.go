// Generate a real proof for the repository's tiny rehearsal circuit and public
// golden vector. No application wallet material is accepted by this helper.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/blake2b"
	"math/big"
	"os"
	"path/filepath"
	"proof-tool/internal/circuit/rehearsal"
	"proof-tool/internal/mpcceremony"
	"proof-tool/internal/prover"
)

type RehearsalEvidenceOptions struct{ KeysDir, CoordinatorPublicKeyFile, CeremonyID, OutPath string }

func parseRehearsalEvidence(args []string) (RehearsalEvidenceOptions, error) {
	var o RehearsalEvidenceOptions
	f := commandFlagSet("finalize rehearsal-evidence")
	f.StringVar(&o.KeysDir, "keys-dir", "", "authenticated preliminary final keys")
	f.StringVar(&o.CoordinatorPublicKeyFile, "coordinator-public-key-file", "", "separately trusted coordinator key")
	f.StringVar(&o.CeremonyID, "ceremony-id", "", "expected signed ceremony ID")
	f.StringVar(&o.OutPath, "out", "", "fresh public evidence file")
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	return o, requireValues(pathValue("--keys-dir", o.KeysDir), pathValue("--coordinator-public-key-file", o.CoordinatorPublicKeyFile), value("--ceremony-id", o.CeremonyID), pathValue("--out", o.OutPath))
}
func executeRehearsalEvidence(o RehearsalEvidenceOptions) (CommandResult, error) {
	if err := generateRehearsalEvidence(o); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{CeremonyID: o.CeremonyID, Summary: "Generated and verified a real tiny-circuit proof using public golden inputs; not a production ownership proof", Outputs: map[string]string{"public_evidence": o.OutPath}}, nil
}
func generateRehearsalEvidence(o RehearsalEvidenceOptions) error {
	key, err := os.ReadFile(o.CoordinatorPublicKeyFile)
	if err != nil {
		return err
	}
	pre, err := mpcceremony.VerifyPreliminaryFinalKeys(o.KeysDir, string(key))
	if err != nil {
		return err
	}
	if pre.CeremonyID != o.CeremonyID {
		return errors.New("ceremony mismatch")
	}
	if pre.Circuit.Constraints != 5 || pre.Circuit.R1CS.Digest.SHA256 != "sha256:1cbaefe7d52545efae5a9033f6fd381b667ec305da58fb84065a79438c5161ab" {
		return errors.New("only the exact pinned five-constraint rehearsal circuit is permitted")
	}
	ccs, err := mpcceremony.ReadR1CSFile(filepath.Join(o.KeysDir, pre.ConstraintSystem.Name), pre.Circuit)
	if err != nil {
		return err
	}
	credential, err := hex.DecodeString(mpcceremony.GoldenPublicCredentialHex)
	if err != nil {
		return err
	}
	destination, err := hex.DecodeString(mpcceremony.GoldenPublicDestinationHex)
	if err != nil {
		return err
	}
	preimage := append([]byte(mpcceremony.DestinationPublicDomain), credential...)
	preimage = append(preimage, destination...)
	digest := blake2b.Sum256(preimage)
	reversed := bytes.Clone(digest[:])
	for l, r := 0, len(reversed)-1; l < r; l, r = l+1, r-1 {
		reversed[l], reversed[r] = reversed[r], reversed[l]
	}
	scalar := new(big.Int).SetBytes(reversed)
	scalar.Mod(scalar, ecc.BLS12_381.ScalarField())
	// The released rehearsal circuit proves X^3 = Pub (the older workflow test
	// helper uses a different tiny circuit). This fixed public golden scalar is
	// a cubic residue. In this field r-1 = 3*q with gcd(3,q)=1, so exponentiating
	// by 3^-1 mod q gives a publicly computable satisfying rehearsal witness.
	field := ecc.BLS12_381.ScalarField()
	q := new(big.Int).Sub(field, big.NewInt(1))
	q.Div(q, big.NewInt(3))
	exponent := new(big.Int).ModInverse(big.NewInt(3), q)
	if exponent == nil {
		return errors.New("unexpected scalar-field cube subgroup")
	}
	cubeRoot := new(big.Int).Exp(scalar, exponent, field)
	if new(big.Int).Exp(cubeRoot, big.NewInt(3), field).Cmp(scalar) != 0 {
		return errors.New("public golden input is not a cubic residue")
	}
	witness, err := frontend.NewWitness(&rehearsal.Circuit{X: cubeRoot, Pub: scalar}, field)
	if err != nil {
		return err
	}
	pk, err := prover.LoadPK(filepath.Join(o.KeysDir, mpcceremony.NativeProvingKeyFile))
	if err != nil {
		return err
	}
	vk, err := prover.LoadVK(filepath.Join(o.KeysDir, mpcceremony.NativeVerifyingKeyFile))
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs.R1CS, pk, witness)
	if err != nil {
		return err
	}
	public, err := witness.Public()
	if err != nil {
		return err
	}
	if err = groth16.Verify(proof, vk, public); err != nil {
		return err
	}
	cardano, format, err := prover.SerializeCardanoProof(proof)
	if err != nil {
		return err
	}
	vkbytes, err := os.ReadFile(filepath.Join(o.KeysDir, mpcceremony.CardanoVKBytesFile))
	if err != nil {
		return err
	}
	evidence := mpcceremony.PublicFinalizationEvidence{Schema: mpcceremony.PublicEvidenceSchema, CeremonyID: o.CeremonyID, Fixture: mpcceremony.PublicEvidenceFixture, CredentialHex: hex.EncodeToString(credential), DestinationHex: hex.EncodeToString(destination), PublicInputDigestHex: hex.EncodeToString(digest[:]), CardanoProofHex: hex.EncodeToString(cardano), CardanoProofFormat: format, CardanoProofRawDigest: mpcceremony.NewDigest(cardano), CardanoVerifyingKey: mpcceremony.ArtifactRef{Name: mpcceremony.CardanoVKBytesFile, Digest: mpcceremony.NewDigest(vkbytes)}}
	if err = evidence.Validate(); err != nil {
		return err
	}
	data, err := mpcceremony.MarshalCanonical(evidence)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(o.OutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return nil
}
