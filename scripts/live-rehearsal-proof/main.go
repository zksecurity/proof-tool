// Generate a real proof for the repository's tiny rehearsal circuit and public
// golden vector. No application wallet material is accepted by this helper.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	keys := flag.String("keys-dir", "", "verified preliminary directory")
	anchor := flag.String("coordinator-public-key-file", "", "trusted coordinator key")
	cid := flag.String("ceremony-id", "", "expected ceremony id")
	out := flag.String("out", "", "fresh public proof evidence")
	flag.Parse()
	key, err := os.ReadFile(*anchor)
	if err != nil {
		return err
	}
	pre, err := mpcceremony.VerifyPreliminaryFinalKeys(*keys, string(key))
	if err != nil {
		return err
	}
	if pre.CeremonyID != *cid {
		return errors.New("ceremony mismatch")
	}
	if pre.Circuit.Constraints != 5 || pre.Circuit.R1CS.Digest.SHA256 != "sha256:1cbaefe7d52545efae5a9033f6fd381b667ec305da58fb84065a79438c5161ab" {
		return errors.New("only the exact pinned five-constraint rehearsal circuit is permitted")
	}
	ccs, err := mpcceremony.ReadR1CSFile(filepath.Join(*keys, pre.ConstraintSystem.Name), pre.Circuit)
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
	pk, err := prover.LoadPK(filepath.Join(*keys, mpcceremony.NativeProvingKeyFile))
	if err != nil {
		return err
	}
	vk, err := prover.LoadVK(filepath.Join(*keys, mpcceremony.NativeVerifyingKeyFile))
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
	vkbytes, err := os.ReadFile(filepath.Join(*keys, mpcceremony.CardanoVKBytesFile))
	if err != nil {
		return err
	}
	evidence := mpcceremony.PublicFinalizationEvidence{Schema: mpcceremony.PublicEvidenceSchema, CeremonyID: *cid, Fixture: mpcceremony.PublicEvidenceFixture, CredentialHex: hex.EncodeToString(credential), DestinationHex: hex.EncodeToString(destination), PublicInputDigestHex: hex.EncodeToString(digest[:]), CardanoProofHex: hex.EncodeToString(cardano), CardanoProofFormat: format, CardanoProofRawDigest: mpcceremony.NewDigest(cardano), CardanoVerifyingKey: mpcceremony.ArtifactRef{Name: mpcceremony.CardanoVKBytesFile, Digest: mpcceremony.NewDigest(vkbytes)}}
	if err = evidence.Validate(); err != nil {
		return err
	}
	data, err := mpcceremony.MarshalCanonical(evidence)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	fmt.Println("Generated and verified real tiny-circuit proof; public evidence retained.")
	return nil
}
