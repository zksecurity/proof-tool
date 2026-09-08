// Rehearsal-only adapter for public operational records missing a CLI signing
// command. Uses the exact frozen protocol library; does not change its verifier.
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"proof-tool/internal/keybundle"
	"proof-tool/internal/mpcceremony"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	kind := flag.String("record-type", "", "operational record type")
	path := flag.String("record", "", "reviewed canonical public record")
	def := flag.String("ceremony", "", "signed definition")
	sig := flag.String("ceremony-signature", "", "definition signature")
	anchor := flag.String("coordinator-public-key-file", "", "trusted coordinator key")
	key := flag.String("signing-key", "", "this actor's private key file")
	reviewed := flag.String("reviewed-sha256", "", "reviewed exact byte digest")
	out := flag.String("out", "", "new detached signature file")
	flag.Parse()
	switch *kind {
	case "handoff", "receipt", "beacon-evidence", "evidence-bundle":
	default:
		return fmt.Errorf("unsupported rehearsal adapter record type")
	}
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: *def, DefinitionSignaturePath: *sig, CoordinatorPublicKeyPath: *anchor})
	if err != nil {
		return err
	}
	if string(trusted.Definition.Mode) != "rehearsal" {
		return fmt.Errorf("adapter only permits explicit rehearsal definitions")
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if len(data) > 16<<20 || fmt.Sprintf("%x", sha256.Sum256(data)) != *reviewed {
		return fmt.Errorf("reviewed digest mismatch")
	}
	record, err := mpcceremony.ParseOperationalRecord(mpcceremony.OperationalRecordType(*kind), data)
	if err != nil {
		return err
	}
	definitionBytes, err := mpcceremony.MarshalCanonical(trusted.Definition)
	if err != nil {
		return err
	}
	identity, err := mpcceremony.VerifyOperationalRecordBinding(trusted.Definition, definitionBytes, record)
	if err != nil {
		return err
	}
	private, public, err := keybundle.LoadExistingPrivateKey(*key)
	if err != nil {
		return err
	}
	if identity.Ed25519PublicKeyHex != fmt.Sprintf("%x", public) {
		return fmt.Errorf("private key does not belong to required signer")
	}
	canonical, signature, err := mpcceremony.SignRecord(record, identity.KeyID, private)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("record canonical bytes changed")
	}
	if err := mpcceremony.VerifySignedRecord(data, signature, record, identity.KeyID, public); err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(signature); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Println("Signed reviewed rehearsal record; exact signature verified. Physical independence is not established.")
	return nil
}
