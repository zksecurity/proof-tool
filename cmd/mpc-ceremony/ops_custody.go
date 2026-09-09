package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"io"
	"os"
	"path/filepath"
	"proof-tool/internal/mpcceremony"
	"time"
)

type CustodyOptions struct {
	CeremonyPath, CeremonySignaturePath, CoordinatorPublicKeyFile          string
	Root, Chain, ChainSignature, Participant, Direction, Candidate, OutDir string
	Handoff, HandoffSignature, SenderPublicKey                             string
	Receipt                                                                bool
}

func parseCustody(args []string, receipt bool) (CustodyOptions, error) {
	o := CustodyOptions{Receipt: receipt}
	f := commandFlagSet("ops prepare-custody")
	addCeremonyTrustFlags(f, &o.CeremonyPath, &o.CeremonySignaturePath, &o.CoordinatorPublicKeyFile)
	f.StringVar(&o.Root, "transcript-root", "", "public files at this station")
	f.StringVar(&o.OutDir, "out-dir", "", "fresh public signing packet")
	if receipt {
		f.StringVar(&o.Handoff, "handoff", "", "exact canonical handoff")
		f.StringVar(&o.HandoffSignature, "handoff-signature", "", "sender's detached signature")
		f.StringVar(&o.SenderPublicKey, "sender-public-key-file", "", "separately trusted sender key")
	} else {
		f.StringVar(&o.Chain, "chain", "", "authenticated current chain before this turn")
		f.StringVar(&o.ChainSignature, "chain-signature", "", "current chain signature")
		f.StringVar(&o.Participant, "participant-id", "", "next scheduled participant")
		f.StringVar(&o.Direction, "direction", "outbound", "outbound or return")
		f.StringVar(&o.Candidate, "candidate-dir", "", "completed public candidate for return handoff")
	}
	if err := parseFlags(f, args); err != nil {
		return o, err
	}
	if o.CeremonyPath == "" || o.CeremonySignaturePath == "" || o.CoordinatorPublicKeyFile == "" || o.Root == "" || o.OutDir == "" {
		return o, errors.New("ceremony trust, transcript root and fresh output directory are required")
	}
	if receipt && (o.Handoff == "" || o.HandoffSignature == "" || o.SenderPublicKey == "") {
		return o, errors.New("receipt requires the handoff, sender signature and trusted sender public key")
	}
	if !receipt && (o.Chain == "" || o.ChainSignature == "" || o.Participant == "" || (o.Direction != "outbound" && o.Direction != "return") || (o.Direction == "return" && o.Candidate == "")) {
		return o, errors.New("handoff requires the current chain, participant, and outbound or return direction; return also requires the candidate")
	}
	return o, nil
}
func executeCustody(o CustodyOptions) (CommandResult, error) {
	trusted, err := mpcceremony.LoadSignedDefinition(mpcceremony.TrustPaths{DefinitionPath: o.CeremonyPath, DefinitionSignaturePath: o.CeremonySignaturePath, CoordinatorPublicKeyPath: o.CoordinatorPublicKeyFile})
	if err != nil {
		return CommandResult{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var record any
	kind := mpcceremony.RecordHandoff
	if o.Receipt {
		if _, err := executeOpsVerify(OpsVerifyOptions{RecordType: "handoff", RecordPath: o.Handoff, SignaturePath: o.HandoffSignature, CeremonyPath: o.CeremonyPath, CeremonySignaturePath: o.CeremonySignaturePath, CoordinatorPublicKeyFile: o.CoordinatorPublicKeyFile, SignerPublicKeyFile: o.SenderPublicKey}); err != nil {
			return CommandResult{}, err
		}
		raw, err := readRegularOperationalFile(o.Handoff, maxOperationalRecordBytes)
		if err != nil {
			return CommandResult{}, err
		}
		parsed, err := mpcceremony.ParseOperationalRecord(mpcceremony.RecordHandoff, raw)
		if err != nil {
			return CommandResult{}, err
		}
		handoff := parsed.(*mpcceremony.TransferHandoff)
		for _, ref := range handoff.Files {
			if err := checkCustodyFile(o.Root, ref); err != nil {
				return CommandResult{}, err
			}
		}
		receipt, err := mpcceremony.NewTransferReceipt(*handoff, raw, mpcceremony.ReceiptReceiver, now)
		if err != nil {
			return CommandResult{}, err
		}
		record = receipt
		kind = mpcceremony.RecordReceipt
	} else {
		chain, err := mpcceremony.LoadSignedChain(trusted, mpcceremony.PhaseTranscriptPaths{RootDir: o.Root, ChainPath: o.Chain, ChainSignaturePath: o.ChainSignature})
		if err != nil {
			return CommandResult{}, err
		}
		index := len(chain.Records) + 1
		var policy mpcceremony.PhasePolicy
		if chain.Phase == mpcceremony.Phase1 {
			policy = trusted.Definition.Phase1Policy
		} else {
			policy = trusted.Definition.Phase2Policy
		}
		if index > len(policy.Participants) || policy.Participants[index-1] != o.Participant {
			return CommandResult{}, errors.New("participant is not the next signed turn")
		}
		participant, ok := trusted.Definition.ParticipantByID(o.Participant)
		if !ok {
			return CommandResult{}, errors.New("participant is not assigned")
		}
		head, err := chain.HeadRecordID()
		if err != nil {
			return CommandResult{}, err
		}
		payload, err := chain.HeadPayload()
		if err != nil {
			return CommandResult{}, err
		}
		sender, recipient := trusted.Definition.Coordinator, participant.Identity
		files := []mpcceremony.ArtifactRef{payload}
		if o.Direction == "outbound" {
			if err := checkCustodyFile(o.Root, payload); err != nil {
				return CommandResult{}, err
			}
		} else {
			sender, recipient = recipient, sender
			raw, err := readRegularOperationalFile(filepath.Join(o.Candidate, "attestation.json"), maxOperationalRecordBytes)
			if err != nil {
				return CommandResult{}, err
			}
			var att mpcceremony.ContributionAttestation
			if err := mpcceremony.UnmarshalCanonical(raw, &att); err != nil {
				return CommandResult{}, err
			}
			if att.CeremonyID != trusted.Definition.CeremonyID || att.Phase != chain.Phase || int(att.Index) != index || att.ParticipantID != o.Participant || att.PreviousAcceptanceID != head {
				return CommandResult{}, errors.New("candidate does not match this turn")
			}
			files = nil
			for _, name := range []string{"attestation.json", "attestation.sig", "contribution.bin", "erasure.json", "erasure.sig"} {
				path := filepath.Join(o.Candidate, name)
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() {
					return CommandResult{}, errors.New("return candidate must contain regular public files including cleanup acknowledgment")
				}
				digest, err := custodyDigest(path)
				if err != nil {
					return CommandResult{}, err
				}
				files = append(files, mpcceremony.ArtifactRef{Name: fmt.Sprintf("%s/contributions/%04d/%s", chain.Phase, index, name), Digest: digest})
			}
		}
		handoff, err := mpcceremony.NewTransferHandoff(trusted.Definition, chain.Phase, uint8(index), head, files, sender, recipient, now, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
		if err != nil {
			return CommandResult{}, err
		}
		record = handoff
	}
	canonical, err := mpcceremony.MarshalCanonical(record)
	if err != nil {
		return CommandResult{}, err
	}
	request, err := mpcceremony.NewOperationalSigningRequest(kind, canonical)
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
	return CommandResult{CeremonyID: trusted.Definition.CeremonyID, Summary: fmt.Sprintf("Prepared current-time %s; review and sign exact bytes before the next action. File hashes do not prove physical transfer or erasure.", kind), Outputs: map[string]string{"canonical": path, "signing_request": requestPath, "reviewed_sha256": fmt.Sprintf("%x", sha256.Sum256(canonical))}}, nil
}
func checkCustodyFile(root string, ref mpcceremony.ArtifactRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(ref.Name))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == "../" {
		return errors.New("custody file escapes public root")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("custody files cannot traverse symlinks")
		}
		if current == filepath.Clean(root) {
			break
		}
		if filepath.Dir(current) == current {
			return errors.New("invalid custody root")
		}
	}
	digest, err := custodyDigest(path)
	if err != nil {
		return err
	}
	if digest != ref.Digest {
		return errors.New("retained file differs from handoff digest")
	}
	return nil
}

func custodyDigest(path string) (mpcceremony.Digest, error) {
	f, err := os.Open(path)
	if err != nil {
		return mpcceremony.Digest{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return mpcceremony.Digest{}, errors.New("custody payload must be a regular file")
	}
	sha := sha256.New()
	blake, _ := blake2b.New256(nil)
	size, err := io.Copy(io.MultiWriter(sha, blake), f)
	return mpcceremony.Digest{SHA256: fmt.Sprintf("sha256:%x", sha.Sum(nil)), Blake2b256: fmt.Sprintf("blake2b256:%x", blake.Sum(nil)), Size: size}, err
}
