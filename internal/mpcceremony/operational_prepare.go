package mpcceremony

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// Preparation discovers only bounded public JSON/signature files below an
// explicitly selected evidence root. Discovery is never signature verification.
type OperationalPreparation struct {
	Bundle  OperationalEvidenceBundle `json:"bundle"`
	Missing []string                  `json:"missing"`
}

type discoveredOperational struct {
	ref   ArtifactRef
	value any
}

func PrepareOperationalEvidence(definition CeremonyDefinition, root, assembledAt string) (OperationalPreparation, error) {
	result := OperationalPreparation{Bundle: OperationalEvidenceBundle{
		Schema: OperationalEvidenceBundleSchema, CeremonyID: definition.CeremonyID,
		CoordinatorID: definition.Coordinator.ID, CoordinatorKeyID: definition.Coordinator.KeyID,
		AssembledAt: assembledAt, Enrollments: []SignedArtifactRefs{}, GovernanceRecords: []SignedArtifactRefs{},
	}, Missing: []string{}}
	if err := definition.Validate(); err != nil {
		return result, err
	}
	if err := validateTimestamp("assembled_at", assembledAt); err != nil {
		return result, err
	}
	var records []discoveredOperational
	signatures := map[string][]ArtifactRef{}
	seen := map[string]bool{}
	count, total := 0, int64(0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 20000 {
			return errors.New("public evidence tree exceeds 20000 entries")
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("public evidence path is a symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".sig") {
			return nil
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		resolved, err := resolveArtifactPath(root, name)
		if err != nil {
			return err
		}
		raw, err := readRegularBounded(resolved, 16<<20)
		if err != nil {
			return err
		}
		total += int64(len(raw))
		if total > 64<<20 {
			return errors.New("public JSON inventory exceeds 64 MiB")
		}
		var header struct{ Schema, CeremonyID string }
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil
		}
		_ = json.Unmarshal(fields["schema"], &header.Schema)
		_ = json.Unmarshal(fields["ceremony_id"], &header.CeremonyID)
		ref := ArtifactRef{Name: name, Digest: NewDigest(raw)}
		if header.Schema == DetachedSignatureSchema {
			var signature DetachedSignature
			if err := UnmarshalCanonical(raw, &signature); err != nil {
				return fmt.Errorf("signature %s: %w", name, err)
			}
			if err := signature.Validate(); err != nil {
				return err
			}
			key := "signature/" + ref.Digest.SHA256
			if !seen[key] {
				signatures[signature.SignedSHA256] = append(signatures[signature.SignedSHA256], ref)
				seen[key] = true
			}
			return nil
		}
		if header.CeremonyID != definition.CeremonyID {
			return nil
		}
		var value any
		switch header.Schema {
		case EnrollmentRecordSchema:
			value = &EnrollmentRecord{}
		case TransferHandoffSchema:
			value = &TransferHandoff{}
		case TransferReceiptSchema:
			value = &TransferReceipt{}
		case PublicWitnessReceiptSchema:
			value = &PublicWitnessReceipt{}
		case ImmutableMirrorReceiptSchema:
			value = &ImmutableMirrorReceipt{}
		case MultiRelayBeaconEvidenceSchema:
			value = &MultiRelayBeaconEvidence{}
		case GovernanceRecordSchema:
			value = &GovernanceRecord{}
		case ChainSchema:
			value = &Chain{}
		case CloseRecordSchema:
			value = &CloseRecord{}
		default:
			return nil
		}
		if err := UnmarshalCanonical(raw, value); err != nil {
			return fmt.Errorf("public record %s: %w", name, err)
		}
		if !seen[ref.Digest.SHA256] {
			records = append(records, discoveredOperational{ref, value})
			seen[ref.Digest.SHA256] = true
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	pair := func(record discoveredOperational, label string) SignedArtifactRefs {
		found := signatures[record.ref.Digest.SHA256]
		if len(found) != 1 {
			result.Missing = append(result.Missing, fmt.Sprintf("%s: need exactly one matching signature (found %d)", label, len(found)))
			return SignedArtifactRefs{Record: record.ref}
		}
		return SignedArtifactRefs{Record: record.ref, Signature: found[0]}
	}
	all := func(label string, match func(any) bool) []SignedArtifactRefs {
		found := []SignedArtifactRefs{}
		for _, record := range records {
			if match(record.value) {
				found = append(found, pair(record, label))
			}
		}
		slices.SortFunc(found, func(a, b SignedArtifactRefs) int { return strings.Compare(a.Record.Name, b.Record.Name) })
		return found
	}
	pick := func(label string, match func(any) bool) (SignedArtifactRefs, any) {
		var found []discoveredOperational
		for _, record := range records {
			if match(record.value) {
				found = append(found, record)
			}
		}
		if len(found) != 1 {
			result.Missing = append(result.Missing, fmt.Sprintf("%s: need exactly one record (found %d); collect missing evidence or investigate conflicts", label, len(found)))
			return SignedArtifactRefs{}, nil
		}
		return pair(found[0], label), found[0].value
	}
	result.Bundle.Enrollments = all("enrollment", func(v any) bool { _, ok := v.(*EnrollmentRecord); return ok })
	result.Bundle.GovernanceRecords = all("governance", func(v any) bool { _, ok := v.(*GovernanceRecord); return ok })
	// Protocol-enforced roster completeness is checked again by the verifier.
	for _, id := range append([]Identity{definition.Coordinator, definition.ReleaseSigner}, preparationRoster(definition)...) {
		count := 0
		for _, record := range records {
			if e, ok := record.value.(*EnrollmentRecord); ok && e.Identity.ID == id.ID {
				count++
			}
		}
		if count != 1 {
			result.Missing = append(result.Missing, "Collect one signed enrollment from "+id.ID)
		}
	}
	for _, phase := range []Phase{Phase1, Phase2} {
		p := PhaseOperationalEvidence{Phase: phase, PublicWitnessQuorum: 2, AcceptedHeads: []AcceptedHeadOperationalEvidence{}, RawBeaconResponses: []ArtifactRef{}}
		label := string(phase)
		closePair, closeAny := pick(label+" closure", func(v any) bool { c, ok := v.(*CloseRecord); return ok && c.Phase == phase })
		p.Close = closePair
		if closeAny == nil {
			continue
		}
		close := closeAny.(*CloseRecord)
		chainPair, chainAny := pick(label+" final accepted chain", func(v any) bool {
			c, ok := v.(*Chain)
			return ok && c.Phase == phase && len(c.Records) > 0 && c.Records[len(c.Records)-1].RecordID == close.ChainHeadID
		})
		p.AcceptedChain = chainPair
		p.PublicWitnessReceipts = all(label+" witness", func(v any) bool {
			w, ok := v.(*PublicWitnessReceipt)
			return ok && w.Phase == phase && w.CloseID == close.CloseID
		})
		if len(p.PublicWitnessReceipts) < 2 {
			result.Missing = append(result.Missing, label+": collect signed observations from at least two witnesses; expired windows cannot be recreated")
		}
		p.MultiRelayBeaconEvidence, closeAny = pick(label+" two-operator beacon evidence", func(v any) bool {
			b, ok := v.(*MultiRelayBeaconEvidence)
			return ok && b.Phase == phase && b.CloseID == close.CloseID
		})
		if closeAny != nil {
			for _, o := range closeAny.(*MultiRelayBeaconEvidence).Observations {
				p.RawBeaconResponses = append(p.RawBeaconResponses, o.RawResponse)
			}
			slices.SortFunc(p.RawBeaconResponses, func(a, b ArtifactRef) int { return strings.Compare(a.Name, b.Name) })
		}
		if chainAny != nil {
			for _, head := range chainAny.(*Chain).Records {
				h := AcceptedHeadOperationalEvidence{Index: head.Index, PredecessorHeadID: head.PreviousRecordID, AcceptedHeadID: head.RecordID}
				scope := fmt.Sprintf("%s turn %d (%s)", phase, head.Index, head.ParticipantID)
				h.AcceptedChainPrefix, _ = pick(scope+" accepted chain prefix", func(v any) bool {
					c, ok := v.(*Chain)
					return ok && c.Phase == phase && len(c.Records) == int(head.Index) && c.Records[len(c.Records)-1].RecordID == head.RecordID
				})
				for _, outbound := range []bool{true, false} {
					direction := "return"
					sender := head.ParticipantID
					if outbound {
						direction = "outbound"
						sender = definition.Coordinator.ID
					}
					handoff, _ := pick(scope+" "+direction+" handoff (sender-signed)", func(v any) bool {
						r, ok := v.(*TransferHandoff)
						return ok && r.Phase == phase && r.Index == head.Index && r.PredecessorHeadID == head.PreviousRecordID && r.SenderID == sender
					})
					receipt, _ := pick(scope+" "+direction+" receipt (receiver-signed)", func(v any) bool {
						r, ok := v.(*TransferReceipt)
						return ok && r.HandoffSHA256 == handoff.Record.Digest.SHA256
					})
					if outbound {
						h.OutboundHandoff, h.OutboundReceipt = handoff, receipt
					} else {
						h.ReturnHandoff, h.ReturnReceipt = handoff, receipt
					}
				}
				h.MirrorReceipts = all(scope+" mirror receipt", func(v any) bool {
					r, ok := v.(*ImmutableMirrorReceipt)
					return ok && r.Phase == phase && r.Index == head.Index && r.AcceptedHeadID == head.RecordID
				})
				// Byte-identical chain files can exist under several public names.
				// Preserve the exact names the mirrors actually signed, not an
				// arbitrary discovery alias. Full verification checks all mirrors.
				for _, discovered := range records {
					mirror, ok := discovered.value.(*ImmutableMirrorReceipt)
					if !ok || mirror.Phase != phase || mirror.Index != head.Index || mirror.AcceptedHeadID != head.RecordID {
						continue
					}
					for _, ref := range mirror.Files {
						if ref.Digest == h.AcceptedChainPrefix.Record.Digest {
							h.AcceptedChainPrefix.Record = ref
						}
						if ref.Digest == h.AcceptedChainPrefix.Signature.Digest {
							h.AcceptedChainPrefix.Signature = ref
						}
					}
					break
				}
				if len(h.MirrorReceipts) < 2 {
					result.Missing = append(result.Missing, scope+": collect at least two signed mirror receipts for this exact head")
				}
				p.AcceptedHeads = append(p.AcceptedHeads, h)
			}
		}
		if phase == Phase1 {
			result.Bundle.Phase1 = p
		} else {
			result.Bundle.Phase2 = p
		}
	}
	return result, nil
}

func preparationRoster(d CeremonyDefinition) []Identity {
	ids := append([]Identity{}, d.Auditors...)
	for _, p := range d.Roster {
		ids = append(ids, p.Identity)
	}
	return ids
}
