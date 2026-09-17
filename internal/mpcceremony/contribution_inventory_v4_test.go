package mpcceremony

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type inventoryFixtureV4 struct {
	d     CeremonyDefinition
	trust TrustPaths
	paths PhaseTranscriptPaths
	scope ContributionScope
	dir   string
	a     ContributionAttestation
}

func localInventoryFixtureV4(t *testing.T, phase Phase) inventoryFixtureV4 {
	t.Helper()
	d, _, db, ds := checkpointFixtureV4(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	putCheckpointTestFileV4(t, root, "ceremony.json", db)
	putCheckpointTestFileV4(t, root, "ceremony.sig", ds)
	key := adversarialPrivateKey(1)
	putCheckpointTestFileV4(t, root, "coordinator.hex", []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))))
	genesis := d.Phase1Genesis
	parent := ""
	if phase == Phase2 {
		genesis = ArtifactRef{Name: "phase2/genesis.bin", Digest: NewDigest([]byte("phase2 genesis"))}
		parent = NewDigest([]byte("phase1 seal")).SHA256
	}
	phaseID, err := ComputePhaseID(d.CeremonyID, phase, genesis, parent)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewChain(d.CeremonyID, phase, phaseID, genesis)
	if err != nil {
		t.Fatal(err)
	}
	pair := putCheckpointTestPairV4(t, root, string(phase)+"/chain-0000", chain, d.Coordinator.KeyID, key)
	head, err := chain.HeadRecordID()
	if err != nil {
		t.Fatal(err)
	}
	p := d.Roster[0].Identity
	a := adversarialAttestation(t)
	a.CeremonyID, a.Phase, a.PhaseID = d.CeremonyID, phase, phaseID
	a.ParticipantID, a.ParticipantKeyID = p.ID, p.KeyID
	a.PreviousPayload, a.PreviousAcceptanceID = genesis, head
	// Deliberately not a Groth16 object: inspection verifies bytes/signatures,
	// and must never claim that it performed mathematical acceptance.
	payload := []byte("not a mathematical contribution")
	a.OutputPayload = ArtifactRef{Name: fmt.Sprintf("%s/contributions/0001/contribution.bin", phase), Digest: NewDigest(payload)}
	a.ToolBinary, a.SourceCommit = d.Software.ToolBinary, d.Software.SourceCommit
	a.ContributedAt = "2026-07-23T12:01:00Z"
	a, err = NewContributionAttestation(a)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	putCheckpointTestFileV4(t, dir, "contribution.bin", payload)
	f := inventoryFixtureV4{d: d, trust: TrustPaths{DefinitionPath: filepath.Join(root, "ceremony.json"), DefinitionSignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(root, "coordinator.hex")}, paths: PhaseTranscriptPaths{RootDir: root, ChainPath: filepath.Join(root, pair.Record.Name), ChainSignaturePath: filepath.Join(root, pair.Signature.Name)}, scope: ContributionScope{CeremonyID: d.CeremonyID, Phase: phase, Index: 1, ParticipantID: p.ID, ParentHeadID: head}, dir: dir, a: a}
	f.sign(t, a)
	return f
}

func (f inventoryFixtureV4) sign(t *testing.T, a ContributionAttestation) {
	t.Helper()
	a.AttestationID = ""
	var err error
	a, err = NewContributionAttestation(a)
	if err != nil {
		t.Fatal(err)
	}
	p := f.d.Roster[int(a.Index)-1].Identity
	key := adversarialPrivateKey(0x10 + a.Index)
	putCheckpointTestPairV4(t, f.dir, "attestation", a, p.KeyID, key)
	e := adversarialErasure(t, a, "2026-07-23T12:02:00Z")
	putCheckpointTestPairV4(t, f.dir, "erasure", e, p.KeyID, key)
}

func (f inventoryFixtureV4) inspect() (ContributionInventoryInspectionV4, error) {
	return InspectContributionInventoryV4(f.trust, f.paths, f.scope, f.dir)
}

func TestContributionInventoryV4ReconstructsFixedFiveFiles(t *testing.T) {
	for _, phase := range []Phase{Phase1, Phase2} {
		t.Run(string(phase), func(t *testing.T) {
			f := localInventoryFixtureV4(t, phase)
			five, err := f.inspect()
			if err != nil {
				t.Fatal(err)
			}
			if len(five.Computed.Files) != 5 || five.ComputedCandidateID == "" || five.Complete == nil || five.CandidateResultID != five.ComputedCandidateID || five.Scope != f.scope {
				t.Fatalf("bad computed result %+v", five)
			}
			putCheckpointTestFileV4(t, f.dir, "local-metadata.json", []byte("not uploaded"))
			again, err := f.inspect()
			if err != nil || again.CandidateResultID != five.CandidateResultID {
				t.Fatal("extra file changed inventory", err)
			}
		})
	}
}

func TestContributionInventoryV4RejectsPartialChangedAndUnboundWork(t *testing.T) {
	for _, test := range []string{"scope", "phase", "participant", "software", "time", "payload", "symlink", "oversize"} {
		t.Run(test, func(t *testing.T) {
			f := localInventoryFixtureV4(t, Phase1)
			_, err := f.inspect()
			if err != nil {
				t.Fatal(err)
			}
			switch test {
			case "scope":
				f.scope.ParentHeadID = NewDigest([]byte("other head")).SHA256
			case "phase":
				f.scope.Phase = Phase2
			case "participant":
				f.scope.ParticipantID = f.d.Roster[1].Identity.ID
			case "software":
				a := f.a
				a.SourceCommit = strings.Repeat("aa", 20)
				f.sign(t, a)
			case "time":
				a := f.a
				a.ContributedAt = f.d.CreatedAt
				f.sign(t, a)
			case "payload":
				putCheckpointTestFileV4(t, f.dir, "contribution.bin", []byte("changed"))
			case "symlink":
				if err := os.Rename(filepath.Join(f.dir, "attestation.json"), filepath.Join(f.dir, "other.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other.json", filepath.Join(f.dir, "attestation.json")); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				file, err := os.OpenFile(filepath.Join(f.dir, "attestation.sig"), os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(4097)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := f.inspect()
			if err == nil || got.ComputedCandidateID != "" || got.CandidateResultID != "" {
				t.Fatalf("accepted %s or leaked partial success: %+v %v", test, got, err)
			}
		})
	}
}

func TestContributionInventoryV4ClassifiesOnlySemanticCandidateFailures(t *testing.T) {
	t.Run("signed candidate semantics", func(t *testing.T) {
		f := localInventoryFixtureV4(t, Phase1)
		a := f.a
		a.SourceCommit = strings.Repeat("aa", 20)
		f.sign(t, a)
		if _, err := f.inspect(); err == nil || !IsCandidateInvalid(err) {
			t.Fatalf("candidate semantic failure classification = %v, want candidate invalid", err)
		}
	})

	t.Run("stable payload digest mismatch", func(t *testing.T) {
		f := localInventoryFixtureV4(t, Phase1)
		path := filepath.Join(f.dir, "contribution.bin")
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		payload[len(payload)-1] ^= 1
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.inspect(); err == nil || !IsCandidateInvalid(err) {
			t.Fatalf("stable payload mismatch classification = %v, want candidate invalid", err)
		}
	})

	t.Run("candidate file missing", func(t *testing.T) {
		f := localInventoryFixtureV4(t, Phase1)
		if err := os.Remove(filepath.Join(f.dir, "attestation.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.inspect(); err == nil || IsCandidateInvalid(err) {
			t.Fatalf("operational failure classification = %v, must not be candidate invalid", err)
		}
	})
}

func TestContributionInventoryV4LaterTurnAndPredecessorTime(t *testing.T) {
	for _, phase := range []Phase{Phase1, Phase2} {
		t.Run(string(phase), func(t *testing.T) {
			f := localInventoryFixtureV4(t, phase)
			b, err := os.ReadFile(f.paths.ChainPath)
			if err != nil {
				t.Fatal(err)
			}
			var chain Chain
			if err := UnmarshalCanonical(b, &chain); err != nil {
				t.Fatal(err)
			}
			record := adversarialChainRecord(t, f.d, chain.PhaseID, 1, f.d.Roster[0].Identity.ID, chain.Genesis, f.scope.ParentHeadID, "previous-output")
			record.Phase = phase
			record.AcceptedAt = "2026-07-23T12:00:30Z"
			record, err = NewChainRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := chain.Append(record); err != nil {
				t.Fatal(err)
			}
			pair := putCheckpointTestPairV4(t, f.paths.RootDir, string(phase)+"/chain-0001", chain, f.d.Coordinator.KeyID, adversarialPrivateKey(1))
			f.paths.ChainPath = filepath.Join(f.paths.RootDir, pair.Record.Name)
			f.paths.ChainSignaturePath = filepath.Join(f.paths.RootDir, pair.Signature.Name)
			f.scope.Index = 2
			f.scope.ParticipantID = f.d.Roster[1].Identity.ID
			f.scope.ParentHeadID = record.RecordID
			f.a.Index = 2
			f.a.ParticipantID = f.scope.ParticipantID
			f.a.ParticipantKeyID = f.d.Roster[1].Identity.KeyID
			f.a.PreviousAcceptanceID = record.RecordID
			f.a.PreviousPayload = record.OutputPayload
			f.a.OutputPayload.Name = fmt.Sprintf("%s/contributions/0002/contribution.bin", phase)
			f.sign(t, f.a)
			i, err := f.inspect()
			if err != nil {
				t.Fatal(err)
			}
			if i.CandidateResultID == "" {
				t.Fatal("complete candidate result ID missing")
			}
			f.a.ContributedAt = record.AcceptedAt
			f.sign(t, f.a)
			if _, err := f.inspect(); err == nil || !strings.Contains(err.Error(), "strictly after the previous acceptance") {
				t.Fatal(err)
			}
		})
	}
}
