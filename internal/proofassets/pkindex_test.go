package proofassets

import (
	"math"
	"strings"
	"testing"
)

// validAllocIndex returns a PKIndex whose geometry and counters are mutually
// consistent, matching what BuildPKIndex produces for a one-commitment key.
func validAllocIndex() *PKIndex {
	const g2bOff = 10_000
	sections := map[string]PKSection{
		"A":             {Name: "A", Offset: 100, Len: G1RawBytes, ElemSize: G1RawBytes},
		"B":             {Name: "B", Offset: 200, Len: G1RawBytes, ElemSize: G1RawBytes},
		"Z":             {Name: "Z", Offset: 300, Len: G1RawBytes, ElemSize: G1RawBytes},
		"K":             {Name: "K", Offset: 400, Len: G1RawBytes, ElemSize: G1RawBytes},
		"G2B":           {Name: "G2B", Offset: g2bOff, Len: G2RawBytes, ElemSize: G2RawBytes},
		"Basis":         {Name: "Basis", Offset: 20_000, Len: G1RawBytes, ElemSize: G1RawBytes},
		"BasisExpSigma": {Name: "BasisExpSigma", Offset: 21_000, Len: G1RawBytes, ElemSize: G1RawBytes},
	}
	return &PKIndex{
		Sections:         sections,
		NbWires:          4,
		NbInfinityA:      1,
		NbInfinityB:      0,
		NbCommitmentKeys: 1,
		FileSize:         100_000,
	}
}

func TestValidatePKIndexAllocations(t *testing.T) {
	if err := ValidatePKIndex(validAllocIndex()); err != nil {
		t.Fatalf("geometry validation failed on valid index: %v", err)
	}
	if err := ValidatePKIndexAllocations(validAllocIndex()); err != nil {
		t.Fatalf("allocation validation failed on valid index: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*PKIndex)
		wantSub string
	}{
		{"huge commitment count", func(i *PKIndex) { i.NbCommitmentKeys = 0xFFFFFFFF }, "nb_commitment_keys"},
		{"nbWires overflow", func(i *PKIndex) { i.NbWires = math.MaxUint64 }, "implausibly large"},
		{"nbWires arithmetic boundary", func(i *PKIndex) { i.NbWires = math.MaxInt64 / 2 }, "does not fit"},
		{"nbWires exceeds file", func(i *PKIndex) { i.NbWires = 1 << 40 }, "does not fit"},
		{"infinity exceeds wires", func(i *PKIndex) { i.NbInfinityA = 5 }, "exceeds nb_wires"},
		{"missing basis section", func(i *PKIndex) {
			i.NbCommitmentKeys = 2
			i.Sections["Basis_1"] = PKSection{Name: "Basis_1", Offset: 30_000, Len: G1RawBytes, ElemSize: G1RawBytes}
			// count now claims 2 keys (9 sections needed) but only 8 present:
			// the equality check fires before the per-key lookup.
		}, "inconsistent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := validAllocIndex()
			tc.mutate(idx)
			err := ValidatePKIndexAllocations(idx)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestValidatePKIndexRejectsSectionEndOverflow(t *testing.T) {
	idx := validAllocIndex()
	section := idx.Sections["G2B"]
	section.Offset = math.MaxInt64 - section.Len + 1
	idx.Sections["G2B"] = section
	if err := ValidatePKIndex(idx); err == nil || !strings.Contains(err.Error(), "exceeds file size") {
		t.Fatalf("expected overflowing section rejection, got %v", err)
	}
}
