package proofassets

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"

	"proof-tool/internal/strictjson"
)

const (
	DomainHeaderBytes = 169
	G1RawBytes        = 96
	G2RawBytes        = 192
)

type PKSection struct {
	Name     string `json:"name"`
	Offset   int64  `json:"offset"`
	Len      int64  `json:"len"`
	ElemSize int    `json:"elem_size"`
}

type PKIndex struct {
	Sections          map[string]PKSection `json:"sections"`
	DomainCardinality uint64               `json:"domain_cardinality"`
	NbWires           uint64               `json:"nb_wires"`
	NbInfinityA       uint64               `json:"nb_infinity_a"`
	NbInfinityB       uint64               `json:"nb_infinity_b"`
	NbCommitmentKeys  uint32               `json:"nb_commitment_keys"`
	FileSize          int64                `json:"file_size"`
}

func BuildPKIndex(path string) (*PKIndex, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proving key %s: %w", path, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat proving key %s: %w", path, err)
	}

	idx := &PKIndex{
		Sections: make(map[string]PKSection),
		FileSize: stat.Size(),
	}

	var domain [DomainHeaderBytes]byte
	if _, err := io.ReadFull(f, domain[:]); err != nil {
		return nil, fmt.Errorf("read domain header: %w", err)
	}
	idx.DomainCardinality = binary.BigEndian.Uint64(domain[:8])

	if _, err := f.Seek(3*G1RawBytes, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("seek past G1 singletons: %w", err)
	}

	for _, name := range []string{"A", "B", "Z", "K"} {
		sec, err := readSection(f, name, G1RawBytes)
		if err != nil {
			return nil, fmt.Errorf("G1.%s: %w", name, err)
		}
		idx.Sections[name] = sec
	}

	if _, err := f.Seek(2*G2RawBytes, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("seek past G2 singletons: %w", err)
	}

	sec, err := readSection(f, "G2B", G2RawBytes)
	if err != nil {
		return nil, fmt.Errorf("G2.B: %w", err)
	}
	idx.Sections["G2B"] = sec

	idx.NbWires, err = readBEUint64(f)
	if err != nil {
		return nil, fmt.Errorf("read nbWires: %w", err)
	}
	idx.NbInfinityA, err = readBEUint64(f)
	if err != nil {
		return nil, fmt.Errorf("read NbInfinityA: %w", err)
	}
	idx.NbInfinityB, err = readBEUint64(f)
	if err != nil {
		return nil, fmt.Errorf("read NbInfinityB: %w", err)
	}
	if idx.NbWires > math.MaxInt64/2 {
		return nil, fmt.Errorf("nbWires %d would overflow int64", idx.NbWires)
	}
	if _, err := f.Seek(int64(idx.NbWires)*2, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("seek past infinity bitmaps: %w", err)
	}

	idx.NbCommitmentKeys, err = readBEUint32(f)
	if err != nil {
		return nil, fmt.Errorf("read nbCommitmentKeys: %w", err)
	}
	for i := 0; i < int(idx.NbCommitmentKeys); i++ {
		basisName := "Basis"
		sigmaName := "BasisExpSigma"
		if i > 0 {
			basisName = fmt.Sprintf("Basis_%d", i)
			sigmaName = fmt.Sprintf("BasisExpSigma_%d", i)
		}
		basis, err := readSection(f, basisName, G1RawBytes)
		if err != nil {
			return nil, fmt.Errorf("commitment key %d Basis: %w", i, err)
		}
		idx.Sections[basisName] = basis
		sigma, err := readSection(f, sigmaName, G1RawBytes)
		if err != nil {
			return nil, fmt.Errorf("commitment key %d BasisExpSigma: %w", i, err)
		}
		idx.Sections[sigmaName] = sigma
	}

	if off, err := f.Seek(0, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("read final offset: %w", err)
	} else if off != stat.Size() {
		return nil, fmt.Errorf("index ended at byte %d, file size is %d", off, stat.Size())
	}
	return idx, nil
}

func ValidatePKIndex(idx *PKIndex) error {
	if idx == nil {
		return fmt.Errorf("index is required")
	}
	if idx.FileSize <= 0 {
		return fmt.Errorf("index file_size is required")
	}
	required := []string{"A", "B", "Z", "K", "G2B"}
	for _, name := range required {
		if _, ok := idx.Sections[name]; !ok {
			return fmt.Errorf("index missing section %q", name)
		}
	}
	for name, sec := range idx.Sections {
		if sec.Name == "" {
			return fmt.Errorf("section %q has empty name", name)
		}
		if sec.Name != name {
			return fmt.Errorf("section map key %q does not match name %q", name, sec.Name)
		}
		if sec.Offset < 0 || sec.Len < 0 {
			return fmt.Errorf("section %q has negative offset or length", name)
		}
		if sec.ElemSize != G1RawBytes && sec.ElemSize != G2RawBytes {
			return fmt.Errorf("section %q has elem_size %d", name, sec.ElemSize)
		}
		if sec.Len%int64(sec.ElemSize) != 0 {
			return fmt.Errorf("section %q length %d is not divisible by elem_size %d", name, sec.Len, sec.ElemSize)
		}
		// Subtraction keeps a hostile offset+length pair from wrapping int64
		// negative and passing the file boundary check.
		if sec.Len > idx.FileSize || sec.Offset > idx.FileSize-sec.Len {
			return fmt.Errorf("section %q exceeds file size", name)
		}
	}
	return nil
}

// ValidatePKIndexAllocations bounds the counter fields that drive memory
// allocation when a proving key is opened: make([]bool, NbWires) and
// make([]pedersen.ProvingKey, NbCommitmentKeys) in KeySource.loadSmallFields,
// and len(wires)-NbInfinityA in the prove path. It is separate from
// ValidatePKIndex because the manifest-derived index carries only section
// geometry (the counters live outside the signed digest); call this only where
// a full index with populated counters is consumed. Each counter is bounded
// against FileSize and Sections — fields the manifest digest does cover — so an
// out-of-range counter is unrepresentable without also changing a signed field.
//
// ValidatePKIndex must have passed first.
func ValidatePKIndexAllocations(idx *PKIndex) error {
	if idx == nil {
		return fmt.Errorf("index is required")
	}
	g2b, ok := idx.Sections["G2B"]
	if !ok {
		return fmt.Errorf("index missing section \"G2B\"")
	}
	// Layout after G2B: nbWires|NbInfinityA|NbInfinityB (3×8 bytes), then the
	// two infinity bitmaps of NbWires bytes each, then the 4-byte commitment
	// count. Everything must fit inside FileSize.
	const infHeaderLen = 3 * 8
	const countLen = 4
	if idx.NbWires > math.MaxInt64 {
		return fmt.Errorf("nb_wires %d is implausibly large", idx.NbWires)
	}
	if g2b.Len > idx.FileSize || g2b.Offset > idx.FileSize-g2b.Len {
		return fmt.Errorf("G2B section exceeds file_size %d", idx.FileSize)
	}
	infOff := g2b.Offset + g2b.Len
	if infOff > idx.FileSize || idx.FileSize-infOff < infHeaderLen+countLen {
		return fmt.Errorf("infinity metadata does not fit within file_size %d", idx.FileSize)
	}
	bitmapBytes := idx.FileSize - infOff - infHeaderLen - countLen
	if idx.NbWires > uint64(bitmapBytes/2) {
		return fmt.Errorf("nb_wires %d does not fit within file_size %d", idx.NbWires, idx.FileSize)
	}
	if idx.NbInfinityA > idx.NbWires || idx.NbInfinityB > idx.NbWires {
		return fmt.Errorf("nb_infinity (%d, %d) exceeds nb_wires %d", idx.NbInfinityA, idx.NbInfinityB, idx.NbWires)
	}
	// Each commitment key contributes exactly two sections (Basis,
	// BasisExpSigma) on top of the five base sections, so the count is bounded
	// by the section map — itself bounded by the parsed input — and every
	// referenced section must be present.
	if 5+2*uint64(idx.NbCommitmentKeys) != uint64(len(idx.Sections)) {
		return fmt.Errorf("nb_commitment_keys %d is inconsistent with %d sections", idx.NbCommitmentKeys, len(idx.Sections))
	}
	for i := 0; i < int(idx.NbCommitmentKeys); i++ {
		basisName, sigmaName := "Basis", "BasisExpSigma"
		if i > 0 {
			basisName = fmt.Sprintf("Basis_%d", i)
			sigmaName = fmt.Sprintf("BasisExpSigma_%d", i)
		}
		if _, ok := idx.Sections[basisName]; !ok {
			return fmt.Errorf("index missing commitment section %q", basisName)
		}
		if _, ok := idx.Sections[sigmaName]; !ok {
			return fmt.Errorf("index missing commitment section %q", sigmaName)
		}
	}
	return nil
}

func WritePKIndex(path string, idx *PKIndex) error {
	if err := ValidatePKIndex(idx); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write index %s: %w", path, err)
	}
	return nil
}

func ReadPKIndex(path string) (*PKIndex, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read index %s: %w", path, err)
	}
	var idx PKIndex
	if err := strictjson.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("parse index %s: %w", path, err)
	}
	if err := ValidatePKIndex(&idx); err != nil {
		return nil, err
	}
	if err := ValidatePKIndexAllocations(&idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

func readSection(rs io.ReadSeeker, name string, elemSize int) (PKSection, error) {
	count, err := readBEUint32(rs)
	if err != nil {
		return PKSection{}, err
	}
	off, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return PKSection{}, err
	}
	payloadLen := int64(count) * int64(elemSize)
	if _, err := rs.Seek(payloadLen, io.SeekCurrent); err != nil {
		return PKSection{}, err
	}
	return PKSection{Name: name, Offset: off, Len: payloadLen, ElemSize: elemSize}, nil
}

func readBEUint32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func readBEUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}
