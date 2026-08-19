package streampk

import "proof-tool/internal/proofassets"

const (
	DomainHeaderBytes = proofassets.DomainHeaderBytes
	G1RawBytes        = proofassets.G1RawBytes
	G2RawBytes        = proofassets.G2RawBytes
)

type Section = proofassets.PKSection
type Index = proofassets.PKIndex

func BuildIndex(path string) (*Index, error) {
	return proofassets.BuildPKIndex(path)
}

func ValidateIndex(idx *Index) error {
	if err := proofassets.ValidatePKIndex(idx); err != nil {
		return err
	}
	return proofassets.ValidatePKIndexAllocations(idx)
}
