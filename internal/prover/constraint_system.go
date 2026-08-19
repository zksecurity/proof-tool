package prover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const gnarkConstraintSystemHeaderBytes = 4 * 8

// PreflightConstraintSystemReader validates gnark's declared payload length
// before ReadFrom can allocate from it. The returned reader replays the header
// and then continues from r, so callers can pass it directly to ReadFrom.
// Callers must still cap r itself to maxBytes to bound the bytes transported.
func PreflightConstraintSystemReader(r io.Reader, maxBytes int64) (io.Reader, error) {
	if r == nil {
		return nil, fmt.Errorf("constraint system reader is required")
	}
	if maxBytes < gnarkConstraintSystemHeaderBytes {
		return nil, fmt.Errorf("constraint system maximum %d is smaller than its %d-byte header", maxBytes, gnarkConstraintSystemHeaderBytes)
	}
	var header [gnarkConstraintSystemHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read constraint system header: %w", err)
	}
	declared := binary.LittleEndian.Uint64(header[:8])
	maxPayload := uint64(maxBytes - gnarkConstraintSystemHeaderBytes)
	if declared > maxPayload {
		return nil, fmt.Errorf("constraint system declares %d payload bytes, exceeds maximum %d", declared, maxPayload)
	}
	return io.MultiReader(bytes.NewReader(header[:]), r), nil
}
