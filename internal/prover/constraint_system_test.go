package prover

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestPreflightConstraintSystemReader(t *testing.T) {
	header := make([]byte, gnarkConstraintSystemHeaderBytes)
	binary.LittleEndian.PutUint64(header[:8], 3)
	raw := append(header, 1, 2, 3)

	r, err := PreflightConstraintSystemReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("replayed bytes differ: got %x, want %x", got, raw)
	}
}

func TestPreflightConstraintSystemReaderRejectsDeclaredAllocation(t *testing.T) {
	header := make([]byte, gnarkConstraintSystemHeaderBytes)
	binary.LittleEndian.PutUint64(header[:8], 1<<30)
	body := []byte("body must remain unread")
	source := bytes.NewReader(append(header, body...))

	_, err := PreflightConstraintSystemReader(source, 1024)
	if err == nil || !strings.Contains(err.Error(), "declares") {
		t.Fatalf("expected declared-size rejection, got %v", err)
	}
	if source.Len() != len(body) {
		t.Fatalf("preflight read %d payload bytes", len(body)-source.Len())
	}
}

func TestPreflightConstraintSystemReaderRejectsShortHeader(t *testing.T) {
	_, err := PreflightConstraintSystemReader(bytes.NewReader(make([]byte, 8)), 1024)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("expected short-header rejection, got %v", err)
	}
}
