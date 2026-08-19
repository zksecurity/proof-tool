//go:build js && wasm

package main

import (
	"bytes"
	"io"
	"math"
	"strings"
	"testing"
)

func TestBoundedCompressedWireAllowsOneByteForOverrunDetection(t *testing.T) {
	source := bytes.NewReader([]byte("0123456789"))
	r, err := boundedCompressedWire(source, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "01234" {
		t.Fatalf("bounded bytes = %q, want %q", got, "01234")
	}
	if source.Len() != 5 {
		t.Fatalf("bounded reader consumed %d bytes past its cap", 5-source.Len())
	}
}

func TestBoundedCompressedWireRejectsUnsafeSizes(t *testing.T) {
	for _, size := range []int64{0, -1, math.MaxInt64} {
		if _, err := boundedCompressedWire(strings.NewReader("x"), size); err == nil {
			t.Fatalf("size %d was accepted", size)
		}
	}
}
