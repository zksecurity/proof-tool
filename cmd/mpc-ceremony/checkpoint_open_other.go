// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Non-Unix builds are not ceremony execution targets. Keep compilation and
// root confinement without claiming the Unix no-follow guarantee.
func openCheckpointArtifactBytes(root, relative string, limit int64) ([]byte, error) {
	openedRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer openedRoot.Close()
	file, err := openedRoot.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("checkpoint artifact size %d is outside [1,%d] or is not regular", info.Size(), limit)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return nil, errors.New("checkpoint artifact changed while being read")
	}
	return data, nil
}
