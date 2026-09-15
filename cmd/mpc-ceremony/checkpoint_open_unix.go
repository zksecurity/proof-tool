// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openCheckpointArtifactBytes walks beneath an already-open root with
// O_NOFOLLOW on every component. No pathname component can be exchanged for a
// symlink between validation and use.
func openCheckpointArtifactBytes(root, relative string, limit int64) ([]byte, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	currentFD := rootFD
	defer func() { _ = unix.Close(currentFD) }()
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) == 0 || parts[len(parts)-1] == "" || parts[len(parts)-1] == "." {
		return nil, errors.New("checkpoint artifact path must name a file")
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("checkpoint artifact path has an invalid component")
		}
		nextFD, openErr := unix.Openat(currentFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, openErr
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	leaf := parts[len(parts)-1]
	if leaf == ".." {
		return nil, errors.New("checkpoint artifact path has an invalid component")
	}
	fileFD, err := unix.Openat(currentFD, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileFD), relative)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("open checkpoint artifact file descriptor")
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
