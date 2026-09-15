//go:build linux

// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import "golang.org/x/sys/unix"

func renameDirectoryNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}
