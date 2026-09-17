//go:build darwin

// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import "golang.org/x/sys/unix"

func renameDirectoryNoReplace(oldPath, newPath string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_EXCL)
}
