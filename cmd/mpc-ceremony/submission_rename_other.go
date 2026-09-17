//go:build !linux && !darwin

// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

func renameDirectoryNoReplace(_, _ string) error {
	return errors.New("atomic no-replace submission publication requires Linux or macOS")
}
