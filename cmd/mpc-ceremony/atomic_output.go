package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// writeAtomicOutputDir publishes a small closed set of result files with a
// no-replace directory rename. A byte-identical completed result is an
// idempotent success; incomplete or conflicting output is never overwritten.
func writeAtomicOutputDir(outDir string, files map[string][]byte) (err error) {
	parent := filepath.Dir(outDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(outDir); err == nil {
		info, statErr := os.Lstat(outDir)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("atomic output path exists but is not a regular directory")
		}
		for name, expected := range files {
			actual, readErr := readRegularOperationalFile(filepath.Join(outDir, name), maxOperationalRecordBytes)
			if readErr != nil || !slices.Equal(actual, expected) {
				return errors.New("atomic output already exists with conflicting or incomplete contents")
			}
		}
		entries, readErr := os.ReadDir(outDir)
		if readErr != nil || len(entries) != len(files) {
			return errors.New("atomic output already exists with conflicting or incomplete contents")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".atomic-output-*")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(tmp)
		}
	}()
	for name, data := range files {
		if err := writeFreshOperationalFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			return err
		}
	}
	if err := syncDirectory(tmp); err != nil {
		return err
	}
	if err := renameDirectoryNoReplace(tmp, outDir); err != nil {
		return err
	}
	complete = true
	return syncDirectory(parent)
}
