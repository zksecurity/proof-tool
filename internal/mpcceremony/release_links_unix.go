//go:build linux || darwin

package mpcceremony

import (
	"errors"
	"os"
	"syscall"
)

func requireSingleLinkV4(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("V4 release files must have exactly one hard link")
	}
	return nil
}
