//go:build !linux && !darwin

package mpcceremony

import (
	"errors"
	"os"
)

func requireSingleLinkV4(_ os.FileInfo) error {
	return errors.New("V4 release link validation requires Linux or macOS")
}
