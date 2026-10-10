//go:build !unix

package app

import (
	"errors"
	"os"
)

func diskFree(string) (uint64, uint64, error) { return 0, 0, errors.New("unsupported") }

func fileSize(p string) int64 {
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return 0
}
