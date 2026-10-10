//go:build !linux

package lifecycle

import "os"

func chownLike(string, os.FileInfo) {}
