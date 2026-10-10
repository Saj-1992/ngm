//go:build unix

package logs

import (
	"os"
	"strconv"
	"syscall"
)

// fileIdent identifies a file across renames (device:inode).
func fileIdent(fi os.FileInfo) string {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(s.Dev), 10) + ":" + strconv.FormatUint(uint64(s.Ino), 10)
	}
	return ""
}
