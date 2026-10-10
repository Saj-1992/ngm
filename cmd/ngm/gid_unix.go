//go:build unix

package main

import (
	"os"
	"strconv"
	"syscall"
)

func fileGID(st os.FileInfo) string {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(s.Gid), 10)
	}
	return ""
}
