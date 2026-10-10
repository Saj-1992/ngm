//go:build linux

package lifecycle

import (
	"os"
	"syscall"
)

func chownLike(p string, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(p, int(st.Uid), int(st.Gid))
	}
}
