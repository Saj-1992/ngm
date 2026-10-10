//go:build linux

package installer

import (
	"os"

	"golang.org/x/sys/unix"
)

// dpkgBusy returns the first dpkg/apt lock currently held by another process.
func dpkgBusy() string {
	for _, p := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock"} {
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			continue
		}
		lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		err = unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk)
		f.Close()
		if err == nil && lk.Type != unix.F_UNLCK {
			return p
		}
	}
	return ""
}

// diskFree returns available bytes on the filesystem holding path.
func diskFree(path string) (uint64, bool) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, false
	}
	return fs.Bavail * uint64(fs.Bsize), true
}
