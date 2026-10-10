package installer

import (
	"context"
	"os"
	"time"
)

// Exported helpers for lifecycle commands (update, rollback, repair).

// AtomicSymlink replaces link with a symlink to target atomically.
func AtomicSymlink(target, link string) error { return atomicSymlink(target, link) }

// CopyFile copies src to dst with mode (via a temporary file and rename).
func CopyFile(src, dst string, mode os.FileMode) error { return copyFile(src, dst, mode) }

// WaitHealthy polls the local API health endpoint.
func WaitHealthy(ctx context.Context, listen string, within time.Duration) error {
	return waitHealthy(ctx, listen, within)
}

// Units lists NGM's systemd units in start order.
func Units() []string { return append([]string(nil), units...) }
