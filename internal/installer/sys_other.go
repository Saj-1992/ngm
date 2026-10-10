//go:build !linux

package installer

func dpkgBusy() string { return "" }

func diskFree(string) (uint64, bool) { return 0, false }
