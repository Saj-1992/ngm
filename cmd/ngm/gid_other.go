//go:build !unix

package main

import "os"

func fileGID(os.FileInfo) string { return "" }
