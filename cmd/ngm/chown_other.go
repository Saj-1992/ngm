//go:build !linux

package main

import "os"

func chownLike(string, os.FileInfo) {}
