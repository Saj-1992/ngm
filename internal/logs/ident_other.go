//go:build !unix

package logs

import "os"

// fileIdent is unavailable here; rotation then shows up as truncation.
func fileIdent(os.FileInfo) string { return "" }
