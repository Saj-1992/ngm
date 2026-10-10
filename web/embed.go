// Package web embeds the built Control Center SPA (web/dist, produced by
// `npm run build`). When the UI has not been built, only .gitkeep is present
// and the API answers UI paths with 503 "not built".
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built UI filesystem rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
