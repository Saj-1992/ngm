// Package buildinfo exposes version metadata set at link time
// (-ldflags "-X github.com/ngm-gateway/ngm/internal/buildinfo.Version=...").
package buildinfo

import "runtime"

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
	// Channel is stable, beta or development (release builds set it).
	Channel = "development"
)

// APIVersion is the REST API major version.
const APIVersion = "v1"

// Info is the serialisable build description.
type Info struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	Date       string `json:"build_date"`
	APIVersion string `json:"api_version"`
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Channel    string `json:"channel"`
}

// Get returns the current build info.
func Get() Info {
	return Info{Version, Commit, Date, APIVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH, Channel}
}
