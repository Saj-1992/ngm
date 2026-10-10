package httpapi

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/release"
)

func (s *Server) registerUpdateRoutes() {
	s.handle("GET", "/api/v1/system/updates", "system.read", s.getUpdates)
}

// getUpdates reports installed releases and the last update attempt.
// Installing is an administrator action on the server (`ngm update apply`),
// never an API side effect.
func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) error {
	type rel struct {
		Version string `json:"version"`
		Signed  bool   `json:"signed"`
		Current bool   `json:"current"`
	}
	cur, _ := filepath.EvalSymlinks(s.d.Config.Paths.Current)
	rels := []rel{}
	if es, err := os.ReadDir(s.d.Config.Paths.Releases); err == nil {
		for _, e := range es {
			_, err := os.Stat(filepath.Join(s.d.Config.Paths.Releases, e.Name(), "manifest.sig"))
			rels = append(rels, rel{e.Name(), err == nil, filepath.Base(cur) == e.Name()})
		}
	}
	st, err := release.LoadState(s.d.Config.Paths.StateDir)
	resp := map[string]any{"version": buildinfo.Version, "channel": buildinfo.Channel, "releases": rels, "last_update": st,
		"commands": map[string]string{"check": "ngm update check --from DIR", "apply": "ngm update apply --from DIR --yes", "rollback": "ngm update rollback --yes"}}
	if err != nil {
		resp["state_error"] = "update state unreadable"
	}
	return writeJSON(w, http.StatusOK, resp)
}
