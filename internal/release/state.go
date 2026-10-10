package release

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// UpdateState is the durable record of the last update attempt
// (/var/lib/ngm/update/state.json). It lets `ngm update rollback` and the
// API report exactly what happened, including after a crash.
type UpdateState struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	FromSchema int       `json:"from_schema"`
	ToSchema   int       `json:"to_schema,omitempty"`
	Snapshot   string    `json:"snapshot"`         // pre-update DB copy
	Backup     string    `json:"backup,omitempty"` // encrypted archive file, when configured
	Phase      string    `json:"phase"`            // staged|installing|succeeded|failed|rolled_back|rollback_failed
	Error      string    `json:"error,omitempty"`
	Actor      string    `json:"actor"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// StatePath returns the state file under stateDir (/var/lib/ngm).
func StatePath(stateDir string) string { return filepath.Join(stateDir, "update", "state.json") }

// LoadState returns nil, nil when no update was ever attempted.
func LoadState(stateDir string) (*UpdateState, error) {
	b, err := os.ReadFile(StatePath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s UpdateState
	return &s, json.Unmarshal(b, &s)
}

// SaveState writes s atomically (mode 0640; group ngm can read it).
func SaveState(stateDir string, s *UpdateState) error {
	p := StatePath(stateDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
