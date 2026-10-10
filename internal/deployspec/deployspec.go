// Package deployspec holds the deployment job contract shared by the API
// (which submits jobs) and the coordinator (which runs them). It has no
// dependencies so that the API never links data-plane code.
package deployspec

// Job kinds handled by the Deployment Coordinator.
const (
	KindApply    = "deploy.gateway"
	KindRollback = "deploy.rollback"
)

// ApplyPayload is the job payload for KindApply.
type ApplyPayload struct {
	// DisableDistroDefaultSite authorises removing Ubuntu's
	// sites-enabled/default symlink when it conflicts with an NGM :80 listener.
	DisableDistroDefaultSite bool   `json:"disable_distro_default_site,omitempty"`
	Force                    bool   `json:"force,omitempty"` // apply even if the model is unchanged
	Note                     string `json:"note,omitempty"`
}

// RollbackPayload targets a previous generation.
type RollbackPayload struct {
	GenerationID string `json:"generation_id"`
}
