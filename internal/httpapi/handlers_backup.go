package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/audit"
	"github.com/ngm-gateway/ngm/internal/backup"
)

const jobKindBackup = "backup.create" // = deploy.KindBackup

func (s *Server) registerBackupRoutes() {
	s.handle("GET", "/api/v1/backups", "backups.read", s.listBackups)
	s.handle("POST", "/api/v1/backups", "backups.create", s.createBackup)
	s.handle("GET", "/api/v1/backups/settings", "backups.read", s.getBackupSettings)
	s.handle("PUT", "/api/v1/backups/schedule", "settings.write", s.putBackupSchedule)
	s.handle("POST", "/api/v1/backups/passphrase", "settings.write", s.setBackupPassphrase)
	s.handle("GET", "/api/v1/backups/{id}/download", "backups.create", s.downloadBackup)
	s.handle("POST", "/api/v1/backups/{id}/verify", "backups.read", s.verifyBackup)
	s.handle("DELETE", "/api/v1/backups/{id}", "backups.create", s.deleteBackup)
}

func (s *Server) backups() *backup.Service {
	return &backup.Service{DB: s.d.DB, Vault: s.d.Vault, Dir: s.d.Config.Paths.Backups}
}

func mapBackupError(err error) error {
	switch {
	case errors.Is(err, backup.ErrNotFound):
		return apierr.NotFound("backup")
	case errors.Is(err, backup.ErrNoPassphrase):
		return apierr.New(http.StatusConflict, "no_passphrase", "no backup passphrase configured")
	case errors.Is(err, backup.ErrWeak):
		return apierr.BadRequest(err.Error())
	case errors.Is(err, backup.ErrCorrupt), errors.Is(err, backup.ErrWrongPassphrase), errors.Is(err, backup.ErrNotBackup):
		return apierr.New(http.StatusUnprocessableEntity, "backup_invalid", err.Error())
	}
	return err
}

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) error {
	items, err := s.backups().List(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getBackupSettings(w http.ResponseWriter, r *http.Request) error {
	b := s.backups()
	return writeJSON(w, http.StatusOK, map[string]any{"passphrase_configured": b.Configured(r.Context()), "schedule": b.GetSchedule(r.Context()),
		"storage_warning": "Backups are stored only on this server's disk. Download copies regularly: a lost VPS loses its local backups."})
}

func (s *Server) putBackupSchedule(w http.ResponseWriter, r *http.Request) error {
	var in backup.Schedule
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if err := s.backups().SetSchedule(r.Context(), in); err != nil {
		return apierr.BadRequest(err.Error())
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "backup.schedule_update", "settings", "backup.schedule", map[string]any{"enabled": in.Enabled, "interval_hours": in.IntervalHours, "retain": in.Retain}))
	return writeJSON(w, http.StatusOK, in)
}

type passphraseIn struct {
	Passphrase string `json:"passphrase"`
}

func (s *Server) setBackupPassphrase(w http.ResponseWriter, r *http.Request) error {
	var in passphraseIn
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	err := s.backups().SetPassphrase(r.Context(), in.Passphrase)
	in.Passphrase = ""
	if err != nil {
		return mapBackupError(err)
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "backup.passphrase_set", "settings", "backup.kdf", nil))
	return writeJSON(w, http.StatusOK, map[string]any{"passphrase_configured": true,
		"warning": "Store this passphrase safely outside the server. Without it, backups cannot be restored on a new host."})
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) error {
	if !s.backups().Configured(r.Context()) {
		return mapBackupError(backup.ErrNoPassphrase)
	}
	return s.submitJob(w, r, jobKindBackup, []string{"backup-restore"}, map[string]string{"trigger": "manual"})
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	f, a, err := s.backups().Open(r.Context(), id)
	if err != nil {
		return mapBackupError(err)
	}
	defer f.Close()
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "backup.download", "backup", id, nil))
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+a.FileName+`"`)
	h.Set("Content-Length", strconv.FormatInt(a.Size, 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-SHA256", a.SHA256)
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, f)
	return err
}

func (s *Server) verifyBackup(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	m, err := s.backups().Verify(r.Context(), id)
	if err != nil {
		return mapBackupError(err)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
}

func (s *Server) deleteBackup(w http.ResponseWriter, r *http.Request) error {
	id, err := validID(r)
	if err != nil {
		return err
	}
	if err := s.backups().Delete(r.Context(), id); err != nil {
		return mapBackupError(err)
	}
	_, _ = s.d.Audit.Record(r.Context(), auditEvent(r, "backup.delete", "backup", id, nil))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// auditEvent builds a success event attributed to the request's principal.
func auditEvent(r *http.Request, action, targetKind, targetID string, ctx map[string]any) audit.Event {
	e := audit.Event{ActorKind: "system", Action: action, TargetKind: targetKind, TargetID: targetID, Result: "success", RequestID: RequestID(r.Context()), Context: ctx}
	if p := PrincipalFrom(r.Context()); p != nil {
		e.ActorKind, e.ActorID = "user", p.UserID
		if p.Kind == "token" {
			e.ActorKind, e.ActorID = "token", p.TokenID
		}
	}
	return e
}
