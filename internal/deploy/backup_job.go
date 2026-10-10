package deploy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/locks"
)

// KindBackup creates an encrypted local backup.
const KindBackup = "backup.create"

// BackupPayload is the job payload.
type BackupPayload struct {
	Trigger string `json:"trigger"` // manual | scheduled
}

var backupLocks = []locks.Resource{locks.BackupRestore}

func (c *Coordinator) runBackup(r *runner) {
	ctx := r.ctx
	var p BackupPayload
	_ = json.Unmarshal(r.j.Payload, &p)
	if p.Trigger != "scheduled" {
		p.Trigger = "manual"
	}
	if err := r.to(jobs.Validating, "validate", jobs.Idempotent, p); err != nil {
		return
	}
	if c.Backups == nil || !c.Backups.Configured(ctx) {
		r.end(jobs.Blocked, "no_passphrase", nil, &failure{Code: "no_passphrase", Message: "set a backup passphrase first; NGM never stores the passphrase itself"})
		return
	}
	_ = r.to(jobs.ImpactAnalyzed, "impact", jobs.Idempotent, nil)
	_ = r.to(jobs.Staging, "stage", jobs.Idempotent, nil)
	_ = r.to(jobs.Preflight, "preflight", jobs.Idempotent, nil)
	if err := r.to(jobs.Applying, "write_archive", jobs.External, nil); err != nil {
		return
	}
	a, err := c.Backups.CreateArchive(ctx, c.KeysDir, c.Hostname, p.Trigger, r.j.ActorID)
	if err != nil {
		// Nothing is published on failure (partial files are removed).
		_ = r.to(jobs.Compensating, "write_failed", jobs.Idempotent, map[string]string{"error": err.Error()})
		r.end(jobs.RolledBack, "rolled_back", nil, &failure{Code: "backup_failed", Message: err.Error()})
		return
	}
	_ = r.to(jobs.Verifying, "verified", jobs.Idempotent, map[string]any{"file": a.FileName, "sha256": a.SHA256, "size": a.Size})
	removed := 0
	if p.Trigger == "scheduled" {
		removed, _ = c.Backups.ApplyRetention(ctx, c.Backups.GetSchedule(ctx).Retain)
	}
	r.end(jobs.Succeeded, "succeeded", map[string]any{"backup_id": a.ID, "file": a.FileName, "size": a.Size, "retention_removed": removed}, nil)
}

// ScheduleBackups queues a scheduled backup when one is due.
func (c *Coordinator) ScheduleBackups(ctx context.Context) error {
	if c.Backups == nil {
		return nil
	}
	sc := c.Backups.GetSchedule(ctx)
	if !sc.Enabled || !c.Backups.Configured(ctx) {
		return nil
	}
	last := c.Backups.LastScheduled(ctx)
	if !last.IsZero() && time.Since(last) < time.Duration(sc.IntervalHours)*time.Hour {
		return nil
	}
	// One scheduled backup per interval window (idempotency key).
	win := time.Now().UTC().Truncate(time.Duration(sc.IntervalHours) * time.Hour).Format("2006010215")
	_, _, err := c.Jobs.Submit(ctx, jobs.SubmitRequest{Kind: KindBackup, IdempotencyKey: "scheduled-" + win, LockSet: []string{"backup-restore"},
		Payload: BackupPayload{Trigger: "scheduled"}})
	return err
}
