package httpapi

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/jobs"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/store"
)

func TestBackupHTTPFlow(t *testing.T) {
	f, ts := setupServer(t)
	f.srv.d.Config.Paths.Backups = t.TempDir()
	owner, _ := enrolOwner(t, ts)

	// No passphrase yet: create is refused with a clear code.
	if r := owner.do("POST", "/api/v1/backups", nil, nil); r.code != 409 || r.errCode() != "no_passphrase" {
		t.Fatalf("create without passphrase: %d %v", r.code, r.body)
	}
	if r := owner.do("POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": "short"}, nil); r.code != 400 {
		t.Fatalf("weak passphrase: %d %v", r.code, r.body)
	}
	const pass = "a-long-recovery-passphrase-42"
	if r := owner.do("POST", "/api/v1/backups/passphrase", map[string]string{"passphrase": pass}, nil); r.code != 200 {
		t.Fatalf("set passphrase: %d %v", r.code, r.body)
	}
	r := owner.do("GET", "/api/v1/backups/settings", nil, nil)
	if r.body["passphrase_configured"] != true || r.body["storage_warning"] == nil {
		t.Fatalf("settings: %v", r.body)
	}
	// The passphrase is never stored anywhere in the database.
	var n int
	_ = f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM settings WHERE value_json LIKE ?", "%"+pass+"%").Scan(&n)
	var a int
	_ = f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM audit_events WHERE context_json LIKE ?", "%"+pass+"%").Scan(&a)
	if n != 0 || a != 0 {
		t.Fatal("passphrase leaked into settings/audit")
	}

	if r := owner.do("PUT", "/api/v1/backups/schedule", map[string]any{"enabled": true, "interval_hours": 0, "retain": 3}, nil); r.code != 400 {
		t.Fatalf("bad schedule: %d", r.code)
	}
	if r := owner.do("PUT", "/api/v1/backups/schedule", map[string]any{"enabled": true, "interval_hours": 12, "retain": 3}, nil); r.code != 200 {
		t.Fatalf("schedule: %d %v", r.code, r.body)
	}

	// Manual backup → durable job.
	r = owner.do("POST", "/api/v1/backups", nil, nil)
	if r.code != 202 || r.body["job_id"] == nil {
		t.Fatalf("create: %d %v", r.code, r.body)
	}
	j, err := f.jobs.Get(context.Background(), r.body["job_id"].(string))
	if err != nil || j.Kind != jobKindBackup || len(j.LockSet) != 1 || j.LockSet[0] != "backup-restore" {
		t.Fatalf("job: %+v %v", j, err)
	}

	// Write an archive directly (what ngm-ops does) and exercise list/verify/download/delete.
	keys := t.TempDir()
	if err := os.WriteFile(filepath.Join(keys, "kek-1.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	art, err := f.srv.backups().CreateArchive(context.Background(), keys, "test-host", "manual", "")
	if err != nil {
		t.Fatal(err)
	}
	r = owner.do("GET", "/api/v1/backups", nil, nil)
	if items := r.body["items"].([]any); len(items) != 1 {
		t.Fatalf("list: %v", r.body)
	}
	if r := owner.do("POST", "/api/v1/backups/"+art.ID+"/verify", nil, nil); r.code != 200 || r.body["ok"] != true {
		t.Fatalf("verify: %d %v", r.code, r.body)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/backups/"+art.ID+"/download", nil)
	res, err := owner.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || int64(len(body)) != art.Size || !strings.HasPrefix(string(body), "NGMBAK1\n") ||
		!strings.Contains(res.Header.Get("Content-Disposition"), art.FileName) || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("download: %d len=%d hdr=%v", res.StatusCode, len(body), res.Header)
	}

	// Tampered file on disk → verify reports it.
	p := filepath.Join(f.srv.d.Config.Paths.Backups, art.FileName)
	b, _ := os.ReadFile(p)
	b[len(b)-40] ^= 1
	_ = os.WriteFile(p, b, 0o600)
	if r := owner.do("POST", "/api/v1/backups/"+art.ID+"/verify", nil, nil); r.code != 422 || r.errCode() != "backup_invalid" {
		t.Fatalf("tampered verify: %d %v", r.code, r.body)
	}

	if r := owner.do("DELETE", "/api/v1/backups/"+art.ID, nil, nil); r.code != 204 {
		t.Fatalf("delete: %d", r.code)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file not removed")
	}
	if r := owner.do("GET", "/api/v1/backups/"+art.ID+"/download", nil, nil); r.code != 404 {
		t.Fatalf("download deleted: %d", r.code)
	}
}

func TestRecoveryHTTPFlow(t *testing.T) {
	f, ts := setupServer(t)
	owner, _ := enrolOwner(t, ts)
	ctx := context.Background()

	// A job that ended in RecoveryRequired with an open incident.
	j := mustRecoveryJob(t, f)
	iid := ids.New()
	if _, err := f.db.ExecContext(ctx, `INSERT INTO recovery_incidents(id,job_id,status,summary,evidence_json,opened_at) VALUES(?,?,'open','nginx reload outcome unknown','{"code":"x"}',?)`,
		iid, j, store.FormatTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	r := owner.do("GET", "/api/v1/recovery/incidents?status=open", nil, nil)
	items := r.body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["job_kind"] != "deploy.gateway" || len(items[0].(map[string]any)["actions"].([]any)) == 0 {
		t.Fatalf("list: %v", r.body)
	}
	r = owner.do("GET", "/api/v1/recovery/incidents/"+iid, nil, nil)
	if r.body["job"] == nil || r.body["steps"] == nil {
		t.Fatalf("get: %v", r.body)
	}
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", map[string]string{"outcome": "rolled_back", "note": "short"}, nil); r.code != 400 {
		t.Fatalf("note required: %d", r.code)
	}
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", map[string]string{"outcome": "nope", "note": "checked nginx -t and current symlink"}, nil); r.code != 400 {
		t.Fatalf("outcome validated: %d", r.code)
	}
	note := map[string]string{"outcome": "rolled_back", "note": "checked nginx -t and current symlink"}
	// No data-plane evidence → refused.
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", note, nil); r.code != 409 || r.errCode() != "no_evidence" {
		t.Fatalf("no evidence: %d %v", r.code, r.body)
	}
	// Data plane serves something else than the record → refused; detail shows drift.
	observe.Record(ctx, f.db, observe.KindPointer, observe.Pointer{Current: "01SOMEOTHERGENERATION00000"}, 0)
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", note, nil); r.code != 409 || r.errCode() != "active_drift" {
		t.Fatalf("drift: %d %v", r.code, r.body)
	}
	if r := owner.do("GET", "/api/v1/recovery/incidents/"+iid, nil, nil); r.body["drift"] == nil {
		t.Fatalf("detail drift: %v", r.body)
	}
	// Supervised reconcile is queued as a job.
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/reconcile", map[string]string{"mode": "bogus"}, nil); r.code != 400 {
		t.Fatalf("reconcile mode: %d", r.code)
	}
	r = owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/reconcile", map[string]string{"mode": "restore"}, nil)
	if r.code != 202 {
		t.Fatalf("reconcile: %d %v", r.code, r.body)
	}
	if jr, _ := f.jobs.Get(ctx, r.body["job_id"].(string)); jr.Kind != "deploy.reconcile" {
		t.Fatalf("reconcile job kind %s", jr.Kind)
	}
	if r := owner.do("GET", "/api/v1/recovery/drift", nil, nil); r.body["drift"] == nil || r.body["evidence"] != true {
		t.Fatalf("drift endpoint: %v", r.body)
	}
	if r := owner.do("POST", "/api/v1/recovery/reconcile", map[string]string{"mode": "adopt"}, nil); r.code != 202 {
		t.Fatalf("page-level reconcile: %d %v", r.code, r.body)
	}
	// Consistent evidence (nothing recorded, nothing served) → accepted.
	observe.Record(ctx, f.db, observe.KindPointer, observe.Pointer{Current: "empty"}, 0)
	r = owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", note, nil)
	if r.code != 200 || r.body["status"] != "resolved" {
		t.Fatalf("resolve: %d %v", r.code, r.body)
	}
	if jj, _ := f.jobs.Get(ctx, j); jj.State != "RolledBack" {
		t.Fatalf("job state after resolve: %s", jj.State)
	}
	if r := owner.do("POST", "/api/v1/recovery/incidents/"+iid+"/resolve", map[string]string{"outcome": "failed", "note": "checked nginx -t and current symlink"}, nil); r.code != 409 {
		t.Fatalf("double resolve: %d", r.code)
	}
	var n int
	_ = f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events WHERE action='recovery.resolve'").Scan(&n)
	if n != 1 {
		t.Fatal("resolve not audited")
	}
}

// mustRecoveryJob drives a job to RecoveryRequired through valid transitions.
func mustRecoveryJob(t *testing.T, f *fixture) string {
	ctx := context.Background()
	j, _, err := f.jobs.Submit(ctx, jobsSubmit("deploy.gateway"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range [][2]string{{"Queued", "Validating"}, {"Validating", "ImpactAnalyzed"}, {"ImpactAnalyzed", "Staging"}, {"Staging", "Preflight"},
		{"Preflight", "Applying"}, {"Applying", "RecoveryRequired"}} {
		if _, err := f.jobs.Transition(ctx, j.ID, jobsState(s[0]), jobsState(s[1]), jobsOpts()); err != nil {
			t.Fatal(s, err)
		}
	}
	return j.ID
}

func jobsSubmit(kind string) jobs.SubmitRequest {
	return jobs.SubmitRequest{Kind: kind, LockSet: []string{"gateway-config"}}
}
func jobsState(s string) jobs.State { return jobs.State(s) }
func jobsOpts() jobs.TransitionOpts { return jobs.TransitionOpts{} }
