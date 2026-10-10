package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ngm-gateway/ngm/internal/store"
)

func newService(t *testing.T) (*Service, *host) {
	h := newHost(t)
	k := fastKDF()
	s := &Service{DB: h.db, Vault: h.v, Dir: t.TempDir(), KDF: &k}
	if err := s.SetPassphrase(context.Background(), "a-long-test-passphrase-123"); err != nil {
		t.Fatal(err)
	}
	return s, h
}

func TestArchivesInTheSameSecondDoNotCollide(t *testing.T) {
	s, h := newService(t)
	for i := 0; i < 3; i++ {
		if _, err := s.CreateArchive(context.Background(), h.keys, "host", "manual", ""); err != nil {
			t.Fatalf("archive %d: %v", i, err)
		}
	}
	if l, _ := s.List(context.Background()); len(l) != 3 {
		t.Fatalf("want 3 archives, got %d", len(l))
	}
}

func TestRetentionKeepsNewestAndSafetySnapshots(t *testing.T) {
	s, h := newService(t)
	ctx := context.Background()
	mk := func(trigger string, age time.Duration) string {
		a, err := s.CreateArchive(ctx, h.keys, "host", trigger, "")
		if err != nil {
			t.Fatal(err)
		}
		s.DB.ExecContext(ctx, "UPDATE backup_artifacts SET created_at=? WHERE id=?", store.FormatTime(time.Now().Add(-age)), a.ID)
		return a.ID
	}
	old1 := mk("scheduled", 5*time.Hour)
	old2 := mk("manual", 4*time.Hour)
	keep1 := mk("scheduled", 3*time.Hour)
	keep2 := mk("scheduled", 2*time.Hour)
	recentPre := mk("pre_restore", 10*24*time.Hour)
	stalePre := mk("pre_restore", 40*24*time.Hour)
	n, err := s.ApplyRetention(ctx, 2)
	if err != nil || n != 3 {
		t.Fatalf("removed %d err %v", n, err)
	}
	left := map[string]bool{}
	l, _ := s.List(ctx)
	for _, a := range l {
		left[a.ID] = true
		if _, err := os.Stat(filepath.Join(s.Dir, a.FileName)); err != nil {
			t.Fatalf("kept record without file: %v", err)
		}
	}
	if !left[keep1] || !left[keep2] || !left[recentPre] || left[old1] || left[old2] || left[stalePre] {
		t.Fatalf("retention result %v", left)
	}
}

func TestScheduleValidationAndDefaults(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	if sc := s.GetSchedule(ctx); sc.Enabled || sc.IntervalHours != 24 || sc.Retain != 7 {
		t.Fatalf("defaults %+v", sc)
	}
	for _, bad := range []Schedule{{IntervalHours: 0, Retain: 1}, {IntervalHours: 721, Retain: 1}, {IntervalHours: 1, Retain: 0}, {IntervalHours: 1, Retain: 366}} {
		if s.SetSchedule(ctx, bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := s.SetSchedule(ctx, Schedule{Enabled: true, IntervalHours: 6, Retain: 3}); err != nil || s.GetSchedule(ctx).IntervalHours != 6 {
		t.Fatal(err)
	}
}
