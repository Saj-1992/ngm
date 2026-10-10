package app

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/ngm-gateway/ngm/internal/buildinfo"
	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/logs"
	"github.com/ngm-gateway/ngm/internal/observe"
	"github.com/ngm-gateway/ngm/internal/perf"
)

// KindLogPipeline is the observation describing the log pipeline.
const KindLogPipeline = "log_pipeline"

// LogPipeline is the indexer status (lag, pause reason, sizes).
type LogPipeline struct {
	Sources    []logs.SourceStatus `json:"sources"`
	Paused     bool                `json:"paused"`
	Reason     string              `json:"reason,omitempty"`
	Indexed    int                 `json:"indexed_last_pass"`
	LastPass   time.Time           `json:"last_pass"`
	IndexBytes int64               `json:"index_bytes"`
	FreeBytes  uint64              `json:"free_bytes"`
}

// LogIndexPath is the rebuildable index location.
func LogIndexPath(cfg config.Config) string {
	return filepath.Join(cfg.Paths.StateDir, "logindex", "index.db")
}

// LogSources lists what the indexer reads.
func LogSources(cfg config.Config) []logs.Source {
	nd := filepath.Join(cfg.Paths.LogDir, "nginx")
	ad := filepath.Join(cfg.Paths.LogDir, "app")
	return []logs.Source{
		{Path: filepath.Join(nd, "access.jsonl"), Kind: "http"},
		{Path: filepath.Join(nd, "stream.jsonl"), Kind: "stream"},
		{Path: filepath.Join(nd, "error.log"), Kind: "error"},
		{Path: filepath.Join(ad, "api.jsonl"), Kind: "app", Cat: "api"},
		{Path: filepath.Join(ad, "ops.jsonl"), Kind: "app", Cat: "ops"},
		{Path: filepath.Join(ad, "monitor.jsonl"), Kind: "app", Cat: "monitor"},
	}
}

// Disk guard: below either threshold, ingestion pauses (sources keep being
// rotated by logrotate; nothing else is deleted).
const (
	minFreeBytes   = 512 << 20
	minFreePercent = 5
	maxIndexRows   = 5_000_000
)

// RunLogIndexer collects logs into the search index.
func RunLogIndexer(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	ix, err := logs.Open(LogIndexPath(cfg))
	if err != nil {
		return err
	}
	defer ix.Close()
	col := &logs.Collector{Ix: ix, Sources: LogSources(cfg), MaxBatch: 5000}
	log.Info("ngm log-indexer started", "version", buildinfo.Version, "index", ix.Path)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var lastDB, lastPrune time.Time
	_ = observe.Heartbeat(ctx, db, "ngm-log-indexer", "healthy", buildinfo.Version)
	lastHB := time.Now()
	for {
		select {
		case <-ctx.Done():
			_ = observe.Heartbeat(context.Background(), db, "ngm-log-indexer", "down", "stopped")
			return nil
		case <-tick.C:
		}
		st := LogPipeline{LastPass: time.Now().UTC(), IndexBytes: fileSize(ix.Path) + fileSize(ix.Path+"-wal")}
		free, total, derr := diskFree(filepath.Dir(ix.Path))
		st.FreeBytes = free
		if derr == nil && (free < minFreeBytes || total > 0 && free*100/total < minFreePercent) {
			st.Paused, st.Reason = true, "low disk space: ingestion paused (source logs are kept and rotated; nothing is deleted)"
		}
		if !st.Paused {
			sts, n, _ := col.Pass(ctx)
			st.Sources, st.Indexed = sts, n
			if time.Since(lastDB) > 10*time.Second {
				lastDB = time.Now()
				if k, err := col.DBSources(ctx, db.DB); err != nil {
					log.Warn("log indexer: database sources", "err", err)
				} else {
					st.Indexed += k
				}
			}
		}
		if time.Since(lastPrune) > time.Hour {
			lastPrune = time.Now()
			if n, err := ix.Prune(ctx, time.Now(), maxIndexRows); err != nil {
				log.Warn("log indexer: prune", "err", err)
			} else if n > 0 {
				log.Info("log index pruned", "rows", n)
			}
		}
		ix.ShareWithGroup()
		_ = observe.Record(ctx, db, KindLogPipeline, st, 30*time.Second)
		if time.Since(lastHB) > 20*time.Second {
			lastHB = time.Now()
			if b := perf.Current(ctx, db).Internal.LogBatch; b > 0 {
				col.MaxBatch = b // adaptive perf profile
			}
			status := "healthy"
			detail := buildinfo.Version
			if st.Paused {
				status, detail = "degraded", st.Reason
			}
			_ = observe.Heartbeat(ctx, db, "ngm-log-indexer", status, detail)
		}
	}
}
