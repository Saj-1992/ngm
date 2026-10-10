package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/installer"
	"github.com/ngm-gateway/ngm/internal/release"
)

// Repair re-verifies the current release and re-runs its idempotent install
// (directories, modes, accounts, units, hooks of the installer, health).
// A release whose binary no longer matches its signed manifest is never run.
func Repair(ctx context.Context, cfg config.Config, logf Logger) error {
	rel, err := filepath.EvalSymlinks(cfg.Paths.Current)
	if err != nil {
		return fmt.Errorf("current release pointer is broken (%v); reinstall from a signed release", err)
	}
	bin := filepath.Join(rel, "ngm")
	if _, err := os.Stat(filepath.Join(rel, "manifest.json")); err == nil {
		keys, err := release.Trusted()
		if err != nil {
			return err
		}
		m, _, err := release.LoadDir(rel, keys)
		if err != nil {
			return fmt.Errorf("release %s: %w", filepath.Base(rel), err)
		}
		a, err := m.ArtifactFor(runtime.GOARCH)
		if err != nil {
			return err
		}
		if err := release.CheckFile(bin, a); err != nil {
			return fmt.Errorf("%w: %s was modified after installation; reinstall from a signed release", err, bin)
		}
		logf("release %s verified against its signed manifest (%s)", m.Version, m.KeyID)
	} else {
		logf("warning: release %s has no signed manifest (development install); binary integrity cannot be verified", filepath.Base(rel))
	}
	out, err := runLog(ctx, filepath.Join(cfg.Paths.StateDir, "update", "repair.log"), bin, installArgs(rel)...)
	if err != nil {
		return errors.New(lastLine(out, err))
	}
	if err := installer.WaitHealthy(ctx, cfg.API.Listen, 60*time.Second); err != nil {
		return err
	}
	logf("repair complete: directories, permissions, accounts and units re-applied; services healthy")
	return nil
}
