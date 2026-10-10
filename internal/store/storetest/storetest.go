// Package storetest provides migrated temporary databases for tests.
package storetest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ngm-gateway/ngm/internal/store"
)

// New returns a fresh, fully migrated database that is closed on test cleanup.
func New(t testing.TB) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ngm.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}
