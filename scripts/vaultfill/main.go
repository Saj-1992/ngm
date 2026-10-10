// Command vaultfill seeds, verifies or removes test-only vault secrets
// (type notification, scope fill-test) so a KEK rotation can be interrupted inside its rewrap
// window (O-13). Run as root on the test VM only.
//
//	vaultfill -n 20000 fill | verify | clean
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ngm-gateway/ngm/internal/config"
	"github.com/ngm-gateway/ngm/internal/store"
	"github.com/ngm-gateway/ngm/internal/vault"
)

func main() {
	n := flag.Int("n", 20000, "number of secrets")
	flag.Parse()
	cfg, err := config.Load(config.DefaultPath)
	must(err)
	ctx := context.Background()
	db, err := store.Open(cfg.DBPath(), store.Options{})
	must(err)
	defer db.Close()
	kr, err := vault.LoadDir(cfg.Paths.KeysDir)
	must(err)
	v := vault.New(db, kr)
	ref := func(i int) vault.Ref {
		return vault.Ref{Type: "notification", Scope: "fill-test", Name: fmt.Sprintf("s%06d", i)}
	}
	switch flag.Arg(0) {
	case "fill":
		for i := 0; i < *n; i++ {
			_, err := v.Put(ctx, ref(i), []byte(fmt.Sprintf("value-%06d", i)))
			must(err)
		}
		fmt.Println("filled", *n)
	case "verify":
		bad := 0
		for i := 0; i < *n; i++ {
			b, err := v.Get(ctx, ref(i))
			if err != nil || string(b) != fmt.Sprintf("value-%06d", i) {
				bad++
			}
		}
		var vers string
		_ = db.QueryRowContext(ctx, "SELECT group_concat(kek_version || ':' || c) FROM (SELECT kek_version, COUNT(*) c FROM vault_secrets GROUP BY kek_version)").Scan(&vers)
		fmt.Printf("verified %d, bad %d, rows per KEK version %s\n", *n, bad, vers)
		if bad > 0 {
			os.Exit(1)
		}
	case "clean":
		res, err := db.ExecContext(ctx, "DELETE FROM vault_secrets WHERE type='notification' AND scope='fill-test'")
		must(err)
		c, _ := res.RowsAffected()
		fmt.Println("removed", c)
	default:
		fmt.Fprintln(os.Stderr, "usage: vaultfill [-n N] fill|verify|clean")
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
