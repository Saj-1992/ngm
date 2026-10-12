// Command starter prints a template's starter content as JSON (development aid):
//
//	go run ./scripts/ops/starter corporate
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ngm-gateway/ngm/internal/sitebuild"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: starter <template>")
		os.Exit(2)
	}
	json.NewEncoder(os.Stdout).Encode(sitebuild.Starter(os.Args[1]))
}
