package httpapi

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/ngm-gateway/ngm"

// forbiddenInAPI are imports that would let request handlers run system
// commands (MASTER_SPEC §12: "API must never execute direct Nginx/UFW/system
// commands in request handlers").
var forbiddenInAPI = map[string]bool{"os/exec": true, "syscall": false, "plugin": true}

// TestNoExecInAPIDependencyGraph walks the module-internal transitive import
// graph of this package and fails if any reachable package imports os/exec.
func TestNoExecInAPIDependencyGraph(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var walk func(pkg string, chain []string)
	walk = func(pkg string, chain []string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, modulePath)))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if forbiddenInAPI[p] {
					t.Errorf("%s imports %s (via %s)", pkg, p, strings.Join(append(chain, pkg), " -> "))
				}
				if strings.HasPrefix(p, modulePath+"/") {
					walk(p, append(chain, pkg))
				}
			}
		}
	}
	walk(modulePath+"/internal/httpapi", nil)
	if len(seen) < 5 {
		t.Fatalf("walked only %d packages; walker broken?", len(seen))
	}
}
