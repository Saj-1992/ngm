// Command vulncheck is an offline stand-in for govulncheck when vuln.go.dev is
// unreachable: it matches the OSV records of the Go vulnerability database
// (github.com/golang/vulndb data/osv) against the modules linked into a
// binary and the Go version, and marks a finding "imported" when an affected
// package is in the binary's import graph. It does not do symbol-level
// reachability (govulncheck does), so it can only over-report.
//
//	go run ./scripts/vulncheck -osv DIR -bin dist/ngm-linux-amd64 -deps deps.txt
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type osv struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		Eco struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
	Withdrawn string `json:"withdrawn"`
}

func v(s string) string {
	if s == "" || s == "0" {
		return "v0.0.0"
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	return s
}

func affected(ver string, a []struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}) bool {
	in := false
	for _, e := range a {
		if e.Introduced != "" && cmpVer(ver, v(e.Introduced)) >= 0 {
			in = true
		}
		if e.Fixed != "" && cmpVer(ver, v(e.Fixed)) >= 0 {
			in = false
		}
	}
	return in
}

func main() {
	dir := flag.String("osv", "", "directory with GO-*.json OSV files")
	bin := flag.String("bin", "", "Go binary to inspect (modules + Go version)")
	depsFile := flag.String("deps", "", "file with `go list -deps` output (imported packages)")
	flag.Parse()
	out, err := exec.Command("go", "version", "-m", *bin).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "go version -m:", err)
		os.Exit(2)
	}
	mods := map[string]string{}
	for i, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if i == 0 && len(f) >= 2 {
			mods["stdlib"] = "v" + strings.TrimPrefix(f[len(f)-1], "go")
		}
		if len(f) >= 3 && (f[0] == "dep" || f[0] == "=>") {
			mods[f[1]] = f[2]
		}
	}
	imported := map[string]bool{}
	if fh, err := os.Open(*depsFile); err == nil {
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			imported[strings.TrimSpace(sc.Text())] = true
		}
		fh.Close()
	}
	files, _ := filepath.Glob(filepath.Join(*dir, "GO-*.json"))
	var found []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		var o osv
		if json.Unmarshal(b, &o) != nil || o.Withdrawn != "" {
			continue
		}
		for _, a := range o.Affected {
			ver, ok := mods[a.Package.Name]
			if !ok {
				continue
			}
			hit := false
			for _, r := range a.Ranges {
				if r.Type == "SEMVER" && affected(ver, r.Events) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			reach := "module only"
			for _, im := range a.Eco.Imports {
				if imported[im.Path] {
					reach = "IMPORTED " + im.Path
					break
				}
			}
			if len(a.Eco.Imports) == 0 {
				reach = "module-wide"
			}
			found = append(found, fmt.Sprintf("%s  %s@%s  [%s]  %s", o.ID, a.Package.Name, ver, reach, o.Summary))
		}
	}
	sort.Strings(found)
	fmt.Printf("checked %d OSV records against %d modules (Go %s)\n", len(files), len(mods), mods["stdlib"])
	for _, s := range found {
		fmt.Println(s)
	}
	fmt.Printf("%d affected entries\n", len(found))
	for _, s := range found {
		if strings.Contains(s, "IMPORTED") || strings.Contains(s, "module-wide") {
			os.Exit(1)
		}
	}
}

// cmpVer compares Go module/semver versions (vMAJOR.MINOR.PATCH[-pre]);
// a pre-release (incl. pseudo-versions) sorts before its release.
func cmpVer(a, b string) int {
	pa, qa, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	pb, qb, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	na, nb := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < 3; i++ {
		x, y := 0, 0
		if i < len(na) {
			x, _ = strconv.Atoi(na[i])
		}
		if i < len(nb) {
			y, _ = strconv.Atoi(nb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case qa == qb:
		return 0
	case qa == "":
		return 1
	case qb == "":
		return -1
	case qa < qb:
		return -1
	}
	return 1
}
