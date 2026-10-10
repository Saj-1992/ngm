package ids

import (
	"testing"
	"time"
)

func TestSortableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	prev := ""
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2000; i++ {
		id := At(base.Add(time.Duration(i) * time.Millisecond))
		if !Valid(id) {
			t.Fatalf("invalid id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate %q", id)
		}
		seen[id] = true
		if id <= prev {
			t.Fatalf("not sortable: %q <= %q", id, prev)
		}
		prev = id
	}
}

func TestValidRejects(t *testing.T) {
	for _, s := range []string{"", "abc", "01ARZ3NDEKTSV4RRFFQ69G5FAU", "../../etc/passwd0000000000", "81ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}

func TestNewIsStrictlyMonotonic(t *testing.T) {
	prev := ""
	for i := 0; i < 50000; i++ {
		id := New()
		if id <= prev {
			t.Fatalf("New not monotonic at %d: %q <= %q", i, id, prev)
		}
		prev = id
	}
}
