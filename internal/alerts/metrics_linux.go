//go:build linux

package alerts

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sampler computes CPU usage from /proc/stat deltas.
type Sampler struct{ prevIdle, prevTotal uint64 }

// Sample reads /proc and statfs(root).
func (s *Sampler) Sample(root string) (Metrics, error) {
	m := Metrics{At: time.Now().UTC(), CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i, v := range f[1:] {
			x, _ := strconv.ParseUint(v, 10, 64)
			total += x
			if i == 3 || i == 4 {
				idle += x
			}
		}
		if s.prevTotal > 0 && total > s.prevTotal {
			m.CPUPct = 100 * (1 - float64(idle-s.prevIdle)/float64(total-s.prevTotal))
		}
		s.prevIdle, s.prevTotal = idle, total
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		m.Load1, _ = strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				avail = v * 1024
			}
		}
		m.MemTotal, m.MemUsed = total, total-avail
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		return m, err
	}
	m.DiskTotal = st.Blocks * uint64(st.Bsize)
	m.DiskUsed = m.DiskTotal - st.Bavail*uint64(st.Bsize)
	return m, nil
}
