// Command bench is a small closed-loop load generator for NGM capacity
// evidence (MASTER_SPEC §14/§18.13). It reports measured numbers only.
//
//	bench -mode http -url http://127.0.0.1/api/x -host example.com -c 32 -d 20s
//	bench -mode tcp  -addr 127.0.0.1:7000 -c 16 -d 20s      (connect, echo 64 B, close)
//	bench -mode tls  -addr 127.0.0.1:443 -sni x.example -c 16 -d 20s  (full handshake per op)
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	mode := flag.String("mode", "http", "http | tcp | tls")
	url := flag.String("url", "", "HTTP URL")
	host := flag.String("host", "", "HTTP Host header")
	addr := flag.String("addr", "", "tcp/tls address")
	sni := flag.String("sni", "", "TLS SNI")
	c := flag.Int("c", 16, "concurrency")
	d := flag.Duration("d", 20*time.Second, "duration")
	flag.Parse()

	tr := &http.Transport{MaxIdleConnsPerHost: *c, MaxConnsPerHost: *c, DisableCompression: true}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	payload := append(bytes.Repeat([]byte("n"), 63), '\n')
	op := func() error {
		switch *mode {
		case "http":
			req, _ := http.NewRequest("GET", *url, nil)
			if *host != "" {
				req.Host = *host
			}
			res, err := cl.Do(req)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode >= 500 {
				return fmt.Errorf("status %d", res.StatusCode)
			}
			return nil
		case "tcp":
			cn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
			if err != nil {
				return err
			}
			defer cn.Close()
			cn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := cn.Write(payload); err != nil {
				return err
			}
			buf := make([]byte, len(payload))
			_, err = io.ReadFull(cn, buf)
			return err
		case "tls":
			cn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", *addr, &tls.Config{ServerName: *sni, InsecureSkipVerify: true}) // test backend uses a self-signed cert
			if err != nil {
				return err
			}
			return cn.Close()
		}
		return fmt.Errorf("unknown mode")
	}

	var mu sync.Mutex
	var lat []time.Duration
	errs := map[string]int{}
	end := time.Now().Add(*d)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var l []time.Duration
			e := map[string]int{}
			for time.Now().Before(end) {
				t := time.Now()
				if err := op(); err != nil {
					e[errClass(err)]++
					continue
				}
				l = append(l, time.Since(t))
			}
			mu.Lock()
			lat = append(lat, l...)
			for k, v := range e {
				errs[k] += v
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	el := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return float64(lat[int(float64(len(lat)-1)*p)].Microseconds()) / 1000
	}
	ne := 0
	for _, v := range errs {
		ne += v
	}
	out := map[string]any{"mode": *mode, "concurrency": *c, "seconds": el.Seconds(), "ok": len(lat), "errors": ne,
		"ops_per_s": float64(len(lat)) / el.Seconds(), "p50_ms": pct(.5), "p90_ms": pct(.9), "p99_ms": pct(.99), "max_ms": pct(1)}
	if ne > 0 {
		out["error_samples"] = errs
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

// errClass strips addresses so error samples aggregate.
func errClass(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
