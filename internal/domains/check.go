package domains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/dnsq"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Querier is the DNS transport (dnsq.Client in production, fakes in tests).
type Querier interface {
	Query(ctx context.Context, server, name string, qtype uint16, recursion bool) (*dnsq.Response, error)
}

// Checker observes DNS for registered domains.
type Checker struct {
	DB *store.DB
	Q  Querier
	// Resolvers are recursive resolvers (default: /etc/resolv.conf).
	Resolvers []string
	Now       func() time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) resolvers() []string {
	if len(c.Resolvers) > 0 {
		return c.Resolvers
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		if r := dnsq.SystemResolvers(string(b)); len(r) > 0 {
			return r
		}
	}
	return []string{"127.0.0.53"}
}

// recursive asks the configured resolvers in order.
func (c *Checker) recursive(ctx context.Context, name string, t uint16) (*dnsq.Response, string, error) {
	var last error
	for _, r := range c.resolvers() {
		resp, err := c.Q.Query(ctx, r, name, t, true)
		if err == nil && resp.Rcode != "SERVFAIL" && resp.Rcode != "REFUSED" {
			return resp, r, nil
		}
		if err == nil {
			err = errors.New(resp.Rcode)
		}
		last = err
	}
	return nil, "", fmt.Errorf("no resolver answered: %v", last)
}

// Zone describes where authoritative answers come from.
type Zone struct {
	Apex    string   `json:"apex"`
	NS      []string `json:"nameservers"`
	Servers []string `json:"server_addresses"`
}

// FindZone walks up from name until a SOA owner is found, then resolves the
// zone's nameserver addresses.
func (c *Checker) FindZone(ctx context.Context, name string) (*Zone, error) {
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		cand := strings.Join(labels[i:], ".")
		r, _, err := c.recursive(ctx, cand, dnsq.TypeSOA)
		if err != nil {
			return nil, err
		}
		for _, a := range r.Answers {
			if a.Type == "SOA" && a.Name == cand {
				z := &Zone{Apex: cand}
				nr, _, err := c.recursive(ctx, cand, dnsq.TypeNS)
				if err != nil {
					return nil, err
				}
				for _, n := range nr.Answers {
					if n.Type == "NS" {
						z.NS = append(z.NS, n.Value)
					}
				}
				sort.Strings(z.NS)
				for _, ns := range z.NS {
					ar, _, err := c.recursive(ctx, ns, dnsq.TypeA)
					if err != nil {
						continue
					}
					for _, a := range ar.Answers {
						if a.Type == "A" {
							z.Servers = append(z.Servers, a.Value)
							break
						}
					}
				}
				if len(z.Servers) == 0 {
					return nil, fmt.Errorf("cannot resolve any nameserver of %s", cand)
				}
				return z, nil
			}
		}
	}
	return nil, fmt.Errorf("no DNS zone found for %s", name)
}

type key struct{ name, t string }

// targets: every expectation plus the domain's A/AAAA/NS/CAA (CAA decides
// whether an ACME CA may issue for the domain).
func targets(d *Domain) []key {
	seen := map[key]bool{}
	var out []key
	add := func(k key) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, t := range []string{"A", "AAAA", "NS", "CAA"} {
		add(key{d.FQDN, t})
	}
	for _, e := range d.Expected {
		add(key{e.Name, e.Type})
	}
	return out
}

func valuesOf(r *dnsq.Response, name, t string) ([]string, *int) {
	vals := []string{}
	var ttl *int
	for _, a := range r.Answers {
		if a.Type == t && a.Name == name {
			vals = append(vals, a.Value)
			v := int(a.TTL)
			if ttl == nil || v < *ttl {
				ttl = &v
			}
		}
	}
	// A CNAME at the name answers for every type; record it for clarity.
	if len(vals) == 0 && t != "CNAME" {
		for _, a := range r.Answers {
			if a.Type == "CNAME" && a.Name == name {
				vals = append(vals, "CNAME "+a.Value)
			}
		}
	}
	sort.Strings(vals)
	return vals, ttl
}

// Check observes one domain and stores the evidence.
func (c *Checker) Check(ctx context.Context, d *Domain) error {
	zone, zerr := c.FindZone(ctx, d.FQDN)
	at := store.FormatTime(c.now())
	put := func(k key, src, server string, vals []string, ttl *int, rcode, errS string) error {
		vj, _ := json.Marshal(vals)
		var t any
		if ttl != nil {
			t = *ttl
		}
		_, err := c.DB.ExecContext(ctx, `INSERT INTO dns_observations(domain_id,name,rtype,source,server,values_json,ttl,rcode,error,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(domain_id,name,rtype,source) DO UPDATE SET server=excluded.server, values_json=excluded.values_json, ttl=excluded.ttl, rcode=excluded.rcode,
			error=excluded.error, observed_at=excluded.observed_at`, d.ID, k.name, k.t, src, server, string(vj), t, rcode, errS, at)
		return err
	}
	for _, k := range targets(d) {
		qt := dnsq.TypeByName[k.t]
		// Authoritative: ask the zone's servers directly without recursion.
		if zerr != nil {
			if err := put(k, "authoritative", "", nil, nil, "", zerr.Error()); err != nil {
				return err
			}
		} else {
			var resp *dnsq.Response
			var server string
			var last error
			for _, s := range zone.Servers {
				r, err := c.Q.Query(ctx, s, k.name, qt, false)
				if err == nil && r.Authoritative {
					resp, server = r, s
					break
				}
				if err == nil {
					err = fmt.Errorf("%s answered without authority (%s)", s, r.Rcode)
				}
				last = err
			}
			if resp == nil {
				if err := put(k, "authoritative", strings.Join(zone.Servers, ","), nil, nil, "", errText(last)); err != nil {
					return err
				}
			} else {
				vals, ttl := valuesOf(resp, k.name, k.t)
				if err := put(k, "authoritative", server, vals, ttl, resp.Rcode, ""); err != nil {
					return err
				}
			}
		}
		// Resolver view (what clients see now, including cache).
		r, server, err := c.recursive(ctx, k.name, qt)
		if err != nil {
			if err := put(k, "resolver", "", nil, nil, "", err.Error()); err != nil {
				return err
			}
			continue
		}
		vals, ttl := valuesOf(r, k.name, k.t)
		if err := put(k, "resolver", server, vals, ttl, r.Rcode, ""); err != nil {
			return err
		}
	}
	return nil
}

func errText(err error) string {
	if err == nil {
		return "no answer"
	}
	return err.Error()
}

// CheckAll observes every registered domain (bounded per run).
func (c *Checker) CheckAll(ctx context.Context, reg *Service) (int, error) {
	ds, err := reg.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d0 := range ds {
		d, err := reg.Get(ctx, d0.ID)
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		if err := c.Check(cctx, d); err == nil {
			n++
		}
		cancel()
	}
	return n, nil
}

// CAAAllows reports whether the CAA evidence allows caDomain (e.g.
// "letsencrypt.org") to issue for the domain. No CAA records = allowed.
// Only the domain's own CAA set is considered (no tree climbing).
func CAAAllows(caa []string, caDomain string, wildcard bool) bool {
	var issue, issuewild []string
	for _, v := range caa {
		f := strings.SplitN(v, " ", 3)
		if len(f) != 3 {
			continue
		}
		val := strings.Trim(f[2], `"`)
		val = strings.TrimSpace(strings.SplitN(val, ";", 2)[0])
		switch strings.ToLower(f[1]) {
		case "issue":
			issue = append(issue, val)
		case "issuewild":
			issuewild = append(issuewild, val)
		}
	}
	set := issue
	if wildcard && len(issuewild) > 0 {
		set = issuewild
	}
	if len(set) == 0 {
		return true
	}
	for _, v := range set {
		if strings.EqualFold(v, caDomain) {
			return true
		}
	}
	return false
}
