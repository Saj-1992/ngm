package deploy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/cloudflare"
)

// cfDNSSolver implements certauto.DNSSolver with Cloudflare DNS, for ACME
// DNS-01 (the only way to obtain wildcard certificates). It marks the TXT
// records it creates and removes them afterwards. DNS is not instant, so
// Propagated polls public resolvers until the record is visible (bounded).
type cfDNSSolver struct {
	cl       *cloudflare.Client
	resolver *net.Resolver
	created  map[string]struct{ zone, id string }
	wait     time.Duration
	poll     time.Duration
}

func newCFDNSSolver(cl *cloudflare.Client) *cfDNSSolver {
	return &cfDNSSolver{cl: cl, resolver: net.DefaultResolver, created: map[string]struct{ zone, id string }{}, wait: 3 * time.Minute, poll: 5 * time.Second}
}

func (s *cfDNSSolver) baseName(fqdn string) string {
	return strings.TrimPrefix(strings.TrimSuffix(fqdn, "."), "_acme-challenge.")
}

func (s *cfDNSSolver) PresentTXT(ctx context.Context, fqdn, value string) error {
	z, err := s.cl.FindZone(ctx, s.baseName(fqdn))
	if err != nil {
		return err
	}
	id, err := s.cl.UpsertTXT(ctx, z.ID, fqdn, value)
	if err != nil {
		return err
	}
	s.created[fqdn+"|"+value] = struct{ zone, id string }{z.ID, id}
	return nil
}

func (s *cfDNSSolver) CleanupTXT(ctx context.Context, fqdn, value string) error {
	c, ok := s.created[fqdn+"|"+value]
	if !ok {
		return nil
	}
	return s.cl.DeleteRecord(ctx, c.zone, c.id)
}

func (s *cfDNSSolver) Propagated(ctx context.Context, fqdn, value string) error {
	name := strings.TrimSuffix(fqdn, ".")
	deadline := time.Now().Add(s.wait)
	for {
		if txts, err := s.resolver.LookupTXT(ctx, name); err == nil {
			for _, t := range txts {
				if t == value {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT record not visible after %s", s.wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.poll):
		}
	}
}

func chalName(dns01 bool) string {
	if dns01 {
		return "dns-01"
	}
	return "http-01"
}
