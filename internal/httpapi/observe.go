package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/ngm-gateway/ngm/internal/monitor"
	"github.com/ngm-gateway/ngm/internal/observe"
)

// nginxStaleAfter bounds how old a data-plane observation may be before the
// dashboard reports Unknown.
const nginxStaleAfter = 2 * time.Minute

// backendsComponent summarises backend health evidence. A down backend
// degrades the gateway (it is not an NGM failure); missing evidence is Unknown.
func (s *Server) backendsComponent(ctx context.Context, now time.Time) (component, bool) {
	if s.d.GW == nil {
		return component{}, false
	}
	eps, err := s.d.GW.ListEndpoints(ctx)
	if err != nil || len(eps) == 0 {
		return component{}, false
	}
	hs, err := monitor.Latest(ctx, s.d.DB, eps)
	if err != nil {
		return component{}, false
	}
	n := map[string]int{}
	for _, h := range hs {
		n[h.Status]++
	}
	c := component{Name: "backends", ObservedAt: now,
		Detail: fmt.Sprintf("%d healthy, %d degraded, %d down, %d unknown, %d disabled", n[Healthy], n[Degraded], n[Down], n[Unknown], n[Disabled])}
	switch {
	case n[Down] > 0 || n[Degraded] > 0:
		c.Status = Degraded
	case n[Unknown] > 0:
		c.Status = Unknown
	default:
		c.Status = Healthy
	}
	return c, true
}

func (s *Server) nginxComponent(ctx context.Context, now time.Time) component {
	c := component{Name: "nginx", Status: Unknown, Detail: "no runtime observation available", ObservedAt: now}
	var n observe.Nginx
	at, err := observe.Latest(ctx, s.d.DB, observe.KindNginx, &n)
	if err != nil {
		return c
	}
	c.ObservedAt = at
	if now.Sub(at) > nginxStaleAfter {
		c.Detail = "observation stale since " + at.UTC().Format(time.RFC3339)
		return c
	}
	switch {
	case !n.Installed:
		c.Status, c.Detail = Unknown, "nginx is not installed"
	case n.ServiceState == "active":
		c.Status, c.Detail = Healthy, "nginx "+n.Version+" active"
		if !n.StreamModule {
			c.Status, c.Detail = Degraded, "nginx "+n.Version+" active; stream module missing"
		}
	case n.ServiceState == "failed" || n.ServiceState == "inactive":
		c.Status, c.Detail = Down, "nginx service "+n.ServiceState
	default:
		c.Status, c.Detail = Unknown, "nginx service state "+n.ServiceState
	}
	return c
}
