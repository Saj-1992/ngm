// Package topology builds the read-only typed graph of the gateway
// (MASTER_SPEC §13.3) and analyses the impact of removing a node. Traffic
// edges (receives, matches, forwards_to, serves) are distinguished from
// dependency edges (uses_certificate, requires_firewall_rule). There is no
// graph editor: changes go through the regular forms and Safe Apply.
package topology

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ngm-gateway/ngm/internal/gateway"
)

// Node is a graph node.
type Node struct {
	ID     string            `json:"id"` // kind:id
	Kind   string            `json:"kind"`
	Label  string            `json:"label"`
	Status string            `json:"status,omitempty"` // observed: healthy | down | unknown | expiring | …
	Attrs  map[string]string `json:"attrs,omitempty"`
}

// Edge is a typed edge.
type Edge struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Type    string `json:"type"`
	Traffic bool   `json:"traffic"`
}

// Graph is the projection returned to clients.
type Graph struct {
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
	Truncated bool   `json:"truncated"`
}

// Observed overlays runtime evidence.
type Observed struct {
	Endpoint map[string]string // endpoint id → health status
	FWRules  []FWRule
	Domains  []string // registered FQDNs
}

// FWRule is a managed firewall rule.
type FWRule struct {
	ID, Key, Proto, State string
	Port                  int
}

// MaxNodes bounds a projection.
const MaxNodes = 2000

// Build creates the graph from a model.
func Build(m *gateway.Model, o Observed) *Graph {
	g := &Graph{}
	seen := map[string]bool{}
	node := func(n Node) {
		if seen[n.ID] || len(g.Nodes) >= MaxNodes {
			if !seen[n.ID] {
				g.Truncated = true
			}
			return
		}
		seen[n.ID] = true
		g.Nodes = append(g.Nodes, n)
	}
	edge := func(from, to, typ string, traffic bool) {
		if seen[from] && seen[to] {
			g.Edges = append(g.Edges, Edge{From: from, To: to, Type: typ, Traffic: traffic})
		}
	}
	for _, l := range m.Listeners {
		st := "enabled"
		if !l.Enabled {
			st = "disabled"
		}
		node(Node{ID: "listener:" + l.ID, Kind: "listener", Label: l.Name, Status: st, Attrs: map[string]string{"bind": l.Address + ":" + strconv.Itoa(l.Port), "kind": l.Kind}})
	}
	for _, c := range m.Certificates {
		node(Node{ID: "certificate:" + c.ID, Kind: "certificate", Label: c.Name, Status: c.Status, Attrs: map[string]string{"expires": c.NotAfter.Format("2006-01-02"), "sans": strings.Join(c.SANs, ", ")}})
	}
	for _, e := range m.Endpoints {
		st := o.Endpoint[e.ID]
		if st == "" {
			st = "unknown"
		}
		if e.Disabled {
			st = "disabled"
		}
		node(Node{ID: "endpoint:" + e.ID, Kind: "endpoint", Label: e.Name, Status: st, Attrs: map[string]string{"target": e.Host + ":" + strconv.Itoa(e.Port), "transport": e.Transport}})
	}
	for _, p := range m.Pools {
		node(Node{ID: "pool:" + p.ID, Kind: "pool", Label: p.Name, Attrs: map[string]string{"strategy": p.Strategy}})
		for _, mem := range p.Members {
			edge("pool:"+p.ID, "endpoint:"+mem.EndpointID, "forwards_to", true)
		}
	}
	for _, w := range m.Websites {
		st := "unpublished"
		if w.Published {
			st = "published"
		}
		node(Node{ID: "website:" + w.ID, Kind: "website", Label: w.Name, Status: st})
	}
	doms := append([]string(nil), o.Domains...)
	sort.Slice(doms, func(i, j int) bool { return len(doms[i]) > len(doms[j]) }) // most specific first
	for _, r := range m.Routes {
		st := "enabled"
		if !r.Enabled {
			st = "disabled"
		}
		var names []string
		for _, mt := range r.Matches {
			names = append(names, mt.Field+"="+mt.Value)
		}
		node(Node{ID: "route:" + r.ID, Kind: "route", Label: r.Name, Status: st, Attrs: map[string]string{"protocol": r.Protocol, "matches": strings.Join(names, " ")}})
		edge("listener:"+r.ListenerID, "route:"+r.ID, "matches", true)
		switch r.DestKind {
		case gateway.DestPool:
			edge("route:"+r.ID, "pool:"+r.DestID, "forwards_to", true)
		case gateway.DestEndpoint:
			edge("route:"+r.ID, "endpoint:"+r.DestID, "forwards_to", true)
		case gateway.DestWebsite:
			edge("route:"+r.ID, "website:"+r.DestID, "serves", true)
		}
		if r.CertificateID != "" {
			edge("route:"+r.ID, "certificate:"+r.CertificateID, "uses_certificate", false)
		}
		for _, mt := range r.Matches {
			if mt.Field != gateway.FieldHost && mt.Field != gateway.FieldSNI {
				continue
			}
			v := strings.TrimPrefix(strings.ToLower(mt.Value), "*.")
			for _, d := range doms {
				if v == d || strings.HasSuffix(v, "."+d) {
					node(Node{ID: "domain:" + d, Kind: "domain", Label: d})
					edge("domain:"+d, "route:"+r.ID, "receives", true)
					break
				}
			}
		}
	}
	for _, f := range o.FWRules {
		node(Node{ID: "firewall_rule:" + f.ID, Kind: "firewall_rule", Label: "ngm:" + f.Key, Status: f.State, Attrs: map[string]string{"port": strconv.Itoa(f.Port) + "/" + f.Proto}})
		for _, l := range m.Listeners {
			if l.Port == f.Port {
				edge("listener:"+l.ID, "firewall_rule:"+f.ID, "requires_firewall_rule", false)
			}
		}
	}
	// Listeners on public addresses without an allowing firewall rule are
	// reported (only when NGM manages firewall rules at all).
	return g
}

// Impact describes what depends on a node.
type Impact struct {
	Node     string   `json:"node"`
	Affected []Node   `json:"affected"`
	Critical []string `json:"critical"` // blocking dependencies
}

// Analyze lists every node upstream of target in the traffic graph and
// flags routes that would lose their only destination.
func Analyze(g *Graph, target string) Impact {
	in := map[string][]Edge{}
	for _, e := range g.Edges {
		in[e.To] = append(in[e.To], e)
	}
	byID := map[string]Node{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	imp := Impact{Node: target, Affected: []Node{}, Critical: []string{}}
	visited := map[string]bool{target: true}
	queue := []string{target}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range in[cur] {
			if visited[e.From] {
				continue
			}
			visited[e.From] = true
			n := byID[e.From]
			imp.Affected = append(imp.Affected, n)
			switch {
			case e.Type == "uses_certificate":
				imp.Critical = append(imp.Critical, "route "+n.Label+" uses this certificate")
			case e.Type == "forwards_to" || e.Type == "serves":
				if n.Kind == "route" {
					imp.Critical = append(imp.Critical, "route "+n.Label+" would lose its destination")
				} else if n.Kind == "pool" && countOut(g, n.ID) == 1 {
					imp.Critical = append(imp.Critical, "pool "+n.Label+" would have no members")
				}
			}
			queue = append(queue, e.From)
		}
	}
	return imp
}

func countOut(g *Graph, id string) int {
	n := 0
	for _, e := range g.Edges {
		if e.From == id && e.Traffic {
			n++
		}
	}
	return n
}
