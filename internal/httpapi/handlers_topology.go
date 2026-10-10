package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/ngm-gateway/ngm/internal/apierr"
	"github.com/ngm-gateway/ngm/internal/gateway"
	"github.com/ngm-gateway/ngm/internal/topology"
)

func (s *Server) registerTopologyRoutes() {
	s.handle("GET", "/api/v1/topology", "topology.read", s.getTopology)
	s.handle("GET", "/api/v1/topology/impact", "topology.read", s.getImpact)
}

func (s *Server) topologyGraph(r *http.Request) (*topology.Graph, error) {
	ctx := r.Context()
	var m *gateway.Model
	switch r.URL.Query().Get("view") {
	case "active":
		var mj string
		err := s.d.DB.QueryRowContext(ctx, `SELECT d.model_json FROM active_state a JOIN config_generations g ON g.id=a.generation_id JOIN desired_revisions d ON d.id=g.desired_revision_id WHERE a.id=1`).Scan(&mj)
		if err != nil {
			return &topology.Graph{Nodes: []topology.Node{}, Edges: []topology.Edge{}}, nil
		}
		m = &gateway.Model{}
		if err := json.Unmarshal([]byte(mj), m); err != nil {
			return nil, err
		}
	case "", "desired":
		var err error
		if m, err = s.d.GW.LoadModel(ctx); err != nil {
			return nil, err
		}
	default:
		return nil, apierr.BadRequest("view must be desired or active")
	}
	o := topology.Observed{Endpoint: map[string]string{}}
	rows, err := s.d.DB.QueryContext(ctx, `SELECT h.subject_id, h.status FROM health_samples h JOIN (SELECT subject_id, MAX(seq) seq FROM health_samples WHERE subject_kind='endpoint' GROUP BY subject_id) x ON x.seq=h.seq`)
	if err == nil {
		for rows.Next() {
			var id, st string
			if rows.Scan(&id, &st) == nil {
				o.Endpoint[id] = st
			}
		}
		rows.Close()
	}
	if rows, err := s.d.DB.QueryContext(ctx, "SELECT fqdn FROM domains"); err == nil {
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil {
				o.Domains = append(o.Domains, d)
			}
		}
		rows.Close()
	}
	if rules, err := s.fw().List(ctx); err == nil {
		for _, f := range rules {
			o.FWRules = append(o.FWRules, topology.FWRule{ID: f.ID, Key: f.Key, Proto: f.Proto, Port: f.Port, State: f.ActiveState})
		}
	}
	g := topology.Build(m, o)
	if g.Nodes == nil {
		g.Nodes = []topology.Node{}
	}
	if g.Edges == nil {
		g.Edges = []topology.Edge{}
	}
	return g, nil
}

func (s *Server) getTopology(w http.ResponseWriter, r *http.Request) error {
	g, err := s.topologyGraph(r)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, g)
}

var nodeIDRe = regexp.MustCompile(`^(listener|route|pool|endpoint|website|certificate|domain|firewall_rule):[A-Za-z0-9.-]{1,253}$`)

func (s *Server) getImpact(w http.ResponseWriter, r *http.Request) error {
	node := r.URL.Query().Get("node")
	if !nodeIDRe.MatchString(node) {
		return apierr.BadRequest("node must look like endpoint:<id>")
	}
	g, err := s.topologyGraph(r)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, topology.Analyze(g, node))
}
