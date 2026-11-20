package gateway

import (
	"strings"
	"testing"
)

func TestEnterpriseRouteCompileAndValidation(t *testing.T) {
	gzipOn := true
	m := Model{
		Listeners: []Listener{
			{ID: "L1", Name: "http", Kind: KindHTTP, Address: "0.0.0.0", Port: 80, Family: "ipv4", Enabled: true},
		},
		Endpoints: []Endpoint{
			{ID: "E1", Name: "app", Host: "10.0.0.10", Port: 8080, Transport: "http", Weight: 1, ConnectTimeoutMS: 5000, ReadTimeoutMS: 60000, WriteTimeoutMS: 60000},
			{ID: "E2", Name: "grpc-svc", Host: "10.0.0.11", Port: 9090, Transport: "http", Weight: 1, ConnectTimeoutMS: 5000, ReadTimeoutMS: 60000, WriteTimeoutMS: 60000},
		},
		Routes: []Route{
			{
				ID: "R1", Name: "api", ListenerID: "L1", Protocol: ProtoHTTP, Priority: 10,
				DestKind: DestEndpoint, DestID: "E1", Enabled: true,
				Matches: []Match{
					{Field: FieldHost, Operator: OpExact, Value: "api.example.com"},
					{Field: FieldPathPrefix, Operator: OpPrefix, Value: "/v1/"},
				},
				Options: RouteOptions{
					StripPrefix:     true,
					IPAllow:         []string{"192.168.1.0/24", "10.0.0.5"},
					IPDeny:          []string{"192.168.1.99"},
					RateLimitRPS:    25,
					RateLimitBurst:  50,
					Gzip:            &gzipOn,
					RequestHeaders:  map[string]string{"X-Forwarded-Custom": "ngm"},
					ResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
					CORS: &CORSPolicy{
						Enabled:          true,
						AllowOrigins:     []string{"https://app.example.com"},
						AllowMethods:     []string{"GET", "POST"},
						AllowHeaders:     []string{"Authorization", "Content-Type"},
						AllowCredentials: true,
						MaxAgeSec:        3600,
					},
				},
			},
			{
				ID: "R2", Name: "grpc", ListenerID: "L1", Protocol: ProtoHTTP, Priority: 20,
				DestKind: DestEndpoint, DestID: "E2", Enabled: true,
				Matches: []Match{
					{Field: FieldHost, Operator: OpExact, Value: "grpc.example.com"},
				},
				Options: RouteOptions{GRPC: true},
			},
		},
	}

	caps := Caps{HTTP2Directive: true, RejectHandshake: true}
	plan, issues := Build(&m, caps, BuildOptions{})
	if HasErrors(issues) {
		t.Fatalf("unexpected validation errors: %+v", issues)
	}
	out, err := Compile(plan, issues, caps, CompileInput{
		GenID:      "01TESTGEN00000000000000000",
		ProbeToken: "tok",
		RealIP: &RealIPConfig{
			Enabled:      true,
			Header:       "CF-Connecting-IP",
			TrustedCIDRs: []string{"173.245.48.0/20"},
			Recursive:    true,
		},
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	conf := string(out.Files[FileHTTP])
	for _, want := range []string{
		"set_real_ip_from 173.245.48.0/20;",
		"real_ip_header CF-Connecting-IP;",
		"real_ip_recursive on;",
		"limit_req_zone $binary_remote_addr zone=ngm_rl_r1:2m rate=25r/s;",
		"deny 192.168.1.99;",
		"allow 192.168.1.0/24;",
		"deny all;",
		"limit_req zone=ngm_rl_r1 burst=50 nodelay;",
		"limit_req_status 429;",
		"gzip on;",
		`add_header Access-Control-Allow-Origin "https://app.example.com" always;`,
		`add_header X-Frame-Options "DENY" always;`,
		`proxy_set_header X-Forwarded-Custom "ngm";`,
		"rewrite ^/v1(/.*)$ $1 break;",
		"grpc_pass grpc://ngm_up_e2;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("compiled config missing %q\n--- conf ---\n%s", want, conf)
		}
	}
}

func TestEnterpriseValidationRejectsInjection(t *testing.T) {
	base := Model{
		Listeners: []Listener{{ID: "L1", Name: "http", Kind: KindHTTP, Address: "0.0.0.0", Port: 80, Family: "ipv4", Enabled: true}},
		Endpoints: []Endpoint{{ID: "E1", Name: "app", Host: "10.0.0.10", Port: 8080, Transport: "http"}},
		Routes: []Route{{
			ID: "R1", Name: "api", ListenerID: "L1", Protocol: ProtoHTTP, DestKind: DestEndpoint, DestID: "E1", Enabled: true,
			Matches: []Match{{Field: FieldHost, Operator: OpExact, Value: "a.example.com"}},
			Options: RouteOptions{
				ResponseHeaders: map[string]string{"X-Test": "ok; evil_directive on"},
			},
		}},
	}
	_, issues := Build(&base, Caps{}, BuildOptions{})
	if !HasErrors(issues) {
		t.Fatal("expected error for header value containing semicolon")
	}

	base.Routes[0].Options = RouteOptions{
		CORS: &CORSPolicy{Enabled: true, AllowOrigins: []string{"*"}, AllowCredentials: true},
	}
	_, issues = Build(&base, Caps{}, BuildOptions{})
	if !HasErrors(issues) {
		t.Fatal("expected error for wildcard CORS with AllowCredentials")
	}

	if err := ValidateRealIP(RealIPConfig{Enabled: true, Header: "X-Forwarded-For", TrustedCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("expected error for invalid CIDR in RealIP")
	}
}
