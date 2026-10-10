package audit

import (
	"context"
	"testing"

	"github.com/ngm-gateway/ngm/internal/store/storetest"
)

func seed(t *testing.T) *Logger {
	l := New(storetest.New(t))
	for i, a := range []string{"login", "route.create", "deploy.apply", "logout"} {
		if _, err := l.Record(context.Background(), Event{ActorKind: "user", ActorID: "u1", Action: a, Result: "success", Context: map[string]any{"n": i}}); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func TestChainVerifies(t *testing.T) {
	l := seed(t)
	r, err := l.Verify(context.Background())
	if err != nil || !r.OK || r.Events != 4 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestTamperDetected(t *testing.T) {
	ctx := context.Background()
	cases := map[string]string{
		"edit":   "UPDATE audit_events SET result='failure' WHERE seq=2",
		"delete": "DELETE FROM audit_events WHERE seq=2",
		"ctx":    `UPDATE audit_events SET context_json='{"n":99}' WHERE seq=3`,
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			l := seed(t)
			if _, err := l.db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
			r, _ := l.Verify(ctx)
			if r.OK {
				t.Fatalf("tamper %q not detected", name)
			}
		})
	}
}

func TestRejectsSensitiveContext(t *testing.T) {
	l := New(storetest.New(t))
	for _, k := range []string{"password", "api_token", "Authorization", "backup_passphrase"} {
		_, err := l.Record(context.Background(), Event{ActorKind: "user", Action: "x", Result: "success", Context: map[string]any{k: "v"}})
		if err == nil {
			t.Errorf("context key %q accepted", k)
		}
	}
}
