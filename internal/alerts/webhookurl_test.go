package alerts

import (
	"testing"

	"github.com/ngm-gateway/ngm/internal/observe"
)

func TestCheckWebhookURLRejectsInternal(t *testing.T) {
	for _, u := range []string{"http://example.com/x", "https://127.0.0.1/x", "https://10.0.0.5/x", "https://[::1]/x", "https://169.254.169.254/x", "https://localhost/x", "https://[::ffff:127.0.0.1]/x", "https://u:p@example.com/"} {
		if checkWebhookURL(u, false) == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if err := checkWebhookURL("https://hooks.example.com/ngm", false); err != nil {
		t.Errorf("public URL rejected: %v", err)
	}
	if err := checkWebhookURL("https://127.0.0.1/x", true); err != nil {
		t.Errorf("AllowPrivate ignored: %v", err)
	}
}

func TestNginxDrift(t *testing.T) {
	b := NginxBaseline{Version: "1.24.0", PackageVersion: "1.24.0-2ubuntu7", StreamModule: true, SSLPreread: true}
	n := observe.Nginx{Installed: true, Version: "1.24.0", PackageVersion: "1.24.0-2ubuntu7", StreamModule: true, SSLPreread: true}
	if m, _ := Drift(b, n); m != "" {
		t.Fatalf("no drift expected: %s", m)
	}
	n.PackageVersion = "1.24.0-2ubuntu7.1"
	if m, crit := Drift(b, n); m == "" || crit {
		t.Fatalf("package change: %q %v", m, crit)
	}
	n.StreamModule = false
	if m, crit := Drift(b, n); m == "" || !crit {
		t.Fatalf("lost stream module must be critical: %q %v", m, crit)
	}
}
