package backup

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteBackupS3Upload(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotSHA string
	var gotLen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotSHA = r.Header.Get("x-amz-content-sha256")
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, h := newService(t)
	ctx := context.Background()

	cfg, err := s.SetRemote(ctx, RemoteInput{
		RemoteConfig: RemoteConfig{
			Enabled:   true,
			Endpoint:  srv.URL,
			Region:    "us-east-1",
			Bucket:    "ngm-bak",
			Prefix:    "prod",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			PathStyle: true,
		},
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatalf("SetRemote: %v", err)
	}
	if !cfg.HasSecret {
		t.Fatal("expected HasSecret=true")
	}
	if err := s.TestRemote(ctx); err != nil {
		t.Fatalf("TestRemote: %v", err)
	}
	if gotMethod != http.MethodHead || gotPath != "/ngm-bak" || !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("unexpected HEAD request: %s %s auth=%q", gotMethod, gotPath, gotAuth)
	}

	art, err := s.CreateArchive(ctx, h.keys, "host1", "manual", "")
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if art.RemoteStatus != "uploaded" {
		t.Fatalf("expected remote_status=uploaded, got %q (err=%q)", art.RemoteStatus, art.RemoteError)
	}
	if gotMethod != http.MethodPut || !strings.HasPrefix(gotPath, "/ngm-bak/prod/") || gotLen == 0 || gotSHA != art.SHA256 {
		t.Fatalf("unexpected PUT upload: method=%s path=%s len=%d sha=%s vs %s", gotMethod, gotPath, gotLen, gotSHA, art.SHA256)
	}
}
