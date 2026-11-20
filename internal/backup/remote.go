package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/vault"
)

const SettingRemote = "backup.remote"

var remoteSecretRef = vault.Ref{Type: "backup_remote", Scope: "global", Name: "s3_secret"}

// RemoteConfig configures off-site S3-compatible backup uploads.
type RemoteConfig struct {
	Enabled   bool   `json:"enabled"`
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"access_key"`
	PathStyle bool   `json:"path_style"`
	HasSecret bool   `json:"has_secret,omitempty"`
}

// RemoteInput updates RemoteConfig; an empty SecretKey keeps the stored one.
type RemoteInput struct {
	RemoteConfig
	SecretKey string `json:"secret_key,omitempty"`
}

func validateRemote(in RemoteConfig) error {
	if !in.Enabled {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(in.Endpoint))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("remote endpoint must be a valid http(s) URL")
	}
	if strings.TrimSpace(in.Bucket) == "" {
		return errors.New("bucket is required")
	}
	if strings.TrimSpace(in.AccessKey) == "" {
		return errors.New("access key is required")
	}
	return nil
}

// Remote returns the configured off-site S3 target (without secret).
func (s *Service) Remote(ctx context.Context) (RemoteConfig, error) {
	var cfg RemoteConfig
	if err := s.setting(ctx, SettingRemote, &cfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RemoteConfig{Region: "us-east-1", PathStyle: true}, nil
		}
		return cfg, err
	}
	if sec, err := s.Vault.Get(ctx, remoteSecretRef); err == nil {
		cfg.HasSecret = len(sec) > 0
		clear(sec)
	}
	return cfg, nil
}

// SetRemote saves the off-site S3 target and optionally updates the secret key.
func (s *Service) SetRemote(ctx context.Context, in RemoteInput) (RemoteConfig, error) {
	in.Endpoint = strings.TrimRight(strings.TrimSpace(in.Endpoint), "/")
	in.Region = strings.TrimSpace(in.Region)
	if in.Region == "" {
		in.Region = "us-east-1"
	}
	in.Bucket = strings.TrimSpace(in.Bucket)
	in.Prefix = strings.Trim(strings.TrimSpace(in.Prefix), "/")
	in.AccessKey = strings.TrimSpace(in.AccessKey)
	if err := validateRemote(in.RemoteConfig); err != nil {
		return RemoteConfig{}, err
	}
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if in.SecretKey != "" {
			if _, err := s.Vault.PutTx(ctx, tx, remoteSecretRef, []byte(in.SecretKey)); err != nil {
				return err
			}
		} else if in.Enabled {
			if sec, err := s.Vault.Get(ctx, remoteSecretRef); err != nil || len(sec) == 0 {
				return errors.New("secret key is required")
			} else {
				clear(sec)
			}
		}
		cfg := in.RemoteConfig
		cfg.HasSecret = false
		return putSetting(ctx, tx, SettingRemote, cfg)
	})
	if err != nil {
		return RemoteConfig{}, err
	}
	return s.Remote(ctx)
}

// TestRemote verifies S3 connectivity by issuing a signed HeadBucket request.
func (s *Service) TestRemote(ctx context.Context) error {
	cfg, err := s.Remote(ctx)
	if err != nil {
		return err
	}
	if err := validateRemote(cfg); err != nil {
		return err
	}
	sec, err := s.Vault.Get(ctx, remoteSecretRef)
	if err != nil {
		return fmt.Errorf("load secret key: %w", err)
	}
	defer clear(sec)

	targetURL, hostHeader := s3URL(cfg, "")
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		return err
	}
	req.Host = hostHeader
	signS3(req, cfg.AccessKey, string(sec), cfg.Region, sha256Hex(nil), time.Now().UTC())
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("s3 returned HTTP %d", resp.StatusCode)
}

// UploadRemote uploads an existing backup archive to the configured S3 target.
func (s *Service) UploadRemote(ctx context.Context, id, filePath, archiveSHA256 string) (string, error) {
	cfg, err := s.Remote(ctx)
	if err != nil || !cfg.Enabled {
		return "", err
	}
	sec, err := s.Vault.Get(ctx, remoteSecretRef)
	if err != nil {
		return "", err
	}
	defer clear(sec)

	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	key := path.Base(filePath)
	if cfg.Prefix != "" {
		key = cfg.Prefix + "/" + key
	}
	targetURL, hostHeader := s3URL(cfg, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, f)
	if err != nil {
		return key, err
	}
	req.Host = hostHeader
	req.ContentLength = fi.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	if archiveSHA256 == "" {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return key, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return key, err
		}
		archiveSHA256 = hex.EncodeToString(h.Sum(nil))
	}
	signS3(req, cfg.AccessKey, string(sec), cfg.Region, archiveSHA256, time.Now().UTC())
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return key, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return key, fmt.Errorf("s3 put HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_, _ = s.DB.ExecContext(ctx, "UPDATE backup_artifacts SET remote_status='uploaded', remote_key=?, remote_error='' WHERE id=?", key, id)
	return key, nil
}

func (s *Service) recordRemoteFailure(ctx context.Context, id, key string, err error) {
	_, _ = s.DB.ExecContext(ctx, "UPDATE backup_artifacts SET remote_status='failed', remote_key=?, remote_error=? WHERE id=?", key, err.Error(), id)
}

func s3URL(cfg RemoteConfig, objectKey string) (fullURL string, host string) {
	u, _ := url.Parse(cfg.Endpoint)
	basePath := strings.TrimRight(u.Path, "/")
	if cfg.PathStyle {
		p := basePath + "/" + url.PathEscape(cfg.Bucket)
		if objectKey != "" {
			p += "/" + escapeS3Key(objectKey)
		}
		u.Path = p
		return u.String(), u.Host
	}
	u.Host = cfg.Bucket + "." + u.Host
	p := basePath + "/"
	if objectKey != "" {
		p += escapeS3Key(objectKey)
	}
	u.Path = p
	return u.String(), u.Host
}

func escapeS3Key(k string) string {
	parts := strings.Split(strings.TrimLeft(k, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signS3(req *http.Request, accessKey, secretKey, region, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", req.Host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, sig))
}

var _ = bytes.NewReader
var _ = json.Marshal
