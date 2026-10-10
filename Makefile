# NGM build entry points. Requires Go 1.26+ and Node 24+.
GO        ?= go
VERSION   ?= 0.1.0-dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG       := github.com/ngm-gateway/ngm/internal/buildinfo
LDFLAGS   := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)
export CGO_ENABLED=0

.PHONY: all test vet web web-test build clean

all: test build

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

test: vet
	$(GO) test ./...

web:
	cd web && npm ci && npm run build

web-test:
	cd web && npm ci && npm test

build: web
	mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/ngm-linux-amd64 ./cmd/ngm
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/ngm-linux-arm64 ./cmd/ngm
	cd dist && sha256sum ngm-linux-amd64 ngm-linux-arm64 > SHA256SUMS

clean:
	rm -rf dist
