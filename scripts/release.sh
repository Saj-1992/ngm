#!/bin/sh
# Build a signed release: sh scripts/release.sh VERSION CHANNEL KEYFILE
#   dist/release/VERSION/{ngm-linux-amd64,ngm-linux-arm64,manifest.json,manifest.sig,install.sh}
# The private key never enters the repository (.local/ is git-ignored).
set -eu
V=$1 CH=$2 KEY=$3
case "$CH" in stable | beta | development) ;; *) echo "channel must be stable|beta|development" >&2; exit 2 ;; esac
GO=${GO:-go}
OUT=dist/release/$V
rm -rf "$OUT" && mkdir -p "$OUT"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo uncommitted)
LD="-s -w -X github.com/ngm-gateway/ngm/internal/buildinfo.Version=$V -X github.com/ngm-gateway/ngm/internal/buildinfo.Commit=$COMMIT -X github.com/ngm-gateway/ngm/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X github.com/ngm-gateway/ngm/internal/buildinfo.Channel=$CH"
for A in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$A $GO build -trimpath -ldflags "$LD" -o "$OUT/ngm-linux-$A" ./cmd/ngm
done
$GO run ./cmd/ngm release sign --key "$KEY" --dir "$OUT" --version "$V" --channel "$CH" --commit "$COMMIT"
$GO run ./cmd/ngm release verify --dir "$OUT"
# install.sh with the pinned public keys embedded.
node -e '
const fs=require("fs");
const keys=fs.readdirSync("internal/release/trusted").filter(f=>f.endsWith(".pub")).sort();
const block=keys.map((k,i)=>"cat >\"$TMP/key-"+i+".pem\" <<'"'"'EOF'"'"'\n"+fs.readFileSync("internal/release/trusted/"+k,"utf8").trim()+"\nEOF").join("\n");
const src=process.env.NGM_RELEASE_URL||"https://github.com/Saj-1992/ngm/releases/latest/download";
const t=fs.readFileSync("deploy/install.sh.in","utf8").split("@@PINNED_KEYS@@").join(block).split("@@DEFAULT_SRC@@").join(src);
fs.writeFileSync(process.argv[1]+"/install.sh",t.replace(/\r\n/g,"\n"));
' "$OUT"
# Regression guard (caught a real bug once): without "--from", install.sh
# must NOT reject its own built-in default source. A prior version of the
# template compared SRC against the placeholder text, which after
# substitution equalled the real default and made the one-line install
# ("curl ... | sudo sh", no --from) always fail. Run it unprivileged with no
# args: it must get past the source check and fail on "run as root" instead
# (reached before any network call), not on "no download source".
FIRST_LINE=$(sh "$OUT/install.sh" </dev/null 2>&1 | head -1 || true)
case "$FIRST_LINE" in
*"no download source"*) echo "release.sh: install.sh rejects its own default source: $FIRST_LINE" >&2; exit 1 ;;
esac
(cd "$OUT" && sha256sum ngm-linux-amd64 ngm-linux-arm64 manifest.json manifest.sig install.sh >SHA256SUMS)
echo "release $V ($CH) in $OUT"
