# nostrhost-nsite

Optional NIP-5A static-site gateway for NostrHost (implementation plan:
`docs/NSITES-IMPLEMENTATION-PLAN.md`, Phase 1). Disabled by default; when
enabled it serves allowlisted ("hosted" mode, D3) root and named nsites on a
dedicated gateway domain in front of Caddy, resolving site manifests from
public relays and blobs from Blossom servers.

- **Protocol:** NIP-5A pinned to `nostr-protocol/nips@5d6b4322`. The
  conformance corpus in the parent repo (`tools/tests/nsites/corpus`) is the
  shared oracle between this Go implementation and the Python validator in
  `forks/yunohost/src/nostrhost/nsites/manifest.py`; the corpus test skips
  when the parent checkout is absent (`NSITES_CORPUS` overrides the path).
- **Hosting:** dedicated gateway domain + Caddy On-Demand TLS via the
  loopback-only `GET /internal/tls-ask?domain=<host>` endpoint (D2).
- **Exposure:** `hosted` allowlist mode only before Phase 5 (D3).
- **No Docker:** the package runs the gateway as a hardened systemd unit.

## Layout

```text
cmd/nostrhost-nsite/   flags, config load, two listeners, SIGHUP reload
internal/config/       TOML schema + validation (loopback relays rejected, D5)
internal/nip5a/        label codec + manifest validation + aggregate hash
internal/server/       public handler (host parse -> allowlist) and the
                       loopback-only internal handler (healthz, tls-ask, status)
deploy/                systemd unit, maintainer scripts, example config
```

Manifest/blob resolution (`internal/resolve`, `internal/blossom`,
`internal/cache`) and the public serving path are Phase 1.3; until then a
decodable, allowlisted host gets a bounded 404 and `/internal/*` is never
served publicly.

## Build and test

```bash
go build -buildvcs=false ./cmd/nostrhost-nsite
NSITES_CORPUS=../../nostrhost/tools/tests/nsites/corpus go test ./...
```

## Run

```bash
sudo cp deploy/nsite.example.toml /etc/nostrhost/nsite.toml   # edit it
sudo install -d -o nostrhost-nsite -g nostrhost-nsite -m 0700 /var/cache/nostrhost-nsite
sudo install -m 0644 deploy/nostrhost-nsite.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nostrhost-nsite
curl http://127.0.0.1:8196/healthz
```