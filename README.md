# BannerFP

BannerFP is a dependency-free Go client/server for batch recognition of raw
network scan banners. It reports protocol, product, version, an optional OS
hint, and a confidence score while preserving input order. Unrecognized input
is a normal result with `"protocol": "unknown"`; it never fails the whole batch.

## Quick start

Requirements: Docker Engine with the Compose v2 plugin.

```sh
docker compose up
```

The default Compose project builds the image, starts the server, waits for its
real HTTP health check to pass, then runs the client against the complete
20-banner fixture in `examples/input.json`. View the pretty-printed result in
the `client` service logs:

```sh
docker compose logs client
```

The server deliberately has no published host port. The client reaches it only
as `http://server:8080` on the Compose-internal network. This keeps the default
deployment boundary closed. For local development outside Compose:

```sh
go run ./cmd/bannerfp serve --addr 127.0.0.1:8080 --rules rules/default.json
go run ./cmd/bannerfp client --server http://127.0.0.1:8080 --input examples/input.json
```

## API

### `POST /fingerprint`

The request is a JSON array. Each item has `ip` (string), `port` (integer), and
`banner` (string):

```json
[
  {
    "ip": "192.0.2.10",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_9.3 Debian-1"
  }
]
```

A successful response has one result for every input item, in the same order:

```json
[
  {
    "ip": "192.0.2.10",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "9.3",
    "os_hint": "Debian",
    "confidence": 0.95
  }
]
```

Use `Content-Type: application/json`. Malformed envelopes and oversized
requests receive a JSON 4xx error. A syntactically valid banner that has no
matching evidence receives the neutral unknown result instead.

### `GET /health`

Returns HTTP 200 when the process is ready to recognize banners. The same probe
is built into the static binary, so the `scratch` image needs no shell, curl, or
package manager:

```sh
bannerfp healthcheck --url http://127.0.0.1:8080/health
```

## CLI

The project builds one executable with three subcommands:

```text
bannerfp serve --addr :8080 --rules /config/rules.json
bannerfp client --server http://server:8080 --input /data/input.json
bannerfp healthcheck --url http://127.0.0.1:8080/health
```

`serve` applies HTTP header/read/write/idle timeouts and drains active requests
on SIGINT or SIGTERM. `client` validates its local JSON, applies a request
timeout, rejects non-success or invalid-JSON responses, and prints formatted
JSON. The flags may also be supplied through `BANNERFP_ADDR`,
`BANNERFP_RULES`, `BANNERFP_SERVER`, and `BANNERFP_HEALTH_URL`.

## External fingerprint rules

Rules are loaded and compiled once at startup from `rules/default.json`. Compose
bind-mounts this file read-only at `/config/rules.json`; it is intentionally not
baked into the image, so rules can be reviewed or replaced without rebuilding
the executable.

Each rule contains:

- `id`: unique stable identifier.
- `protocol`, `product`, and `confidence`: output values.
- `scope`: `banner`, `first_line`, or `http_headers`.
- `pattern`: a Go RE2 regular expression. Named captures `version` and `os`
  populate the `version` and `os_hint` result fields.

Rules are evaluated in file order, with product-specific matches before generic
protocol fallbacks. `http_headers` limits inspection to the HTTP header block so
tokens in a response body cannot masquerade as a `Server` header. Invalid
rules fail startup rather than silently weakening recognition.

## Production-oriented container posture

- Multi-stage build with a pinned Go Alpine builder and a stripped,
  reproducible, `CGO_ENABLED=0` binary.
- Empty `scratch` runtime image containing only `/bannerfp`.
- Numeric unprivileged UID/GID `65532:65532`.
- Read-only root filesystems and read-only bind mounts.
- All Linux capabilities dropped and `no-new-privileges` enabled.
- No host port publishing; traffic remains on an `internal: true` network.
- Client startup is gated by the server's actual `/health` response.

Useful checks:

```sh
make check
docker compose config
docker compose up --build
docker compose port server 8080
docker inspect bannerfp-server-1 --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}}'
```

`docker compose port server 8080` should report that port 8080 is not published.
Use `docker compose down --remove-orphans` to remove the created containers and
network.

## Development

```sh
make test
make vet
make build
```

Only the Go standard library is used. Tests cover recognition variants,
ambiguous negatives, malformed JSON boundaries, mixed batches, concurrency, and
health behavior.
