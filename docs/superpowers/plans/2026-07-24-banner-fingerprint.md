# Banner Fingerprint Implementation Plan

> **For agentic workers:** Implement the following tasks in parallel where file
> ownership does not overlap. Track completion with the checkboxes below.

**Goal:** Deliver a production-oriented Go banner fingerprint client/server that
starts with Docker Compose and survives hidden parser and malformed-input tests.

**Architecture:** A dependency-free static Go binary contains server, client,
and health probe commands. A concurrency-safe generic engine loads ordered JSON
rules and limits matches to structured scopes such as HTTP headers.

**Tech Stack:** Go 1.24 standard library, Docker multi-stage build, Docker Compose

## Global Constraints

- Preserve input order and identity and return confidence in the range 0..1.
- Unknown inputs return `protocol: "unknown"` and never panic the service.
- Rules remain external and replaceable without rebuilding the image.
- Compose publishes no server host ports; client uses `http://server:8080`.
- Runtime image is `scratch`, numeric non-root, read-only, and capability-free.

---

### Task 1: Rule engine

**Files:** `internal/fingerprint/*.go`, `rules/default.json`

- [x] Define request/result/rule types and validate the ruleset.
- [x] Compile named-group RE2 patterns once and implement scoped matching.
- [x] Add SSH, HTTP server, MySQL handshake, Redis, FTP, TLS, and generic
      protocol fallbacks with specific rules ordered before generic rules.
- [x] Test LF/CRLF, case, optional versions, changed ports, false-positive
      overlaps, binary/truncated banners, unknowns, and concurrent recognition.

### Task 2: HTTP server

**Files:** `internal/api/*.go`

- [x] Implement exact `GET /health` and `POST /fingerprint` routes.
- [x] Enforce method, content type, body, batch, and single-JSON-value limits.
- [x] Return stable JSON errors for envelope failures and ordered results for
      mixed known/unknown batches.
- [x] Test success, route/method failures, null/object/trailing JSON, oversized
      requests, and continued health.

### Task 3: Executable and client

**Files:** `cmd/bannerfp/*.go`

- [x] Implement `serve` with bounded HTTP timeouts and graceful shutdown.
- [x] Implement `client` flags, local JSON reading, request timeout, and pretty
      JSON output.
- [x] Implement a healthcheck command usable in a `scratch` image.
- [x] Test CLI argument and transport behavior where practical.

### Task 4: Container delivery and proof

**Files:** `Dockerfile`, `compose.yaml`, `.dockerignore`, `Makefile`,
`examples/input.json`, `README.md`

- [x] Build a static stripped binary in a pinned builder and copy only it into
      `scratch`.
- [x] Configure internal networking, health-gated dependency, read-only mounts
      and filesystems, numeric users, no-new-privileges, and dropped caps.
- [x] Document API, CLI, rule schema, security posture, and exact verification.
- [x] Run gofmt, `go test ./...`, `go vet ./...`, `docker compose config`, a cold
      Compose E2E, zero-port inspection, container security inspection, and
      external-rule replacement proof.

### Task 5: Publish

- [x] Inspect the complete diff and ensure the worktree contains only this task.
- [x] Commit the verified project and create/push a public GitHub repository
      using authenticated `gh`.
- [x] Verify public visibility, remote/local commit parity, and clean worktree.
