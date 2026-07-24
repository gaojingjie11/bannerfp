# Banner Fingerprint System Design

## Scope

Build a dependency-free Go client/server system that accepts ordered batches of
`ip`, `port`, and `banner`, and returns protocol, product, version, OS hint, and
confidence. Unknown or malformed-but-representable banners produce a neutral
`unknown` result without failing the batch.

## Architecture

One statically linked binary exposes `serve`, `client`, and `healthcheck`
subcommands. The server owns a generic recognizer that loads ordered rules from
an external JSON file. Rules select a banner scope (`banner`, `first_line`, or
`http_headers`) and use RE2 named groups for version and OS extraction. The API
limits request size, rejects malformed envelopes, preserves item identity and
order, and never treats recognition failure as an HTTP error.

Docker Compose builds a multi-stage `scratch` image, mounts rules and client
fixtures read-only, runs as an unprivileged numeric user with a read-only root
filesystem and no Linux capabilities, and uses an internal-only network.
Client startup is gated on the server binary's real HTTP health probe.

## Errors and verification

Configuration errors fail server startup. Transport or JSON envelope errors
return a JSON error with an appropriate 4xx/5xx status. Individual unknown
banners return a normal result. Tests cover semantic variants, changed ports,
overlapping negatives, malformed requests, mixed batches, and concurrent use.
Runtime verification checks health-gated service-name access, zero published
ports, non-root/read-only security settings, and a `scratch` final stage.
