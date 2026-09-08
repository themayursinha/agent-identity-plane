# Operations (v0.2)

This is an operable single-node STS, not a production identity plane.
Loopback binds and fail-closed minting still apply.

## TLS and reverse proxy

Prefer `-tls-cert` and `-tls-key` on `serve` (TLS 1.2+).

If a reverse proxy terminates TLS instead:

- Bind the STS to loopback (`127.0.0.1`), never `0.0.0.0`.
- Forward `POST /oauth/token` with the body unchanged.
- Do not rewrite JSON, strip form fields, or inject `agent_id`.
- Treat `/jwks.json` as public verification material (no private keys).
- Do not trust `X-Forwarded-For` for authorization. Rate limiting is
  global on the process, not per client IP.

## Signing keys

`keys generate -out FILE` writes mode `0600`. `serve` refuses group- or
world-readable signing files.

Single key:

```json
{"kid":"sts-1","alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"…","d":"…"}
```

Keyring (rotate without dropping in-flight tokens):

```json
{
  "active_kid": "sts-2",
  "keys": [
    {"kid":"sts-1","alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"…","d":"…"},
    {"kid":"sts-2","alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"…","d":"…"}
  ]
}
```

1. Preload: add the new key, keep `active_kid` on the current kid, `kill -HUP`.
   `/jwks.json` now publishes both. Wait until verifiers refresh JWKS
   (visor-gateway re-reads `-jwks` / `-jwks-url` on each verify).
2. Activate: set `active_kid` to the already-published new kid, `kill -HUP`.
   Activating a kid that was not in the previous JWKS is rejected.
3. Retire: wait at least mint TTL plus clock skew (`KeyRetirementWait`,
   default 150s), then remove the old key and `kill -HUP`.

## Registry and key reload

Replace registry and/or signing files atomically (`mv` into place), then
`SIGHUP`. Both documents are decoded first; then registry and keyring
are published together. If either document fails strict decode, neither
changes and the process does not exit.

## Replay

STS-issued subject tokens are single-use at `/oauth/token` for as long
as `ValidateTime` would still accept them (`exp + 30s` skew). Consumed
`jti` values are written to `-replay-log` (JSONL, mode 0600) before the
mint, so a restart does not resurrect them. `-replay-log` must not
alias `-audit-log`, the signing key, or any other serve identity file
(same path, symlink, or hard link). Foreign JSONL fails closed at
open. Retry a hop from a first-hop IdP token, not by replaying an STS
subject token. This is not an agent denylist.

## Endpoints

| Path | Role |
|---|---|
| `GET /healthz` | Process is up |
| `GET /readyz` | Registry and signing ring are loaded |
| `GET /metrics` | Prometheus text counters |
| `GET /jwks.json` | Public STS keys |
| `POST /oauth/token` | RFC 8693 exchange (rate-limited) |
