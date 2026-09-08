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

1. Add the new key, set `active_kid` to it, `kill -HUP`.
2. Wait at least the mint TTL (default 120s).
3. Remove the old key, `kill -HUP`.

## Registry reload

Replace the registry file atomically (`mv` into place), then `SIGHUP`.
If the new document fails strict decode, the previous registry stays
loaded and the process does not exit.

## Replay

STS-issued subject tokens are single-use at `/oauth/token`. Retry a hop
with a new exchange from the previous (unconsumed) token, or from a
first-hop IdP token. This is not an agent denylist.

## Endpoints

| Path | Role |
|---|---|
| `GET /healthz` | Process is up |
| `GET /readyz` | Registry and signing ring are loaded |
| `GET /metrics` | Prometheus text counters |
| `GET /jwks.json` | Public STS keys |
| `POST /oauth/token` | RFC 8693 exchange (rate-limited) |
