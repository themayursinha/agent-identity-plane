# Operations (v0.2 STS, v0.3 visor-gateway, v0.4 live workload JWKS, v0.5 denylist, v0.6 DPoP, v0.7 trace)

This is an operable single-node STS, not a production identity plane.
Loopback binds and fail-closed minting still apply. Incident procedures
(key compromise, `trace -jti` / `-txn`) are in [runbooks.md](runbooks.md).

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
   (visor-gateway re-reads `-jwks-url` on each verify; a `-jwks` file
   is re-read from disk, so replace that copy when the ring changes).
2. Activate: set `active_kid` to the already-published new kid, `kill -HUP`.
   Activating a kid that was not in the previous JWKS is rejected.
   Reloading a published kid with different public-key bytes is rejected.
3. Retire: wait at least mint TTL plus clock skew (`KeyRetirementWait`,
   default 150s), then remove the old key and `kill -HUP`.
   Compromise recovery is not this wait: after the replacement kid is
   active, remove the burned kid immediately even if in-flight tokens
   under it fail (see [runbooks.md](runbooks.md)).

## Registry and key reload

Replace registry and/or signing files atomically (`mv` into place), then
`SIGHUP`. Both documents are decoded first; then registry and keyring
are published together. If either document fails strict decode, neither
changes and the process does not exit. `-denylist` is included in that
same snapshot.

## Replay

STS-issued subject tokens are single-use at `/oauth/token` for as long
as `ValidateTime` would still accept them (`exp + 30s` skew). Consumed
`jti` values are written to `-replay-log` (JSONL, mode 0600) before the
mint, so a restart does not resurrect them. `-replay-log` must not
alias `-audit-log`, the signing key, or any other serve identity file
(same path, symlink—including dangling links to the same target—or
hard link). Replay records require `jti` and `until`; foreign or
incomplete JSONL fails closed at open. Retry a hop from a first-hop
IdP token, not by replaying an STS subject token. Replay is not an
agent denylist; see below.

## Trace

`agent-identity-plane trace -txn ID -audit sts-audit.jsonl` reconstructs
hops. `trace -jti JTI` maps jti→txn from verified `-audit` records
only. `-audit` is always chain-verified; only `-visor` may be generic
JSONL. The hash chain is not a MAC: tail truncation, an empty file,
and a fully recomputed log are not detected. Hashed Event strings are
valid UTF-8 and length-bounded so recover can reopen the file. See [runbooks.md](runbooks.md).

## Endpoints

| Path | Role |
|---|---|
| `GET /healthz` | Process is up |
| `GET /readyz` | Registry, signing ring, and live workload JWKS (if configured) are loaded |
| `GET /metrics` | Prometheus text counters |
| `GET /jwks.json` | Public STS keys |
| `POST /oauth/token` | RFC 8693 exchange (rate-limited) |

## visor-gateway

`agent-identity-plane visor-gateway` is the identity PEP. Bind loopback.
Prefer `-tls-cert` / `-tls-key`. `-jwks-url` must be `https` except
loopback `http` for a local STS.

```bash
agent-identity-plane visor-gateway \
  -listen 127.0.0.1:8090 \
  -audience https://mcp-gateway.example.test \
  -issuer https://sts.example.test \
  -jwks-url http://127.0.0.1:8080/jwks.json \
  -identity-only \
  -audit-log ./gateway-audit.jsonl \
  -denylist testdata/denylist.json \
  -dpop-replay ./gateway-dpop.jsonl
```

`GET /healthz`, `GET /readyz` (JWKS fetchable), `GET /metrics`.
`-backend URL` reverse-proxies after verify and overwrites `X-Visor-*`.
Rate limit default 30/s. `-audit-log`, `-denylist`, and `-dpop-replay`
are required and must not alias `-jwks`. Use `-identity-only` to obtain `--client-id` / `--session-id`
for a stdio visor process; visor stdio is not an HTTP backend.

## Denylist

`-denylist` is owned JSON. Empty lists mean nothing is revoked.

```json
{"version":1,"agents":[],"workloads":[],"principals":[]}
```

IDs match exactly. Last-segment short names are not identifiers.
Agent and workload IDs must be parseable URIs with a scheme and host.
`serve` checks agent, attested workload, and verified principal at
mint. visor-gateway re-reads the file on each request and denies if
the principal, acting agent, or any hop after the principal position
is listed (later hops are agents even if their URI equals `sub`).
Invalid documents fail closed (serve keeps the previous snapshot on
SIGHUP).

## DPoP

visor-gateway requires a `DPoP` header on every identity PEP request
that would otherwise be allowed. The minted access token's `cnf.jkt`
must equal the proof JWK thumbprint. Callers prove possession of the
same workload key that attested the hop. Proof `jti` values are written
to `-dpop-replay` (JSONL, mode 0600) before allow, through
`iat + ClockSkew`. Token-endpoint proof jtis in the STS `-replay-log`
are stored as `dpop:` + proof `jti` so they cannot occupy a subject
token jti. Unprefixed proof jtis already in that log still count as
consumed until they expire. Reconstruct `htu` from this request (TLS, Host,
path). Do not trust `X-Forwarded-Proto` or `X-Forwarded-Host`.
Clients that mint a DPoP proof (the A2A tripper) set `htu` from the
outbound URL scheme and `Host` (then `URL.Host`). `RoundTrip` still has
`TLS == nil`. JWT-SVID hops must send DPoP on `POST /oauth/token` so
`cnf.jkt` is a workload key, not the SPIFFE issuer key.
`token_type` is `DPoP`; visor-gateway and the A2A tripper accept
`Authorization: DPoP` or `Bearer` plus the `DPoP` proof header.
There is no DPoP nonce. STS `POST /oauth/token` still uses
`actor_token` as the grant, not DPoP as the credential.

## Live JWT-SVID JWKS

`serve` still verifies local `-workload-keys`. Optionally add **one** of:

```bash
# Static bundle (v0.1+)
-spiffe-jwks ./spiffe-jwks.json

# Direct JWKS URL (https, or loopback http)
-spiffe-jwks-url https://oidc.example.test/keys

# OIDC discovery (issuer URL, same URL policy)
-spiffe-oidc-issuer https://oidc.example.test
```

Discovery GETs `{issuer}/.well-known/openid-configuration`, requires
the document `issuer` (and later JWT `iss`) to equal `-spiffe-oidc-issuer`
exactly, then fetches `jwks_uri`. Serve fails to start if that source
is unreachable or empty. `/readyz` fails later if it cannot load keys.
This is not the SPIRE Workload API.
