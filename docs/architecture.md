# Architecture

Agent Identity Plane is the identity and provenance layer of the Visor Trust
Plane. It authenticates AI agents, binds each agent to the workloads that may
host it, and mints a new single-hop token at every agent-to-agent or
agent-to-tool boundary so the originating principal is never dropped.

```text
user --session--> oncall-agent --RFC 8693--> STS --JWT aud=investigation--> investigation-agent
                                                                      |
                                                                      +--> Agent Registry
investigation-agent --RFC 8693--> STS --JWT aud=mcp-gateway--> visor-gateway
visor-gateway --verified --client-id / --session-id--> mcp-visor --policy--> MCP server
```

## Packages

| Package | Role |
|---|---|
| `internal/token` | Compact JWS (EdDSA sign; EdDSA/ES256/RS256 verify), JWKS, claims |
| `internal/registry` | Strict JSON agent registry |
| `internal/attest` | `WorkloadAttestor`: local Ed25519 keys and SPIFFE JWT-SVID JWKS (file, URL, or OIDC) |
| `internal/sts` | Token exchange, minting, loopback HTTP server |
| `internal/verify` | Audience-bound verification → `ActorChain` |
| `internal/a2a` | Client `RoundTripper` and server middleware |
| `internal/audit` | Hash-linked JSONL + `trace` reconstruction |
| `internal/gateway` | visor-gateway identity PEP (verify, denylist, audit, reverse-proxy) |
| `internal/visoradapter` | Map a verified chain to mcp-visor identity fields |
| `internal/denylist` | Exact-ID agent/workload/principal revocation list |
| `internal/dpop` | RFC 9449 DPoP proofs at visor-gateway |

## Token exchange

`POST /oauth/token` implements RFC 8693:

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token` — user token (first hop) or prior STS token
- `actor_token` — workload credential (JWT-SVID or localkeys JWT)
- `audience` — exactly one next hop
- `agent_id` — registered agent URI
- `scope` — optional; must only narrow

The actor token is verified first (AI1). The registry then checks that
`agent_id` may run on that workload and call that audience (AI2, AI3). Subject
tokens signed by the STS keys are subsequent hops; tokens signed by the IdP
JWKS are first hops. Cross-signing (IdP key, STS `iss`) is rejected.

Minted claims: immutable `sub` and `txn`, single `aud`, nested RFC 8693 `act`,
flat `actchain`, narrowed `scope`, `jti`, `exp` (default 120s), and `cnf.jkt`
(RFC 7800) of the actor-token verification key for that hop.

## Enforcement vs mcp-visor

This process answers *who is acting*. mcp-visor answers *whether the tool call
is allowed*. `visor-gateway` verifies the actor chain and emits visor
`--client-id` / `--session-id` (identity-only) or reverse-proxies to an
HTTP backend with those headers overwritten. visor identity policy is
then bound to a verified actor, not a spoofable CLI string. See
[visor-integration.md](visor-integration.md).

## Bind addresses

`serve` and `visor-gateway` reject unspecified hosts (`0.0.0.0`, `::`, empty
host). Default is `127.0.0.1`.

## Operability (v0.2)

- Signing material is a 0600 Ed25519 key file or a keyring document
  (`active_kid` + `keys`). Mint uses the active kid. A new kid must be
  published in JWKS (preload) before it can become `active_kid`.
  Overlapping kids keep the same public-key bytes. `/jwks.json` lists every key in the ring; retire a kid only after
  mint TTL plus clock skew.
- `SIGHUP` reloads registry and signing files, then publishes both as
  one snapshot. Invalid documents keep the previous snapshot.
- Consumed STS subject `jti` values are durable (`-replay-log`) through
  `exp + ClockSkew` and survive restart. The replay log must not alias
  the audit log or other exclusive identity files.
- Optional `-tls-cert` / `-tls-key`. Without them, put a TLS reverse
  proxy in front and keep the STS on loopback (see
  [operations.md](operations.md)).
- `GET /readyz` and `GET /metrics`. `POST /oauth/token` is rate-limited
  (`-rate-limit`, default 30/s).

## visor-gateway (v0.3)

`visor-gateway` is the identity PEP in front of mcp-visor. Loopback bind,
optional TLS, `/readyz` `/metrics`, rate limit, required audit log.
JWKS from `-jwks` or `-jwks-url` (`https`, or loopback `http`) is
loaded on each verify. `-identity-only` returns the visor mapping JSON
so an operator can start stdio `mcp-visor serve`. `-backend` reverse-proxies
an HTTP service after verification and overwrites `X-Visor-*`. visor
stdio is not an HTTP backend. mcp-visor is not modified.

## Live workload JWKS (v0.4)

`serve` may verify JWT-SVIDs against a live JWKS in addition to local
workload keys. Use one of `-spiffe-jwks`, `-spiffe-jwks-url`, or
`-spiffe-oidc-issuer`. URLs must be `https` except loopback `http`
(TLS 1.2+, 1MiB cap, same check on redirects). OIDC discovery is
`{issuer}/.well-known/openid-configuration`; the document `issuer`
must equal the configured issuer exactly (trailing slash is
significant), and `jwks_uri` is fetched under the same URL policy.
Keys are re-fetched on each `Attest`. `/readyz` fails if that live
source cannot load keys. This is still JWKS verification, not a
SPIRE Workload API client.

## Agent denylist (v0.5)

`serve -denylist` and `visor-gateway -denylist` load an owned JSON
document of agent, workload, and principal IDs. Matching is exact
(trailing slash is significant; last-segment short names are not
IDs). The STS denies minting; visor-gateway denies a verified chain
that contains a listed hop so already-minted tokens stop at the PEP.
SIGHUP publishes denylist with registry and keys. Empty lists are
valid. visor-gateway still requires DPoP (v0.6) for hops that are
not denylisted.

## DPoP at visor-gateway (v0.6)

Minted STS tokens include `cnf.jkt`, the RFC 7638 thumbprint of the
JWK that verified the actor token for that hop. visor-gateway requires
a `DPoP` proof JWT (`typ=dpop+jwt`) whose embedded public JWK
thumbprint equals `cnf.jkt`. The proof must match this request's
method (`htm`), reconstructed URI (`htu`: TLS→https else http, `Host`,
path; no query/fragment; `X-Forwarded-*` ignored), access-token hash
(`ath`), and `iat` within clock skew. Proof `jti` values are consumed
in `-dpop-replay` through `iat + ClockSkew`. Missing `cnf`, missing or
invalid DPoP, or a replayed proof is 401 with no backend. This is not
a DPoP nonce deployment and not a Production identity plane.
