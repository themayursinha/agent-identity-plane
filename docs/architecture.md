# Architecture

Agent Identity Plane is the Identity & Trust Foundation layer of the Visor Trust
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
| `internal/attest` | `WorkloadAttestor`: local Ed25519 keys and SPIFFE JWT-SVID JWKS |
| `internal/sts` | Token exchange, minting, loopback HTTP server |
| `internal/verify` | Audience-bound verification → `ActorChain` |
| `internal/a2a` | Client `RoundTripper` and server middleware (the paved path) |
| `internal/audit` | Hash-linked JSONL + `trace` reconstruction |
| `internal/visoradapter` | Map a verified chain to mcp-visor identity fields |
| `examples/visor-gateway` | HTTP front door that derives visor flags from a Bearer chain |

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
flat `actchain`, narrowed `scope`, `jti`, `exp` (default 120s).

## Enforcement vs mcp-visor

This process answers *who is acting*. mcp-visor answers *whether the tool call
is allowed*. The visor-gateway verifies the chain and starts mcp-visor with
`--client-id` and `--session-id` derived from it, so visor identity policy is
no longer an unauthenticated string. See [visor-integration.md](visor-integration.md).

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
