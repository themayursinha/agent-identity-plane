# mcp-visor integration

mcp-visor decides whether a `tools/call` may proceed. Standalone Visor still
accepts an operator-supplied `--client-id` string, matched by optional
`identities[]` allowlists. That value is not authenticated. Stdio attestation
pins the MCP *server*, not the agent.

Agent Identity Plane fills that gap by producing a `VerifiedActorContext`
**only after** STS+DPoP verification and handing it to visor on a
process-start file descriptor. The two repositories stay separate.

1. Agents obtain a next-hop token from this STS (`aud` = the visor-gateway).
2. `agent-identity-plane visor-gateway` verifies the Bearer token (JWKS
   file or `https` URL, re-fetched on each request) **and** a `DPoP`
   proof bound to the token's `cnf.jkt`, including a server-issued nonce.
3. `internal/visoradapter` maps the verified chain:
   - `--client-id` ← acting agent (`act.sub`). `-client-short-name` is
     opt-in and uses the last URI segment; that can collide across prefixes.
   - `--session-id` ← `txn`
   - `verified_actor` ← sealed `VerifiedActorContext` (principal, acting
     agent, hops, scopes, issuer/audience/token/expiry, proof thumbprint,
     `sts+dpop`, `identity_snapshot_hash`)
4. `-identity-only` returns that mapping as JSON and headers.
   `agent-identity-plane visor-session` POSTs to that endpoint with
   DPoP (one retry on `use_dpop_nonce`) and starts
   `mcp-visor serve -client-id … -session-id … -verified-actor-fd 3`.
   The JSON object is written to a pipe, `dup2`'d onto fd 3, then visor
   is `exec`'d. The JSON is capped at 32KiB so the pre-exec pipe write
   cannot block waiting for visor. Extra visor args cannot set identity flags, including
   `-verified-actor-fd`. visor stdio is not an HTTP server. Typing
   `mcp-visor serve -client-id …` by hand is still spoofable.
5. `-backend` reverse-proxies to an HTTP service (for example a
   streamable-HTTP MCP front) and overwrites `X-Visor-Client-Id` /
   `X-Visor-Session-Id` so a caller cannot spoof them.

Do not spawn a visor process per HTTP request.

Visor policy `settings.require_verified_actor: true` (or a tool
`required_scopes` list) fails closed when that process-start context is
missing, expired, or structurally invalid. H44 `lineage_require` remains an
optional constraint over the session identity; it is not a third token
format. Deny-before-relay is proven at visor's `interceptAndModify` gate
(H50), not as a Phase 2 network-isolation topology.

Division of labour:

| Question | Owner |
|---|---|
| Who is acting, for whom, through which agents, with what scope? | agent-identity-plane |
| May this concrete `tools/call` execute? | mcp-visor |
| What authority could a delegation reach? | authority-graph-simulator |
| Did a trajectory acquire stronger capability? | capability-delta-receipts |

## Rejected transports

These are not the Phase 1 seam and must not be added later as a way for the
MCP client or model to populate identity:

- MCP `tools/call` arguments / `_meta` / `_verified_actor`
- In-proxy JWT or DPoP on every `tools/call` (the former “proposed later seam”)
- Environment variables
- A path the agent can write
- A stdin preamble (`visor-session` `exec`s visor, so stdin **is** the MCP client stream)

## Mapping example

Verified chain:

```text
user1 > spiffe://example.test/agent/oncall > spiffe://example.test/agent/investigation
txn = txn-abc
```

Supported start (default: full `act.sub`):

```text
agent-identity-plane visor-session \
  -gateway http://127.0.0.1:8090/session \
  -token "$JWT" \
  -dpop-key workload.json \
  -- -policy policy.yaml
```

That execs:

```text
mcp-visor serve -client-id spiffe://example.test/agent/investigation -session-id txn-abc -verified-actor-fd 3 -policy policy.yaml
```

`-client-short-name` is opt-in (`-client-id investigation`). Last-segment
names are not unique across URI prefixes, so visor `identities[]` must
be written for the identifier the gateway actually emits. The verified
context on fd 3 still carries the full acting-agent URI.
