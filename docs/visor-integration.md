# mcp-visor integration

mcp-visor decides whether a `tools/call` may proceed. Its caller identity today
is the operator-supplied `--client-id` string, matched by optional
`identities[]` allowlists. The threat model records that this value is not
authenticated. Stdio attestation pins the MCP *server*, not the agent.

Agent Identity Plane fills that gap **without modifying mcp-visor**:

1. Agents obtain a next-hop token from this STS (`aud` = the visor-gateway).
2. `agent-identity-plane visor-gateway` verifies the Bearer token (JWKS
   file or `https` URL, re-fetched on each request).
3. `internal/visoradapter` maps the verified chain:
   - `--client-id` ← acting agent (`act.sub`). `-client-short-name` is
     opt-in and uses the last URI segment; that can collide across prefixes.
   - `--session-id` ← `txn`
4. `-identity-only` returns that mapping as JSON and headers. Start
   `mcp-visor serve -client-id … -session-id …` with those values for
   the session. visor stdio is not an HTTP server.
5. `-backend` reverse-proxies to an HTTP service (for example a
   streamable-HTTP MCP front) and overwrites `X-Visor-Client-Id` /
   `X-Visor-Session-Id` so a caller cannot spoof them.

Do not spawn a visor process per HTTP request.

Division of labour:

| Question | Owner |
|---|---|
| Who is acting, for whom, through which agents, with what scope? | agent-identity-plane |
| May this concrete `tools/call` execute? | mcp-visor |
| What authority could a delegation reach? | authority-graph-simulator |
| Did a trajectory acquire stronger capability? | capability-delta-receipts |

## Proposed later seam (not implemented here)

A future mcp-visor PR could replace spoofable `--client-id` with an in-proxy
token gate:

- New flag `-identity-jwks` / `-identity-issuer` / `-identity-audience`
- On each `tools/call`, verify `Authorization: Bearer` (or a JSON-RPC param)
  and set `ClientID` from `act.sub` and session id from `txn`
- Optional `lineage_require` tool rule can read typed lineage fields that the
  adapter already emits (`principal`, `acting_agent`, `txn`)
- Audit `lineage` object on allow/deny, without changing the hash-chain core

Until that lands, visor-gateway is the enforcement point that makes visor
identity policy meaningful: only a verified chain that is not denylisted
produces the `--client-id` / `--session-id` you pass to visor.

## Mapping example

Verified chain:

```text
user1 > spiffe://example.test/agent/oncall > spiffe://example.test/agent/investigation
txn = txn-abc
```

Visor flags (default: full `act.sub`):

```text
mcp-visor serve -client-id spiffe://example.test/agent/investigation -session-id txn-abc ...
```

`-client-short-name` is opt-in (`-client-id investigation`). Last-segment
names are not unique across URI prefixes, so visor `identities[]` must
be written for the identifier the gateway actually emits.
