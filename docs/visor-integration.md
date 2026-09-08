# mcp-visor integration

mcp-visor decides whether a `tools/call` may proceed. Its caller identity today
is the operator-supplied `--client-id` string, matched by optional
`identities[]` allowlists. The threat model records that this value is not
authenticated. Stdio attestation pins the MCP *server*, not the agent.

Agent Identity Plane fills that gap **without modifying mcp-visor**:

1. Agents obtain a next-hop token from this STS (`aud` = the visor-gateway).
2. `examples/visor-gateway` verifies the Bearer token.
3. `internal/visoradapter` maps the verified chain:
   - `--client-id` ← acting agent (`act.sub`), optionally the last URI segment
   - `--session-id` ← `txn`
4. The gateway can spawn `mcp-visor serve -client-id … -session-id …` or run
   `-identity-only` and emit `X-Visor-Client-Id` / `X-Visor-Session-Id`.

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

Until that lands, the visor-gateway is the enforcement point that makes visor
identity policy meaningful.

## Mapping example

Verified chain:

```text
user1 > spiffe://example.test/agent/oncall > spiffe://example.test/agent/investigation
txn = txn-abc
```

Visor flags (`-client-short-name`):

```text
mcp-visor serve -client-id investigation -session-id txn-abc ...
```

A visor policy `identities[]` entry named `investigation` then applies to a
*verified* actor, not a spoofable CLI string.
