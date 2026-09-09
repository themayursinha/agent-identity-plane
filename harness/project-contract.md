# Agent Identity Plane — Project Contract

A standalone, deterministic Go implementation of an identity and provenance
layer for AI agents: an Agent Registry, a Security Token Service
that performs RFC 8693 token exchange with actor-chain provenance, a verifier
and A2A client, and a visor-gateway identity PEP that derives mcp-visor's
`--client-id` / `--session-id` from a verified actor chain.

## Boundary

- Standard library only. No third-party Go modules.
- Not a live SPIRE deployment. JWT-SVID verification is JWKS-based.
- Not an MCP action-policy engine. mcp-visor remains the tools/call PEP.
- Not a host sandbox. Not a general-purpose OAuth authorization server for
  browser users.
- Listen addresses must be explicit unicast hosts; unspecified addresses
  (`0.0.0.0`, `::`) are rejected.

## Enforced property

A token is minted iff:

1. The actor token verifies as a workload credential (AI1).
2. The named agent is registered to run on that workload (AI2).
3. The requested audience is exactly one allowed next hop (AI3).
4. `sub` and `txn` are copied from the verified subject token (AI4).
5. Requested scopes are a subset of (incoming scopes ∩ agent max_scopes) (AI5).
6. Delegation depth is within the agent's max_depth (AI6).
7. The reconstructed actor chain matches the verified prior token (AI7).

Otherwise the exchange is denied with a stable reason code, an audit record
is written (AI8), and no token is issued.

## CLI contract

Subcommands: `serve`, `visor-gateway`, `registry lint`, `token inspect`,
`token verify`, `trace`, `keys generate`, `demo`, `version`.

`serve` loads a 0600 signing key or keyring (`active_kid` + `keys`),
rejects group/world-readable key files, optional `-tls-cert`/`-tls-key`,
`-rate-limit` (default 30/s), and a required `-replay-log` that must
not alias `-audit-log` or other exclusive identity files. SIGHUP
reloads registry and signing material as one identity snapshot; an
invalid file keeps the previous snapshot.

`visor-gateway` is the identity PEP in front of mcp-visor. It verifies
the Bearer actor chain (a complete current actor, principal, and
session), overwrites `X-Visor-Client-Id` / `X-Visor-Session-Id` after
hop-by-hop stripping (client-id is the full `act.sub` unless
`-client-short-name` is set), and reverse-proxies to `-backend` (or
returns the mapping with `-identity-only`). Audit writes fail closed.
JWKS URLs must be `https` except loopback `http`. visor itself is
unchanged.

A deny is an authorization result (HTTP 400 with `error` / `error_description`
and a reason code), not a process failure. Process failure is reserved for
unreadable config, unspecified bind addresses, open signing-key modes,
aliased identity-file paths, and malformed registry files at startup.
Reload failures are logged and do not exit the process.
