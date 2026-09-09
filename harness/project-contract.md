# Agent Identity Plane — Project Contract

A standalone, deterministic Go implementation of an identity and provenance
layer for AI agents: an Agent Registry, a Security Token Service
that performs RFC 8693 token exchange with actor-chain provenance, a verifier
and A2A client, and a visor-gateway identity PEP that derives mcp-visor's
`--client-id` / `--session-id` from a verified actor chain. `visor-session`
is the supported command that starts mcp-visor with that mapping.

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

Subcommands: `serve`, `visor-gateway`, `visor-session`, `registry lint`,
`token inspect`, `token verify`, `trace`, `keys generate`, `demo`, `version`.

`serve` loads a 0600 signing key or keyring (`active_kid` + `keys`),
rejects group/world-readable key files, optional `-tls-cert`/`-tls-key`,
`-rate-limit` (default 30/s), and a required `-replay-log` that must
not alias `-audit-log` or other exclusive identity files. Required
`-denylist` is owned JSON (exact agent/workload/principal IDs; empty
lists are valid) and is published with registry and keys on SIGHUP.
Optional JWT-SVID material is one of `-spiffe-jwks`, `-spiffe-jwks-url`, or
`-spiffe-oidc-issuer` (`https`, or loopback `http`). SIGHUP
reloads registry, signing material, and denylist as one identity snapshot; an
invalid file keeps the previous snapshot.

`visor-gateway` is the identity PEP in front of mcp-visor. It verifies
the Bearer actor chain (a complete current actor, principal, and
session), overwrites `X-Visor-Client-Id` / `X-Visor-Session-Id` after
hop-by-hop stripping (client-id is the full `act.sub` unless
`-client-short-name` is set), and does not forward the STS Bearer.
It reverse-proxies to `-backend` (or returns the mapping with
`-identity-only`). Audit writes fail closed. `-denylist` is required
and re-read on each verify. visor-gateway requires a DPoP proof bound
to minted `cnf.jkt` and a durable `-dpop-replay` log. JWKS URLs must be
`https` except loopback `http`. visor itself is unchanged.

`visor-session` is the supported authentic start for stdio visor
(AI21). It POSTs the access token to visor-gateway with DPoP, accepts
only a complete mapping, and execs `mcp-visor serve` with
`-client-id` / `-session-id` from that mapping. Extra visor arguments
cannot set those flags. Gateway URLs follow the JWKS policy (`https`,
or loopback `http`; no query or fragment). Redirects are not followed. `-dpop-key` is a 0600 key
file. Hand-starting visor with a typed `--client-id` is still
spoofable. On Unix the process is replaced by visor; `AIP_ACCESS_TOKEN`
is stripped from visor's environment. This is not a Production claim.

`trace` reconstructs hops from required `-audit-log` JSONL. `-audit`
is always chain-verified; only `-visor` may be generic JSONL. Opening
and tracing an STS/gateway audit file verifies the hash chain (AI20).
Operators look up a minted `jti` or `txn` from verified records.
The hash chain is not a MAC. Key-compromise procedures are in
`docs/runbooks.md`. This is not a Production claim.

A deny is an authorization result (HTTP 400 with `error` / `error_description`
and a reason code), not a process failure. Process failure is reserved for
unreadable config, unspecified bind addresses, open signing-key modes,
aliased identity-file paths, malformed registry files at startup, and
a broken audit hash chain at open.
Reload failures are logged and do not exit the process.
