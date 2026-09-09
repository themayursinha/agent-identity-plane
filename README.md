# Agent Identity Plane

**Cryptographic identity and actor-chain provenance for AI agents.**

Agent Identity Plane is a self-hosted Agent Registry + Security Token Service (STS) + verifier/A2A client. It issues short-lived, single-audience tokens that carry the full user-to-agent-to-tool delegation chain, so downstream systems can answer *who did this, on whose behalf, through which agents*.

> **This is not an action-policy engine.** It authenticates agents and preserves provenance.
> [MCP Visor](https://github.com/themayursinha/mcp-visor) decides whether a concrete `tools/call` may proceed.

The design composes RFC 8693, WIMSE identifiers, and the AIMS (`draft-klrc-aiagent-auth`) profile. It does not require a live SPIRE Workload API: workload credentials are verified from a JWKS bundle (file, HTTPS URL, or OIDC discovery).

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/themayursinha/agent-identity-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/themayursinha/agent-identity-plane/actions/workflows/ci.yml)

---

## The Visor Trust Plane research program

| Repo | Question it answers | Status |
|---|---|---|
| [**mcp-visor**](https://github.com/themayursinha/mcp-visor) | What may an agent *do*? (runtime policy at the MCP `tools/call` boundary) | Production |
| [**agent-identity-plane**](https://github.com/themayursinha/agent-identity-plane) | *Who* is acting, for whom, through which chain? (identity + provenance) | **This repo** |
| [**authority-graph-simulator**](https://github.com/themayursinha/authority-graph-simulator) | What authority can an agent *reach*? (counterfactual delegation analysis) | Prototype |
| [**capability-delta-receipts**](https://github.com/themayursinha/capability-delta-receipts) | What capability can an agent *acquire*? (trajectory-level capability accounting) | Prototype |

mcp-visor’s `--client-id` is an operator-supplied string and is not authenticated. This project issues a verified actor chain and a visor-gateway that derives `--client-id` and `--session-id` from that chain. `visor-session` is the supported path that starts mcp-visor with those values; typing the flags by hand is still spoofable. See [docs/visor-integration.md](docs/visor-integration.md). The two prototypes are standalone proofs; visor also ships an opt-in capability evaluator aligned with capability-delta-receipts. The authority-graph is not in the proxy.

---

## Why it exists

Today’s identity models describe humans and workloads. An AI agent is neither: it is authorized to act *for* someone else, and it calls other agents. Without per-hop token exchange:

- downstream tools see a generic service identity
- the originating user is untraceable
- a token minted for agent B can be replayed against a database

Agent Identity Plane mints a new single-hop JWT at every boundary. Each token names one audience, a short TTL, the immutable originating principal, and a verifiable actor chain.

---

## Install

```bash
go install github.com/themayursinha/agent-identity-plane/cmd/agent-identity-plane@latest
```

Pre-built binaries and checksums are on the [Releases](https://github.com/themayursinha/agent-identity-plane/releases) page.

## Quick start

```bash
# Generate a demo key pair and run the multi-hop scenario plus attack cases
agent-identity-plane demo

# Lint a registry file
agent-identity-plane registry lint testdata/registry.json

# Serve the STS on loopback (never binds 0.0.0.0)
agent-identity-plane serve \
  -listen 127.0.0.1:8080 \
  -registry testdata/registry.json \
  -issuer https://sts.example.test \
  -signing-key testdata/sts-ed25519.json \
  -workload-keys testdata/workloads.json \
  -idp-jwks testdata/idp-jwks.json \
  -audit-log ./sts-audit.jsonl \
  -replay-log ./sts-replay.jsonl \
  -denylist testdata/denylist.json

# Identity PEP: verified --client-id / --session-id (stdio visor is started separately)
agent-identity-plane visor-gateway \
  -listen 127.0.0.1:8090 \
  -audience https://mcp-gateway.example.test \
  -issuer https://sts.example.test \
  -jwks-url http://127.0.0.1:8080/jwks.json \
  -identity-only \
  -audit-log ./gateway-audit.jsonl \
  -denylist testdata/denylist.json \
  -dpop-replay ./gateway-dpop.jsonl

# Supported visor start: mapping from visor-gateway only (not a typed --client-id)
agent-identity-plane visor-session \
  -gateway http://127.0.0.1:8090/session \
  -token "$JWT" \
  -dpop-key workload.json \
  -visor-bin mcp-visor \
  -- -policy policy.yaml
```

## What it enforces

| Invariant | Meaning |
|---|---|
| AI1 | No token is minted without a verified workload credential |
| AI2 | `agent_id` must be registered for that workload |
| AI3 | `aud` is exactly one next hop; tokens are rejected elsewhere |
| AI4 | `sub` (originating principal) and `txn` are immutable across hops |
| AI5 | Scope only narrows |
| AI6 | Delegation depth is capped by the registry |
| AI7 | Actor chain integrity: each hop matches the verified prior token |
| AI8 | Every mint or deny is an audit record with a stable reason code |
| AI9 | Audit receipts are deterministic (sorted keys, hash-linked JSONL) |
| AI10 | Malformed registry, token, or JSON fails closed |
| AI11 | Listen addresses must be explicit unicast hosts |
| AI12 | STS-issued subject `jti` is single-use at exchange |
| AI13 | Signing JWKS may overlap kids; preload then activate |
| AI14 | Invalid identity reloads keep the previous snapshot |
| AI15 | Signing-key files must not be group- or world-readable |
| AI16 | visor-gateway forwards only a verified actor chain |
| AI17 | Workload JWT-SVID JWKS is fetched over https (loopback http) |
| AI18 | Denylisted agents, workloads, and principals cannot mint or pass the PEP |
| AI19 | visor-gateway requires a DPoP proof bound to minted `cnf.jkt` |
| AI20 | `trace` verifies the audit hash chain and reconstructs by `txn` or `jti` |
| AI21 | `visor-session` starts mcp-visor only with visor-gateway mapping identity |
| AI22 | visor-gateway requires a server-issued DPoP nonce |

## Architecture

```text
user --session--> oncall-agent --RFC 8693 exchange--> STS
                         |                              |
                         | JWT aud=investigation        | Agent Registry
                         v                              |
                   investigation-agent --exchange--> STS
                         |
                         | JWT aud=mcp-gateway
                         v
                   visor-gateway --identity-only JSON--> visor-session --mcp-visor serve -client-id--> mcp-visor --policy--> MCP server
```

Core packages: `internal/token`, `internal/registry`, `internal/attest`, `internal/sts`, `internal/verify`, `internal/a2a`, `internal/audit`, `internal/visoradapter`, `internal/gateway`, `internal/denylist`, `internal/dpop`, `internal/visorsession`.

CLI: `serve`, `visor-gateway`, `visor-session`, `registry lint`, `token inspect|verify`, `trace`, `keys generate`, `demo`.

## Security model

- **Deterministic:** no LLM on the mint path
- **Fail closed:** unknown agents, bad signatures, scope widening, depth overflow, and unspecified bind addresses are denied
- **Single hop:** tokens are audience-bound and short-lived (default 120s)
- **Self-hosted:** single Go binary; standard library only
- **Loopback by default:** `-listen` rejects `0.0.0.0` and `[::]`
- **Honest SPIFFE claim:** JWT-SVID verification is JWKS-based (file, `https` URL, or OIDC discovery). This is not a live SPIRE Workload API / gRPC client.
- **v0.2 operability:** overlapping STS kids, durable `jti` replay at exchange, atomic SIGHUP identity snapshot, optional TLS, `/readyz` + `/metrics`. Not a production identity plane.
- **v0.3 visor-gateway:** first-class identity PEP. JWKS file or `https` URL (loopback `http` allowed). Verified `--client-id` / `--session-id`; optional HTTP reverse-proxy that overwrites `X-Visor-*`. mcp-visor is unchanged.
- **v0.4 live workload JWKS:** `serve` may fetch JWT-SVID keys from `-spiffe-jwks-url` or `-spiffe-oidc-issuer` (same URL/TLS policy as visor-gateway). Still not Workload API.
- **v0.5 agent denylist:** owned JSON of agent, workload, and principal IDs. Exact match. Enforced at mint and at visor-gateway (in-flight hops).
- **v0.6 DPoP at visor-gateway:** minted tokens carry `cnf.jkt` of a workload-possessed key. visor-gateway requires a DPoP proof (`htm`/`htu`/`ath`/`jti`) whose JWK thumbprint matches, with durable proof-jti replay. Not Production (STS exchange is still actor_token).
- **v0.7 incident reconstruction:** `trace -audit` verifies the STS/gateway hash chain (not a MAC) and looks up hops by `txn` or minted `jti` from verified records. Key-compromise procedures are in [runbooks](docs/runbooks.md). Not Production.
- **v0.8 visor-session:** the supported path that starts mcp-visor with `-client-id` / `-session-id` taken only from a visor-gateway identity-only mapping. Extra visor args cannot set those flags. Typing `mcp-visor serve -client-id …` by hand is still spoofable. Not Production.
- **v0.9 DPoP nonce:** visor-gateway requires RFC 9449 `use_dpop_nonce`. Nonces are unguessable, single-use, and process-local. visor-session and the A2A tripper retry once. Not Production (no live visor-only operator deployment; STS exchange is still `actor_token`).
- **Not a host sandbox and not an MCP policy proxy**

## Documentation

[Architecture](docs/architecture.md) · [Token profile](docs/token-profile.md) · [Registry model](docs/registry-model.md) · [Threat model](docs/threat-model.md) · [Standards alignment](docs/standards-alignment.md) · [Visor integration](docs/visor-integration.md) · [Operations](docs/operations.md) · [Runbooks](docs/runbooks.md)

## Development

```bash
go build ./cmd/agent-identity-plane/
go test ./...
go test -race ./...
harness/check.sh
```

## License

MIT — see [LICENSE](LICENSE)
