# Threat model

This document is an engineering threat model, not a compliance claim.

## Assets

- STS signing key
- Agent registry (who may run where, and with which next hops)
- Actor-chain provenance in minted tokens and the audit JSONL
- Downstream assumption that `--client-id` is authentic once visor-gateway is in path

## Adversaries

- An agent process that tries to impersonate another agent on the same workload
- A stolen next-hop token replayed to a different audience
- A caller that widens scope or nests extra actors without a valid prior token
- An operator who binds the STS to `0.0.0.0`

## Controls

| Threat | Control | Reason code |
|---|---|---|
| Unattested workload | Actor token must verify (AI1) | `invalid_actor_token` |
| Workload hosts unregistered agent | Registry workloads list (AI2) | `agent_not_registered` / `agent_not_authorized_on_workload` |
| Replay to another hop | Single `aud` (AI3) | `audience_mismatch` / `audience_not_allowed` |
| Principal swap | `sub`/`txn` copied from verified subject (AI4) | `chain_integrity` |
| Privilege accumulation | Scope subset (AI5) | `scope_widening` |
| Unbounded delegation | `max_depth` (AI6) | `depth_exceeded` |
| Forged actor chain | STS vs IdP key split; nested `act` rebuilt from verified token (AI7) | `chain_integrity` / `invalid_subject_token` |
| Stolen STS subject reused at exchange | `jti` consumed on first successful hop (AI12) | `replayed_token` |
| `alg=none` / alg confusion | Header alg must match JWK type | verify fail |
| Missing attribution | Audit record before HTTP response (AI8) | n/a |
| Spoofed visor `--client-id` at the gateway | visor-gateway verifies Bearer/DPoP and overwrites `X-Visor-*` after hop-by-hop strip (AI16) | `missing_bearer` / `invalid_token` / `incomplete_chain` |
| Typed visor `--client-id` bypass | visor-session starts visor only with a complete visor-gateway mapping; extra args cannot set identity flags (AI21) | process error |
| Stolen minted JWT presented at visor-gateway | DPoP bound to `cnf.jkt` of the actor-token key (AI19) | `missing_dpop` / `invalid_dpop_proof` / `replayed_dpop` / `missing_cnf` |
| Unspecified bind | `ValidateBind` (AI11) | process error |
| Cleartext or empty live JWT-SVID JWKS | URL policy + empty-JWKS fail-closed (AI17) | process error / `/readyz` 503 |
| Subverted but still-registered agent | Exact-ID denylist at mint and visor-gateway (AI18) | `agent_denied` / `workload_denied` / `principal_denied` |
| Tampered STS audit JSONL | Hash chain verified on open and on `trace` (AI20) | process / CLI error |

## Out of scope / honest limits

- Not a live SPIRE Workload API or node attestor. JWT-SVID verification is JWKS-based (file, `https` URL, or OIDC discovery).
- Not a host sandbox. A compromised workload that *is* registered for an agent can mint tokens for that agent until the workload or agent is denylisted.
- Not mcp-visor action policy. A valid actor chain can still be denied by visor tool rules.
- Revocation is TTL + durable `jti` replay at exchange plus an exact-ID denylist (agents, workloads, principals) at mint and at visor-gateway. Already-minted tokens are stopped at the PEP when the gateway re-reads the denylist.
- visor-gateway requires RFC 9449 DPoP bound to minted `cnf.jkt` (a workload-possessed key), including a server-issued nonce. STS exchange still uses `actor_token`, with optional token-endpoint DPoP to bind `cnf.jkt`. Residual PoP is accepted (AI23). This is not a Production identity plane.
- visor-gateway `-backend` is an HTTP reverse-proxy. mcp-visor `serve` is stdio; use `-identity-only` and `visor-session` to start visor with the derived `--client-id` / `--session-id`. Hand-starting visor with a typed `--client-id` is still spoofable.
- `-client-short-name` is opt-in. Last URI segments are not unique across prefixes; the default client-id is the full `act.sub`.
- Cross-domain federation (OAuth Identity Chaining) is not implemented.
- The STS/gateway audit hash chain is not a MAC. In-place edits fail
  closed. Tail truncation, emptying the file, or rewriting it with a
  freshly computed chain is not detected.

## Residual risk

A process that holds a valid workload key and a valid inbound subject token can mint the next hop until TTL/depth/scope **or the denylist** stop it. Detecting a *subverted but correctly attested* agent still needs that operator-supplied denylist (or visor policy). This repo does not invent a host sandbox. Theft of a minted JWT without the workload private key is stopped at visor-gateway by DPoP. A DPoP proof `jti` already in `-dpop-replay` is rejected. Resource proofs require a process-local nonce; restart forgets issued nonces, so a captured proof cannot be replayed from a lost `-dpop-replay` log. Two in-flight copies of the same proof can still race while that nonce is live. STS exchange is still `actor_token` with no token-endpoint nonce. Hand-starting visor with a typed `--client-id` remains spoofable. Those residuals are accepted (AI23). Operators reconstruct hops with `trace` after verifying the audit hash chain; unverified visor JSONL cannot choose the `jti`→`txn` mapping. A visor-gateway `-jwks` file copy keeps trusting a burned kid until that file is regenerated. Key-compromise steps are in [runbooks.md](runbooks.md). The visor-only operator path is [deploy.md](deploy.md).
