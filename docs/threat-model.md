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
| Unspecified bind | `ValidateBind` (AI11) | process error |

## Out of scope / honest limits

- Not a live SPIRE Workload API or node attestor. JWT-SVID verification is JWKS-based and fixture-tested.
- Not a host sandbox. A compromised workload that *is* registered for an agent can mint tokens for that agent.
- Not mcp-visor action policy. A valid actor chain can still be denied by visor tool rules.
- Revocation is TTL + `jti` replay at exchange for STS-issued subject tokens; there is no agent denylist in v0.2.0.
- Proof-of-possession (WPT / DPoP) is not implemented; minted tokens are bearer tokens with short TTL and single audience.
- Cross-domain federation (OAuth Identity Chaining) is not implemented.

## Residual risk

A process that holds a valid workload key and a valid inbound subject token can mint the next hop until TTL/depth/scope stop it. Detecting a *subverted but correctly attested* agent requires an external signal (visor policy, human approval, or revocation) which this repo does not invent.
