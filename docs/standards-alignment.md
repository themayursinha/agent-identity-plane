# Standards alignment

This implementation composes existing standards. It does not claim to be a
complete AIMS or WIMSE deployment.

| Source | What we take | What we do not implement |
|---|---|---|
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange | `subject_token` / `actor_token`, nested `act` | Full OAuth AS feature set, `may_act`, RFC 9068 access-token profile |
| [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) / [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | `cnf.jkt` on minted STS tokens | Confirmation methods other than JWK thumbprint |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP | visor-gateway `DPoP` header, `htm`/`htu`/`ath`/`jti`/`iat`, proof-jti replay; token-endpoint DPoP (`ath` omitted) to bind `cnf.jkt`; `token_type` DPoP with `Authorization` DPoP or Bearer | DPoP nonce, WPT |
| [draft-klrc-aiagent-auth-03](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) AIMS | Agents are workloads; WIMSE-style URIs; OAuth as delegation; audit minimums (agent id, delegated subject, resource, action, decision) | Browser authorization-code UX, transaction-token replacement flow, WPT |
| [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | Immutable `sub`/`txn`, short-lived context tokens | Full Txn-Token processing, `purp` authorization semantics |
| [draft-oauth-transaction-tokens-for-agents-06](https://www.ietf.org/archive/id/draft-oauth-transaction-tokens-for-agents-06.html) | Flat `actchain` plus current `act` | Replacement-flow TTS specifics |
| WIMSE identifier / workload-creds / WPT | URI identifiers; JWT-SVID-shaped actor tokens; OIDC JWKS discovery for those tokens | X.509 SVIDs, Workload Proof Tokens, mTLS, SPIRE Workload API |
| mcp-visor threat model | Spoofed `--client-id` is unauthenticated | In-proxy `lineage_require` (proposed in visor-integration.md). visor-session is the supported authentic start without changing visor. |

Differentiation versus related OSS (Charon, PingFederate demos, KAIF): this
repo is Go, standard-library only, deterministic, fail-closed, and designed as
the identity half of an existing MCP policy proxy rather than a replacement
for it.
