# Token profile

Minted tokens are compact JWS JWTs. The STS signs only with EdDSA (Ed25519). A keyring may list several kids;
minting uses `active_kid`. Verification accepts EdDSA, ES256 (P-256), and
RS256 so JWT-SVIDs from a SPIRE OIDC JWKS bundle can be used as actor tokens.

## Header

```json
{"alg":"EdDSA","typ":"JWT","kid":"sts-1"}
```

`alg=none` is rejected. The header `alg` must match the selected JWK key type
(algorithm confusion is a hard fail).

## Claims (minted STS token)

| Claim | Rule |
|---|---|
| `iss` | STS issuer URL |
| `sub` | Originating principal; copied on every hop |
| `aud` | JSON string, exactly one next hop |
| `exp` / `nbf` / `iat` | Unix seconds; default TTL 120s; 30s skew |
| `jti` | Unique per mint |
| `txn` | Transaction id; minted on first hop, copied after |
| `act` | RFC 8693 actor object: current agent, nested prior `act` |
| `actchain` | Flat prior actors (incoming `actchain` + incoming `act`) |
| `scope` | Space-separated; only narrows |
| `purp` | Optional intent, copied if unset |
| `cnf.jkt` | RFC 7638 SHA-256 thumbprint of the actor-token verification key (this hop) |

First-hop user tokens come from a trusted IdP JWKS. They MUST have `aud` equal
to the requesting `agent_id` and MUST NOT carry `act` / `actchain`.

Actor tokens (workload credentials) MUST have `aud` equal to the STS issuer
and `sub` equal to the workload identifier (`spiffe://…` for the SPIFFE
attestor). Live JWT-SVID JWKS may come from a file, an `https` URL
(loopback `http`), or OIDC discovery; that is still JWKS verification,
not a Workload API call.

## Actor chain reconstruction

Verified hops:

```text
Hops = [sub] + actchain[].sub + act.sub
Depth = len(actchain) + 1
```

Example after oncall → investigation → mcp-gateway:

```text
sub = user1
actchain = [{sub: oncall-agent}]
act = {sub: investigation-agent, act: {sub: oncall-agent}}
Hops = user1 > oncall-agent > investigation-agent
```
