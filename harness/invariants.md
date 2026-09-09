# Agent Identity Plane — Invariants

## AI1 — Verified workload credential

No token is minted unless the `actor_token` verifies against a configured
workload attestor (local Ed25519 keys or a SPIFFE JWT-SVID JWKS from a
file, `https` URL, or OIDC discovery). Reason code on failure:
`invalid_actor_token`.

## AI2 — Agent authorized on workload

The requested `agent_id` must be registered and list the attested workload
id in `workloads`. Reason codes: `agent_not_registered`,
`agent_not_authorized_on_workload`, `agent_not_yet_valid`, `agent_expired`.

## AI3 — Single-hop audience

Minted tokens have exactly one `aud` value, equal to the requested next hop.
That audience must be in the agent's `audiences` list. A token presented to
any other audience is rejected (`audience_mismatch` / `audience_not_allowed`).

## AI4 — Immutable principal and transaction

`sub` (originating user or system) and `txn` are copied from the verified
subject token on every hop. First hop mints a new `txn`. Reason code:
`principal_mutation` if a client attempts to override them.

## AI5 — Scope only narrows

Requested scopes must be a subset of the intersection of the incoming token
scope (if any) and the agent's `max_scopes`. Reason code: `scope_widening`.

## AI6 — Depth cap

`depth = len(actchain) + 1` (current actor counts). Depth must be `<=`
the agent's `max_depth`. Reason code: `depth_exceeded`.

## AI7 — Chain integrity

On a subsequent hop the subject token must be issued by this STS, its `aud`
must equal the requesting `agent_id`, and the new `actchain` is exactly
`append(incoming.actchain, incoming.act)`. Nested `act` (RFC 8693) is the
current actor wrapping the incoming `act`. Reason code: `chain_integrity`.

## AI8 — Audit before response

Every mint or deny writes a hash-linked JSONL record with a stable
`reason_code` before the HTTP response is sent, including HTTP-layer
denials that never enter `Exchange` (`rate_limited`, malformed form).
The audit log path must not alias the replay log. Recovered audit
records must be complete (hash-chain fields present). Allows `Sync()`
the file.

## AI9 — Deterministic receipts

Audit JSON uses struct field order and sorted scope/hop slices. Identical
inputs at a frozen clock produce byte-identical hash payloads (excluding
the hash chain fields themselves, which depend on history).

## AI10 — Fail closed

Unknown JSON fields, empty identifiers, inverted validity windows, `alg=none`,
algorithm confusion, unspecified bind addresses, trailing JSON (including
unmatched closers after a complete value), and aliased identity-file paths
(audit log, replay log, signing key, and other serve paths that resolve to
the same file) all fail closed. No partial token is issued.

## AI11 — Loopback-safe serve

`serve` rejects bind hosts that are empty or unspecified (`0.0.0.0`, `::`).
Default listen address is `127.0.0.1:8080`.

## AI12 — STS subject tokens are single-use at exchange

An STS-issued subject token (`jti`) is consumed on the first successful
exchange and remains consumed through the same `exp + ClockSkew` window
`ValidateTime` uses, including across process restart when a replay log
is configured. A second exchange with that `jti` in that window is
denied (`replayed_token`) and issues no token. Missing replay state, a
failed durable write, a foreign or incomplete replay JSONL, or a replay
path that aliases another exclusive identity file fail closed.
First-hop IdP user tokens are not consumed this way.

## AI13 — Rotatable signing JWKS

The STS signing ring may contain multiple Ed25519 kids. Minting uses
`active_kid`. A kid may become active only after it was already present
in the previously published JWKS (preload, then activate), with the
same public-key bytes. A published kid is that material, not a reusable
label: overlapping kids cannot change `x` (or other verification
fields). Verification JWKS includes every key in the ring so tokens
minted under a previous kid remain valid until that kid is removed,
which must wait mint TTL plus `ClockSkew`.

## AI14 — Reload is fail-closed

SIGHUP (or `Reloader.Reload`) loads every requested identity document
completely, then publishes registry, signing ring, and denylist under
one lock. An invalid document leaves the previous snapshot in place and
the process stays up. One request never observes a new registry with an
old signing ring or an old denylist, or the reverse.

## AI15 — Signing-key file mode

On-disk STS signing material must be a regular file that is not
group- or world-readable. Open modes fail closed at load and reload.

## AI16 — visor-gateway is the identity PEP

No request is forwarded to `-backend` without a verified STS actor
chain for the configured audience. The current actor, session/`txn`,
and principal must be present; an otherwise valid JWT with no `act`
is denied (`incomplete_chain`). `X-Visor-Client-Id` defaults to the
complete acting-agent URI (`act.sub`); last-segment short names are
opt-in because they can collide across prefixes. `X-Visor-Session-Id`
is `txn`. Both overwrite any caller-supplied values after hop-by-hop
header stripping, so a `Connection` listing those names cannot drop
them. The STS Bearer is consumed at the PEP and is not forwarded to
`-backend`. Missing or invalid Bearer tokens are denied and audited
(`identity_denied`) before the response. An unwritable audit sink
fails closed (no backend forward, no completed identity decision).
JWKS is re-read or fetched on each verify; JWKS URLs must be `https`
except loopback `http`.

## AI17 — Live workload JWKS is HTTPS (or loopback HTTP)

JWT-SVID verification may fetch JWKS from `-spiffe-jwks-url` or from
OIDC discovery (`-spiffe-oidc-issuer` → `{issuer}/.well-known/openid-configuration`
→ `jwks_uri`). Those URLs, and any redirect, must be `https` except
loopback `http`. TLS is 1.2+; bodies are capped at 1MiB; an empty
JWKS fails closed. Discovery `issuer` and JWT `iss` must equal the
configured issuer exactly (trailing slash is significant). Keys are
re-fetched on each `Attest`. `/readyz` fails if a live attestor cannot
load keys. This is not a SPIRE Workload API client.

## AI18 — Denylist is an exact-ID revocation signal

A configured denylist denies minting when `agent_id`, the attested
workload, or the verified principal matches an entry exactly
(trailing slash and last-segment short names are distinct IDs).
visor-gateway applies the same document on each verify to the
principal, the acting agent, and every hop after the principal
position (later hops are agents even if their URI equals `sub`).
Agent and workload entries must be parseable URIs (scheme and host).
Owned denylist JSON is strict-decoded. Empty lists are valid.
Agent, workload, and principal IDs contain no Unicode whitespace.
Unreadable denylist fails closed. The path must not alias other
exclusive identity files. This is not a Production claim.

## AI19 — visor-gateway DPoP is bound to minted `cnf.jkt`

Every minted STS token carries `cnf.jkt`, the RFC 7638 thumbprint of
the JWK that verified the actor token for that hop. visor-gateway
requires a `DPoP` proof JWT (`typ=dpop+jwt`) whose embedded public JWK
thumbprint equals that value. `htm` matches the request method. `htu`
is reconstructed from this request (https iff TLS is present, `Host`,
escaped path, no query or fragment). `X-Forwarded-*` is not used.
`ath` is SHA-256 of the access token. `iat` uses the same clock skew
as minted tokens. Proof `jti` is single-use in `-dpop-replay` through
`iat + ClockSkew`. The DPoP header JWK must be a public key. Missing
`cnf`, missing DPoP, invalid proof, or replay is denied with no
backend forward. `-dpop-replay` must not alias other exclusive
identity files. This is not a DPoP nonce deployment and not a
Production claim.

