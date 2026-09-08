# Agent Identity Plane — Invariants

## AI1 — Verified workload credential

No token is minted unless the `actor_token` verifies against a configured
workload attestor (local Ed25519 keys or a SPIFFE JWT-SVID JWKS bundle).
Reason code on failure: `invalid_actor_token`.

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
`reason_code` before the HTTP response is sent. Allows `Sync()` the file.

## AI9 — Deterministic receipts

Audit JSON uses struct field order and sorted scope/hop slices. Identical
inputs at a frozen clock produce byte-identical hash payloads (excluding
the hash chain fields themselves, which depend on history).

## AI10 — Fail closed

Unknown JSON fields, empty identifiers, inverted validity windows, `alg=none`,
algorithm confusion, unspecified bind addresses, and trailing JSON all fail
closed. No partial token is issued.

## AI11 — Loopback-safe serve

`serve` rejects bind hosts that are empty or unspecified (`0.0.0.0`, `::`).
Default listen address is `127.0.0.1:8080`.

## AI12 — STS subject tokens are single-use at exchange

An STS-issued subject token (`jti`) is consumed on the first successful
exchange. A second exchange with the same `jti` before expiry is denied
(`replayed_token`) and issues no token. First-hop IdP user tokens are not
consumed this way.

## AI13 — Rotatable signing JWKS

The STS signing ring may contain multiple Ed25519 kids. Minting uses
`active_kid`. Verification JWKS includes every key in the ring so tokens
minted under a previous kid remain valid until that kid is removed.

## AI14 — Reload is fail-closed

SIGHUP (or `Reloader.Reload`) loads the new registry and signing files
completely before swapping. An invalid document leaves the previous
snapshot in place and the process stays up.

## AI15 — Signing-key file mode

On-disk STS signing material must be a regular file that is not
group- or world-readable. Open modes fail closed at load and reload.

