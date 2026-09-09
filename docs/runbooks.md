# Operator runbooks (v0.7)

These procedures use the shipped CLI. This is still not a Production
identity plane: there is no DPoP nonce, and visor `--client-id` is
authentic only when visor-gateway is the only path that sets it.

## Incident reconstruction

Every STS and visor-gateway decision is a hash-linked JSONL record
(`-audit-log`). `trace -audit` is always that Event stream: any line
that is not a complete audit record is a chain break. Only `-visor`
may be generic JSONL (mcp-visor does not hash-chain). A broken
`prev_hash`, `chain_index`, or payload `hash` is a hard fail; do not
reconstruct from a tampered STS/gateway file.

The chain is not a MAC. In-place payload edits fail closed. Truncating
the tail, emptying the file, or rewriting the whole log with a freshly
computed chain looks genuine; opening the log appends onto whatever
suffix remains. Keep the file on integrity-protected storage and copy
it off-box. Hashed Event strings are valid UTF-8 and length-bounded:
invalid or oversized request fields are replaced/truncated before
hashing so a deny that copied form fields cannot make the log
unverifiable.

A stolen compact JWT still carries `jti` and `txn`. Inspect first,
then reconstruct:

```bash
agent-identity-plane token inspect "$STOLEN_JWT"
agent-identity-plane trace -jti "$JTI" -audit ./sts-audit.jsonl [-visor ./visor.jsonl]
agent-identity-plane trace -txn "$TXN" -audit ./sts-audit.jsonl [-visor ./visor.jsonl]
```

`-jti` maps jti→txn from verified `-audit` records only, then returns
every verified record for that transaction plus visor lines whose
`txn` or `session_id` equals it. Verified records that carry the jti
but no txn (an IdP user token) are still returned. Unverified visor lines cannot choose
the transaction. Output labels `verified=` / `unverified=` and the
source path. Gateway allow/deny records are in the gateway
`-audit-log`; pass that path as `-audit` when the incident is at the PEP.
Once a subject JWT verifies, STS and visor-gateway denials record that
`txn`/`jti` so a stolen-token lookup includes failed hops.

## Key compromise (STS signing key)

Compromise recovery is not routine rotation. visor-gateway re-fetches
JWKS on every verify, so a burned kid that remains published still
lets an attacker forge tokens. Drop that kid as soon as the
replacement is active, even though in-flight tokens under the burned
kid will fail verify.

1. Treat the key as burned. Do not keep minting with it.
2. Preload a new kid (same file, `active_kid` still the old kid), `kill -HUP`.
   Until you activate, the STS still mints under the burned `active_kid`.
   Wait until visor-gateway has the new public key: `-jwks-url` re-reads
   on each verify; a `-jwks` file copy does not, so regenerate that file
   from the STS public JWKS and replace it atomically before activate.
3. Activate the new kid (`active_kid` already in the previous JWKS),
   `kill -HUP`.
4. Remove the burned kid from the keyring immediately, `kill -HUP`.
   Do not wait `KeyRetirementWait`; that wait is for planned rotation
   only (see [operations.md](operations.md)).
   If visor-gateway uses `-jwks`, regenerate that file again so it no
   longer contains the burned kid. Until that copy is replaced, the
   gateway keeps trusting the burned key.
5. Trace recent mints (`trace -txn` / `-jti`) if you need the actor
   chains issued under the burned key.
6. If a workload or agent was the cause, denylist it (below) so the PEP
   stops in-flight hops without waiting for TTL.

## Key compromise (workload key)

A process that holds a registered workload private key can mint until
the denylist says otherwise. DPoP does not stop that process; it stops
theft of a minted JWT *without* that key.

1. Add the workload URI (and the agent URI if the agent is burned) to
   `-denylist`. Exact IDs only.
2. `kill -HUP` the STS. visor-gateway re-reads the denylist on each
   request; already-minted tokens fail at the PEP.
3. Rotate the workload key out of `-workload-keys` or the live JWT-SVID
   JWKS source.
4. Trace the `jti` / `txn` values you still have to see what was minted.

## Residual proof-of-possession

visor-gateway requires RFC 9449 DPoP bound to minted `cnf.jkt`. There
is no DPoP nonce. A proof `jti` already consumed in `-dpop-replay` is
rejected. An intercepted proof can still win a race before that first
consume, or be replayed if the durable log is lost before
`iat + ClockSkew`. STS exchange still uses `actor_token`;
token-endpoint DPoP only binds `cnf.jkt` for hops whose actor token is
not a possessed key (JWT-SVID).
