# Operator runbooks (v0.7)

These procedures use the shipped CLI. This is still not a Production
identity plane: there is no DPoP nonce, and visor `--client-id` is
authentic only when visor-gateway is the only path that sets it.

## Incident reconstruction

Every STS and visor-gateway decision is a hash-linked JSONL record
(`-audit-log`). `trace` verifies that chain before printing hops. A
broken `prev_hash`, `chain_index`, or payload `hash` is a hard fail;
do not reconstruct from a tampered file.

A stolen compact JWT still carries `jti` and `txn`. Inspect first,
then reconstruct:

```bash
agent-identity-plane token inspect "$STOLEN_JWT"
agent-identity-plane trace -jti "$JTI" -audit ./sts-audit.jsonl [-visor ./visor.jsonl]
agent-identity-plane trace -txn "$TXN" -audit ./sts-audit.jsonl [-visor ./visor.jsonl]
```

`-jti` returns every STS record for the transaction that minted that
token (later hops included), plus visor lines whose `session_id`
equals that `txn`. Gateway allow/deny records are in the gateway
`-audit-log`; pass that path as `-audit` when the incident is at the PEP.

## Key compromise (STS signing key)

1. Treat the key as burned. Do not keep minting with it.
2. Preload a new kid (same file, `active_kid` still the old kid), `kill -HUP`.
   Wait until visor-gateway has fetched the new JWKS (it re-reads on
   each verify).
3. Activate the new kid (`active_kid` already in the previous JWKS),
   `kill -HUP`.
4. Wait at least mint TTL plus clock skew (`KeyRetirementWait`, default
   150s) so in-flight tokens under the old kid expire.
5. Remove the old private key from the keyring, `kill -HUP`.
6. Trace recent mints (`trace -txn` / `-jti`) if you need the actor
   chains issued under the burned key.
7. If a workload or agent was the cause, denylist it (below) so the PEP
   stops in-flight hops without waiting for TTL.

See [operations.md](operations.md) for the preload/activate/retire
contract.

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
is no DPoP nonce. An intercepted proof can be replayed until
`-dpop-replay` still holds that proof `jti` (`iat + ClockSkew`) or the
process loses the log. STS exchange still uses `actor_token`;
token-endpoint DPoP only binds `cnf.jkt` for hops whose actor token is
not a possessed key (JWT-SVID).
