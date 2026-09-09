# Deploy (v1.0 visor-only path)

This is the supported operator path: STS on loopback, visor-gateway as
the identity PEP, `visor-session` (or visor-gateway `-backend`) as the
only `--client-id` start. Typing `mcp-visor serve -client-id …` by hand
is still spoofable.

This version is operator-ready (denylist, replay, DPoP nonce, runbooks).
It is not a Production claim: a live visor-only instance is an operator
choice, not something this repository runs.

Binds must be explicit unicast hosts. Default listen addresses are
loopback. Do not use `0.0.0.0` or `[::]`. Incident procedures are in
[runbooks.md](runbooks.md).

This repository does not ship STS, IdP, or workload private keys.
`testdata/` has only `registry.json` and `denylist.json`. Generate key
material locally (`keys generate` writes mode `0600`; `keys jwks`
emits public verification JWKS with no `d`).

## Loopback visor-only stack

```bash
mkdir -p ./run
agent-identity-plane keys generate -kid sts-1 -out ./run/sts.json
agent-identity-plane keys generate -kid idp-1 -out ./run/idp.json
agent-identity-plane keys generate -kid wl-oncall -sub spiffe://example.test/workload/oncall -out ./run/wl-oncall.json
agent-identity-plane keys generate -kid wl-invest -sub spiffe://example.test/workload/investigation -out ./run/wl-invest.json
agent-identity-plane keys generate -kid wl-monitor -sub spiffe://example.test/workload/monitoring -out ./run/wl-monitor.json
agent-identity-plane keys jwks -in ./run/idp.json -out ./run/idp-jwks.json
agent-identity-plane keys jwks \
  -in ./run/wl-oncall.json \
  -in ./run/wl-invest.json \
  -in ./run/wl-monitor.json \
  -out ./run/workloads.json

agent-identity-plane serve \
  -listen 127.0.0.1:8080 \
  -registry testdata/registry.json \
  -issuer https://sts.example.test \
  -signing-key ./run/sts.json \
  -workload-keys ./run/workloads.json \
  -idp-jwks ./run/idp-jwks.json \
  -idp-issuer https://idp.example.test \
  -audit-log ./run/sts-audit.jsonl \
  -replay-log ./run/sts-replay.jsonl \
  -denylist testdata/denylist.json

agent-identity-plane visor-gateway \
  -listen 127.0.0.1:8090 \
  -audience https://mcp-gateway.example.test \
  -issuer https://sts.example.test \
  -jwks-url http://127.0.0.1:8080/jwks.json \
  -identity-only \
  -audit-log ./run/gateway-audit.jsonl \
  -denylist testdata/denylist.json \
  -dpop-replay ./run/gateway-dpop.jsonl

agent-identity-plane visor-session \
  -gateway http://127.0.0.1:8090/session \
  -token "$JWT" \
  -dpop-key ./run/wl-invest.json \
  -visor-bin mcp-visor \
  -- -policy policy.yaml
```

`$JWT` is an STS-minted access token for audience
`https://mcp-gateway.example.test`, not a file in this repo. Actor
tokens are signed with the workload private keys above; first-hop user
tokens must verify against `./run/idp-jwks.json`.

`visor-session` POSTs the access token with DPoP and retries once on
`use_dpop_nonce`. Identity flags come only from that mapping.

For an HTTP MCP front, use visor-gateway `-backend` instead of
`-identity-only` / `visor-session`. visor stdio is not an HTTP backend.

## Residual proof-of-possession (accepted)

- Two in-flight copies of the same DPoP proof can race while that nonce
  is live; proof-jti consume allows only one.
- STS `POST /oauth/token` still uses `actor_token` and does not require
  a DPoP nonce.
- Hand-starting visor with a typed `--client-id` remains spoofable.
- The audit hash chain is not a MAC.

`demo -strict` exercises mint, deny, `trace`, visor-gateway identity-only
Fetch (including nonce retry), and rejection of a typed `--client-id`
without operator key files.
