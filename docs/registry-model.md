# Registry model

The agent registry is a strict JSON document (`encoding/json` with
`DisallowUnknownFields`). Trailing JSON, unknown fields, duplicate agent ids,
empty identifiers, `max_depth < 1`, missing workloads or audiences, non-URI
ids, and inverted `created_at`/`expiry` windows fail closed at load.

```json
{
  "version": 1,
  "agents": [
    {
      "id": "spiffe://example.test/agent/oncall",
      "workloads": ["spiffe://example.test/workload/oncall"],
      "audiences": ["spiffe://example.test/agent/investigation"],
      "max_scopes": ["mcp:github:pr", "mcp:alerts:read"],
      "max_depth": 4,
      "created_at": "2026-01-01T00:00:00Z",
      "expiry": "2027-01-01T00:00:00Z"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Stable agent URI (WIMSE-style). This is `agent_id` on exchange. |
| `workloads` | Workload identifiers that may host this agent (AI2) |
| `audiences` | Allowed next-hop audiences (AI3) |
| `max_scopes` | Ceiling for minted `scope` (AI5) |
| `max_depth` | Max agent hops including the current actor (AI6) |
| `created_at` / `expiry` | RFC3339 half-open window `[created_at, expiry)` |

`agent-identity-plane registry lint FILE` is the fail-closed loader.
