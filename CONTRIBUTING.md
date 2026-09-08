# Contributing

Run the harness before opening a pull request:

```bash
harness/check.sh
```

That gate is `gofmt`, `go vet`, unit tests, race tests, golden fixtures, a sensitive-content scan, and a check that `.planning/` is not tracked.

Do not commit:

- `.planning/` (local roadmap only)
- `evidence/`
- keys, PEM files, or live audit JSONL
- local filesystem paths

Keep the core module standard-library only.
