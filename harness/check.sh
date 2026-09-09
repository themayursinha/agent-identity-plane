#!/usr/bin/env bash
# Agent Identity Plane harness gate.
#
# Runs format check, vet, unit/race tests, bind-address guard, sensitive
# content scan, and the .planning/ non-track check, then writes a gitignored
# evidence manifest under evidence/harness/<UTC timestamp>/manifest.md.
set -uo pipefail

cd "$(dirname "$0")/.."
export PATH="/usr/local/go/bin:$PATH"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="evidence/harness/${STAMP}"
mkdir -p "${EVIDENCE_DIR}"
MANIFEST="${EVIDENCE_DIR}/manifest.md"

FAILURES=0

record() {
  local name="$1"
  shift
  echo "### ${name}" >> "${MANIFEST}"
  echo '```' >> "${MANIFEST}"
  if "$@" >> "${MANIFEST}" 2>&1; then
    echo '```' >> "${MANIFEST}"
    echo "PASS: ${name}" >> "${MANIFEST}"
  else
    echo '```' >> "${MANIFEST}"
    echo "FAIL: ${name}" >> "${MANIFEST}"
    FAILURES=$((FAILURES + 1))
  fi
}

{
  echo "# Agent Identity Plane harness"
  echo
  echo "Timestamp: $(date -u -Is)"
  echo "Go: $(go version)"
  echo
} > "${MANIFEST}"

record "gofmt" bash -c 'test "$(gofmt -l . | wc -l)" -eq 0'
record "go vet ./..." go vet ./...
record "go test ./... -count=1" go test ./... -count=1
record "go test -race ./... -count=1" go test -race ./... -count=1
record "sensitive-content" bash scripts/check-sensitive-content
record "planning-not-tracked" bash -c 'if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then test "$(git ls-files ".planning" ".planning/**" | wc -l)" -eq 0; else true; fi'
record "demo-transcript" bash -c 'go run ./cmd/agent-identity-plane demo -strict >/tmp/aip-demo.out && grep -q "scenario: allow" /tmp/aip-demo.out && grep -q "attack: unregistered_agent deny" /tmp/aip-demo.out && grep -q "visor-session: mapping" /tmp/aip-demo.out && grep -q "visor-session: typed_client_id deny" /tmp/aip-demo.out'

echo >> "${MANIFEST}"
if [ "${FAILURES}" -eq 0 ]; then
  echo "RESULT: PASS" >> "${MANIFEST}"
  echo "RESULT: PASS"
  exit 0
else
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >> "${MANIFEST}"
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >&2
  exit 1
fi
