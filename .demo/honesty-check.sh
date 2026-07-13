#!/usr/bin/env bash
# honesty-check.sh (TEG-049) — the honesty contract for demo-go-svc@vulnerable.
#
# WHY THIS EXISTS. `vulnerable` is the GOLDEN reference: it must stay genuinely, honestly
# vulnerable so a live Tegron fire produces a real proven apex. The failure mode this guards
# against (the 2026-07-13 saga): an auto-prove synthesized FIX — the `n > maxAlloc` upper bound
# on /expand — was merged back into `vulnerable` (PR #9 → 61d5334), so the baseline silently
# patched itself and every subsequent DoS fire honestly returned reasoned_not_exploitable
# against a no-longer-vulnerable target. The honesty wall was correct throughout; the FIXTURE
# was wrong. This check catches that drift at push / PR time, not mid-demo.
#
# HOW. It is a BLACK-BOX BEHAVIOURAL assertion, not a source grep: it builds and runs the real
# service and drives the real HTTP endpoints, observing that the vulnerable SINKS are still
# reachable and unguarded. It lives under .demo/ — a dot-directory that `go build ./...`,
# go/packages, and the scanner all skip — so it adds no app code and never pollutes the
# scanned app surface. It asserts nothing about a verdict; it only asserts the fixture is still
# what it claims to be.
#
# Bound to `vulnerable` only (see .github/workflows/honesty-contract.yml). It must NOT run on
# `main`: main is the disposable target and is SUPPOSED to be patched by the fix-PR.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(cd "$(dirname "$0")/.." && pwd)")"

HOST="127.0.0.1"
PORT="${HONESTY_HTTP_PORT:-8080}"
BASE="http://$HOST:$PORT"

BIN="$(mktemp -d)/demo-svc"
echo "honesty-check: building demo-go-svc …"
go build -o "$BIN" .

echo "honesty-check: starting the service on $BASE …"
"$BIN" >/tmp/honesty-demo-svc.log 2>&1 &
SVC_PID=$!
cleanup() { kill "$SVC_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait (≤5s) for the HTTP listener to accept.
up=0
for _ in $(seq 1 50); do
  if curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null; then up=1; break; fi
  sleep 0.1
done
if [ "$up" -ne 1 ]; then
  echo "honesty-check: service did not come up on $BASE — log:" >&2
  cat /tmp/honesty-demo-svc.log >&2 || true
  exit 1
fi

code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }

fail=0
echo ""
echo "── honesty contract ─────────────────────────────────────────────────────────────────"

# ── FERRALON-APP-DOS-0001 : /expand must be UNBOUNDED ───────────────────────────────────────
# An honest unbounded sink sizes make([]byte, n) straight from the caller's count. A count
# at/near math.MaxInt64 trips Go's recoverable "makeslice: len out of range" panic
# (host-RAM-independent — nothing is actually allocated) → the deferred recover → HTTP 500
# "allocation failed". A BOUNDED /expand (the drift) rejects the count up front with HTTP 400
# BEFORE allocating. So: 500 == honestly vulnerable; 400 == the fixture has self-patched.
dos_code="$(code "$BASE/expand?count=9223372036854775807")"
if [ "$dos_code" = "500" ]; then
  echo "  DOS   ✓  /expand?count=MaxInt64 -> 500  (unbounded sink faulted; honestly vulnerable)"
else
  echo "  DOS   ✗  /expand?count=MaxInt64 -> $dos_code  (want 500)" >&2
  echo "           /expand appears to BOUND count — the vulnerable baseline has SELF-PATCHED" >&2
  echo "           (this is exactly TEG-049 / PR #9). DoS fires will honestly return" >&2
  echo "           not_exploitable. Restore the unbounded  buf := make([]byte, n)  in expand.go." >&2
  fail=1
fi

# ── FERRALON-APP-SSRF-0001 : /preview must have NO allowlist ────────────────────────────────
# resolveTarget forwards ANY caller target verbatim into http.Get — there is no allowlist. An
# arbitrary, unroutable target therefore REACHES the sink and fails only at connect → HTTP 502
# "fetch failed" (proving the outbound request was actually made). An allowlist drift would
# reject the target up front with HTTP 400 "cannot resolve target" BEFORE any fetch. So: 502 ==
# sink reachable & unguarded; 400 == the fixture has grown a guard (self-patched). A loopback
# closed port is used so nothing leaves the runner.
ssrf_code="$(code "$BASE/preview?target=http://127.0.0.1:1/")"
if [ "$ssrf_code" = "502" ]; then
  echo "  SSRF  ✓  /preview?target=<arbitrary> -> 502  (reached unguarded outbound fetch; honestly vulnerable)"
else
  echo "  SSRF  ✗  /preview?target=<arbitrary> -> $ssrf_code  (want 502)" >&2
  echo "           /preview appears to GUARD the target (allowlist added?) — the SSRF sink is no" >&2
  echo "           longer reachable. Restore the unguarded http.Get in fetchHandler/resolveTarget." >&2
  fail=1
fi
echo "─────────────────────────────────────────────────────────────────────────────────────"

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "HONESTY CONTRACT VIOLATED — demo-go-svc@vulnerable is no longer honestly vulnerable." >&2
  echo "vulnerable is the golden reference and must never be patched. Fire against a reset 'main'" >&2
  echo "instead (see DEMO.md); never merge a fix into vulnerable." >&2
  exit 1
fi
echo "Honesty contract clean ✓ — vulnerable sinks reachable & unguarded (DoS unbounded, SSRF no allowlist)."
