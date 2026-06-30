#!/usr/bin/env bash
# Pushes the run's FULL report.json to the Ferralon Assessment backend's run-snapshot
# endpoint (POST /runs) and captures the returned {handle, run_id} so the pivot Issue can
# link the exact, frozen run this Assay produced (ADR 0023 D5 — the run-addressability
# contract). This PARALLELS post_ingest.sh: same Actions OIDC token, same audience
# (ferralon-ingest) — but it sends the FULL tegron.report.v1 report.json (the verdict
# layer, stored verbatim), NOT the thin ingest-payload.v0 projection. The two paths are
# distinct: /ingest is the durable lakehouse metadata feed (data-minimized), /runs is the
# verbatim per-run snapshot the console serves at a run-scoped URL.
#
# Identity C (the workload identity, ADR 0001): the runner proves WHICH repository/owner
# it is via the GitHub-signed OIDC token. The backend verifies that token (RS256 against
# GitHub's JWKS, iss/aud/exp), binds repository_owner_id to an ACTIVE install of the
# Ferralon App (403 otherwise), and takes the run identity (owner, repo, run_id) from the
# VERIFIED token — never from the body. So the backend-echoed run_id is AUTHORITATIVE (it
# equals github.run_id); this script uses what the backend returns, it does not invent or
# reformat it.
#
# On a 200 the script emits handle/run_id as GitHub step outputs (and to stdout) for the
# downstream pivot-Issue step. Any non-200 FAILS the step — errors are never swallowed,
# and no handle is ever fabricated.
#
# Env (auto-present when the job grants `id-token: write`):
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN
# Config:
#   FERRALON_RUNS_URL   the run-snapshot endpoint (default: the documented prod endpoint).
#   FERRALON_RUNS_AUD   the OIDC audience the backend expects (default: ferralon-ingest —
#                       deliberately the SAME audience as /ingest).
#   REPORT              path to report.json (the full tegron.report.v1 verdict layer).
set -euo pipefail

REPORT="${REPORT:?REPORT (path to report.json) is required}"
RUNS_URL="${FERRALON_RUNS_URL:-https://api.ferralon.com/runs}"
AUD="${FERRALON_RUNS_AUD:-ferralon-ingest}"

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?id-token request url missing — grant 'id-token: write' to this job}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?id-token request token missing — grant 'id-token: write' to this job}"

echo "==> Requesting a GitHub Actions OIDC token (aud=${AUD}) ..."
oidc_token="$(curl -fsS \
  -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUD}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"

echo "==> POST ${RUNS_URL} (full report.json — the verbatim run snapshot)"
code="$(curl -sS -o /tmp/runs-resp.json -w '%{http_code}' \
  -X POST "${RUNS_URL}" \
  -H "Authorization: Bearer ${oidc_token}" \
  -H "Content-Type: application/json" \
  --data-binary "@${REPORT}")"

echo "    HTTP ${code}"
echo "    response: $(cat /tmp/runs-resp.json 2>/dev/null || true)"
if [ "$code" != "200" ]; then
  echo "ERROR: run-snapshot push rejected (HTTP ${code})." >&2
  exit 1
fi

# Pull the backend-authoritative handle + run_id out of the 200 body. Fail the step (not a
# fabricated link) if either is missing — the contract guarantees both on a 200.
read -r handle run_id <<<"$(python3 -c '
import json, sys
r = json.load(open("/tmp/runs-resp.json"))
h, rid = r.get("handle"), r.get("run_id")
if not h or not rid:
    sys.stderr.write("missing handle/run_id in 200 response\n"); sys.exit(1)
print(h, rid)
')"

echo "==> Run snapshot accepted — handle=${handle} run_id=${run_id}"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "handle=${handle}"
    echo "run_id=${run_id}"
  } >> "$GITHUB_OUTPUT"
fi
