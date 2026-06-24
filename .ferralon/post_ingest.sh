#!/usr/bin/env bash
# Requests a GitHub Actions OIDC token (audience = the Ferralon ingest audience),
# projects the scan's report.json into the thin ingest-payload.v0 allowlist, and POSTs
# it to the Ferralon Assessment backend's OIDC ingest endpoint.
#
# Identity C (the workload identity, ADR 0001): the runner proves WHICH repository/owner
# it is via the GitHub-signed OIDC token. The backend verifies that token (RS256 against
# GitHub's JWKS, iss/aud/exp), binds `repository_owner_id` to an ACTIVE install of the
# Ferralon App (403 otherwise), and cross-checks the payload `subject` against the token
# claims. The owner/repo/run identity the backend persists comes from the TOKEN, never
# from the body — the body `subject` is a declared-intent echo only.
#
# No source code or PII is sent — see build_ingest_payload.py (the data-plane minimizer).
#
# Env (auto-present when the job grants `id-token: write`):
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN
# Config:
#   FERRALON_INGEST_URL   the ingest endpoint (default: the documented prod endpoint).
#   FERRALON_INGEST_AUD   the OIDC audience the backend expects (default: ferralon-ingest).
#   REPORT                path to report.json.
set -euo pipefail

REPORT="${REPORT:?REPORT (path to report.json) is required}"
INGEST_URL="${FERRALON_INGEST_URL:-https://api.ferralon.com/ingest}"
AUD="${FERRALON_INGEST_AUD:-ferralon-ingest}"

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?id-token request url missing — grant 'id-token: write' to this job}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?id-token request token missing — grant 'id-token: write' to this job}"

echo "==> Requesting a GitHub Actions OIDC token (aud=${AUD}) ..."
oidc_token="$(curl -fsS \
  -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUD}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"

echo "==> Projecting report.json -> ingest-payload.v0 (thin allowlist; no source/PII) ..."
payload="$(python3 "$(dirname "$0")/build_ingest_payload.py" "$REPORT")"

echo "==> POST ${INGEST_URL}"
code="$(curl -sS -o /tmp/ingest-resp.json -w '%{http_code}' \
  -X POST "${INGEST_URL}" \
  -H "Authorization: Bearer ${oidc_token}" \
  -H "Content-Type: application/json" \
  --data-binary "${payload}")"

echo "    HTTP ${code}"
echo "    response: $(cat /tmp/ingest-resp.json 2>/dev/null || true)"
case "$code" in
  200|201|202) echo "==> Ingest accepted." ;;
  *) echo "ERROR: ingest rejected (HTTP ${code})." >&2; exit 1 ;;
esac
