#!/usr/bin/env bash
# Branding wall (AGA-003 AC4): the internal engine codename must be ABSENT from every
# customer-facing surface this repository AUTHORS — the scan workflow, the pivot Issue
# template/filer, the ingest projector, and the customer-facing README.
#
# Scope rationale (read before widening): this greps the AUTHORED TEXT surfaces, not
# compiled blobs. The prebuilt scanner under bin/ is a vendored compiled artifact whose
# internal Go symbol/import-path strings still contain the codename (a plain stealth
# build is NOT scrubbed at rest — only a garble-hardened or Ferralon-brand engine build
# is; that hardening is the binary-distribution follow-on, see FERRALON_SCAN.md). Those
# symbols are never RENDERED to a customer, so they are out of scope for the wall here;
# bin/ is excluded deliberately, not by oversight.
#
# Likewise the engine's OWN run output (report.json on refs/tegron/state, the Tier-0 job
# summary) can carry the codename via the engine's synthetic demo-advisory ids; that is
# engine-produced data consumed as-is (consume-not-modify) and is surfaced as an
# engine-coordination item in the AGA-003 report — it is not an authored surface.
set -euo pipefail
cd "$(dirname "$0")/.."

CODENAME='tegron'   # the internal engine codename — must not appear on authored surfaces
SURFACES=(
  ".github/workflows"
  ".ferralon/file_pivot_issue.sh"
  ".ferralon/build_ingest_payload.py"
  ".ferralon/post_ingest.sh"
  "FERRALON_SCAN.md"
)
# (check_branding.sh itself is excluded — it must name the codename literal to check for
# it; it is not a customer-facing surface.)

# Allowlisted literals — these are STABLE CROSS-TEAM CONTRACT IDENTIFIERS that
# intentionally retain the "tegron" token even in brand-stealth builds; they are not
# brand surfaces:
#   - refs/tegron/state   the StateStore git ref the backend reader keys off (plumbing;
#                         pinned by Operator/Eric agreement, backend ADR-0015 2026-06-17).
#   - tegron.report.v1    the on-disk report SCHEMA id downstream consumers key off
#                         (the contract explicitly retains it in stealth builds).
ALLOW='refs/tegron/state|tegron\.report\.v1'

hits="$(grep -rinE "$CODENAME" "${SURFACES[@]}" 2>/dev/null | grep -viE "$ALLOW" || true)"

if [ -n "$hits" ]; then
  echo "BRANDING WALL VIOLATION — engine codename found on an authored customer surface:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "Branding wall clean ✓ — codename '${CODENAME}' absent from authored surfaces (refs/tegron/state plumbing literal allowlisted)."
