#!/usr/bin/env bash
# Files (or updates) the Ferralon pinned "pivot" Issue from the scan's report.json.
#
# This is a CUSTOMER-FACING surface, so it is FERRALON-BRANDED and CODENAME-FREE by
# construction: it summarizes only the three honest deterministic verdict COUNTS
# (reachable candidate / not exploitable / disqualified) and never echoes individual
# advisory ids (the free-scan engine seeds synthetic demo-advisory ids that carry the
# internal engine codename — they stay out of every surface Ferralon authors). It
# frames findings as CANDIDATES, never as proofs of exploitability, and pivots to the
# Ferralon console for the full assessment + the consented paid escalation.
#
# Idempotent: a hidden marker locates a prior Issue to update in place, so re-runs do
# not pile up duplicate Issues.
#
# Run-addressable links (ADR 0023 D5): the run-snapshot push (post_runs.sh) runs BEFORE
# this step and returns the backend-minted handle + the authoritative run_id, threaded in
# as FERRALON_RUN_HANDLE / FERRALON_RUN_ID. The console URL is Notion-style: a DECORATIVE
# slug (basename of the repo) is prepended to the real handle as "<slug>-<handle>" — the
# backend ignores the slug and resolves by the trailing handle, so a renamed repo's stale
# slug still resolves. We emit TWO links: the baseline bookmark (/r/<slug>-<handle>) and
# the frozen view of the exact run this Issue reports (/r/<slug>-<handle>/runs/<run_id>).
# If the push did not yield a handle + run_id we FAIL — never a fabricated/guessed URL.
#
# Env: GH_TOKEN (issues:write), REPORT (path to report.json), GITHUB_REPOSITORY,
#      FERRALON_RUN_HANDLE + FERRALON_RUN_ID (from the post_runs.sh push step).
set -euo pipefail

REPORT="${REPORT:?REPORT (path to report.json) is required}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
RUN_HANDLE="${FERRALON_RUN_HANDLE:?FERRALON_RUN_HANDLE is required (from the run-snapshot push) — refusing to emit a fabricated URL}"
RUN_ID="${FERRALON_RUN_ID:?FERRALON_RUN_ID is required (from the run-snapshot push) — refusing to emit a fabricated URL}"
SLUG="$(basename "$REPO")"                 # decorative Notion-style slug; backend ignores it
PRETTY="${SLUG}-${RUN_HANDLE}"             # the console /r/<slug>-<handle> selector
CONSOLE_URL="https://console.ferralon.com/r/${PRETTY}"                    # baseline bookmark
RUN_URL="https://console.ferralon.com/r/${PRETTY}/runs/${RUN_ID}"        # this frozen run
MARKER="<!-- ferralon-assessment-pivot -->"
TITLE="Ferralon Assay - dependency advisory candidates"

# Honest verdict counts (candidate framing). No advisory ids are read out.
counts="$(python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
c = {"reachable_candidate": 0, "not_exploitable": 0, "disqualified": 0}
for f in r.get("advisories", []):
    v = f.get("verdict")
    if v in c:
        c[v] += 1
pkgs = len(r.get("sbom", {}).get("packages", []))
print(c["reachable_candidate"], c["not_exploitable"], c["disqualified"], pkgs)
' "$REPORT")"
read -r REACH NOTEXP DISQ PKGS <<<"$counts"

BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT
cat > "$BODY_FILE" <<EOF
${MARKER}
## Ferralon Assay

A free, deterministic dependency-advisory scan ran in this repository own runner.
No source code leaves your environment - the scan reads your dependency graph and the
public advisory feeds, and reports **candidates for review, never claims of
exploitability**.

**This run, over ${PKGS} resolved dependencies:**

| Outcome | Count | Meaning |
|---|---:|---|
| Reachable candidate | ${REACH} | A path to the vulnerable symbol was found. A **candidate** for review - not a proof it is exploitable. |
| Not exploitable | ${NOTEXP} | The advisory applies, but the vulnerable code is provably absent or unreachable here. |
| Disqualified | ${DISQ} | The advisory provably does not apply (resolved version outside the affected range). |

Reachability grade and EPSS/KEV are **evidence-strength and in-the-wild context** - not
proofs of exploitability for this codebase.

### See the full assessment

➡️ **[Open this repository in the Ferralon console](${CONSOLE_URL})** - the latest
baseline posture for this repository (a stable bookmark that tracks the newest run).

🔎 **[View the exact run this Issue reports](${RUN_URL})** - the frozen snapshot of this
specific scan, preserved for reference even as later runs update the baseline.

The console shows the per-advisory reasoning, the call paths behind each reachable
candidate, and - with your consent - the paid **Prove** escalation that produces a
reproducible Proof of Exploitability (or a Proof of Non-Exploitability) for a chosen
candidate.

<sub>Filed automatically by the Ferralon Assay workflow. Re-runs update this Issue in place.</sub>
EOF

existing="$(gh issue list --repo "$REPO" --state open --search "$MARKER in:body" \
  --json number,body --jq "map(select(.body | contains(\"$MARKER\"))) | .[0].number" 2>/dev/null || true)"

if [ -n "${existing:-}" ] && [ "$existing" != "null" ]; then
  echo "Updating existing pivot Issue #${existing} ..."
  gh issue edit "$existing" --repo "$REPO" --title "$TITLE" --body-file "$BODY_FILE"
else
  echo "Creating the pivot Issue ..."
  # gh issue create has no --json/--jq; it prints the new Issue's URL on stdout on success.
  # Capture it and assert it is a real GitHub issues URL so a silent create failure fails the step.
  issue_url="$(gh issue create --repo "$REPO" --title "$TITLE" --body-file "$BODY_FILE")"
  if [[ ! "$issue_url" =~ ^https://github\.com/.+/issues/[0-9]+$ ]]; then
    echo "gh issue create did not return an issue URL; got: '${issue_url}'" >&2
    exit 1
  fi
  echo "Filed pivot Issue: ${issue_url}"
  num="${issue_url##*/}"
  # Best-effort pin (org/repo may cap pinned issues at 3); never fail the run on it.
  if [[ "${num:-}" =~ ^[0-9]+$ ]]; then
    gh issue pin "$num" --repo "$REPO" 2>/dev/null || echo "(could not pin; continuing)"
  fi
fi
