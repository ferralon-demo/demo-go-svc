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
# Env: GH_TOKEN (issues:write), REPORT (path to report.json), GITHUB_REPOSITORY.
set -euo pipefail

REPORT="${REPORT:?REPORT (path to report.json) is required}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
HANDLE="$(basename "$REPO")"               # the console /r/<handle> selector
CONSOLE_URL="https://console.ferralon.com/r/${HANDLE}"
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

➡️ **[Open this repository in the Ferralon console](${CONSOLE_URL})**

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
  num="$(gh issue create --repo "$REPO" --title "$TITLE" --body-file "$BODY_FILE" --json number --jq .number 2>/dev/null || true)"
  # Best-effort pin (org/repo may cap pinned issues at 3); never fail the run on it.
  if [[ "${num:-}" =~ ^[0-9]+$ ]]; then
    gh issue pin "$num" --repo "$REPO" 2>/dev/null || echo "(could not pin; continuing)"
  fi
fi
