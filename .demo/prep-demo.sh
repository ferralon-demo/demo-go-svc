#!/usr/bin/env bash
# prep-demo.sh (TEG-049) — reset `main` to the exact tree of the golden `vulnerable` branch.
#
# THE REPEATABLE-DEMO RITUAL. In the branch model this fixture uses:
#
#   vulnerable  = the GOLDEN reference. Hand-curated, honestly-vulnerable code for every
#                 demoed candidate (DoS unbounded sink, SSRF fetch route, the SSH hero, …)
#                 plus the canary / FIRING.md contract. NEVER fired against. NEVER accepts a
#                 merge — by convention and reactive CI, not by any hard gate.
#   main        = the DISPOSABLE fire target. Reset FROM vulnerable before each demo, fired
#                 against, then patched by the auto-prove fix-PR ("look — main is safe now").
#                 The next reset wipes it back to the golden baseline.
#
# This script performs that reset: it points `main` at `vulnerable`'s exact commit, so main's
# tree is byte-identical to the golden baseline every single time — deterministic and
# repeatable. A hard reset / force-push is used, NOT a merge: a merge accumulates history and
# cannot cleanly re-introduce the vuln over a previously-patched main.
#
# This reset is what makes the demo repeatable. It is NOT, on its own, what stops the golden
# branch self-patching (the 2026-07-13 saga where an auto-prove DoS fix was merged into
# vulnerable via PR #9). An earlier version of this header called that outcome "structurally
# impossible"; it is not. "Fire against main, never against vulnerable" is a convention the
# pipeline is asked to follow, not one anything checks — see DEMO.md § The protection posture
# for what is actually enforced, and docs/DECISIONS.md § A4 for the recorded correction.
#
# See DEMO.md for the full cycle and the Operator branch-protection handoff.
#
# ─────────────────────────────────────────────────────────────────────────────────────────
# SAFETY: this FORCE-PUSHES the default branch. It is DRY-RUN BY DEFAULT — it fetches, prints
# the exact plan and the main→vulnerable diff, and changes NOTHING. Pass --execute to actually
# reset + force-push (and it still asks you to type the branch name to confirm, unless --yes).
# ─────────────────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   .demo/prep-demo.sh                 # dry-run: show what a reset would do (default)
#   .demo/prep-demo.sh --execute       # live: reset+force-push main (typed confirmation)
#   .demo/prep-demo.sh --execute --yes # live: skip the interactive confirmation prompt
#
# Env overrides (rarely needed):
#   DEMO_REMOTE          (default: origin)
#   DEMO_GOLDEN_BRANCH   (default: vulnerable)
#   DEMO_TARGET_BRANCH   (default: main)
set -euo pipefail

REMOTE="${DEMO_REMOTE:-origin}"
GOLDEN="${DEMO_GOLDEN_BRANCH:-vulnerable}"
TARGET="${DEMO_TARGET_BRANCH:-main}"
EXECUTE=0
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --execute)  EXECUTE=1 ;;
    --yes|-y)   ASSUME_YES=1 ;;
    -h|--help)  sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "prep-demo: unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

banner() {
  echo "==============================================================================="
  echo "  $*"
  echo "==============================================================================="
}

# Always reset FROM the fresh remote golden tree, not a stale local copy.
echo "prep-demo: fetching $REMOTE …"
git fetch --prune "$REMOTE" >/dev/null 2>&1 || { echo "prep-demo: git fetch $REMOTE failed" >&2; exit 1; }

if ! git rev-parse --verify --quiet "$REMOTE/$GOLDEN" >/dev/null; then
  echo "prep-demo: golden branch '$REMOTE/$GOLDEN' not found — cannot reset from a missing baseline." >&2
  exit 1
fi
GOLDEN_SHA="$(git rev-parse "$REMOTE/$GOLDEN")"
GOLDEN_TREE="$(git rev-parse "$REMOTE/$GOLDEN^{tree}")"

if git rev-parse --verify --quiet "$REMOTE/$TARGET" >/dev/null; then
  TARGET_SHA="$(git rev-parse "$REMOTE/$TARGET")"
  TARGET_EXISTS=1
else
  TARGET_SHA="(does not exist yet — would be created)"
  TARGET_EXISTS=0
fi

banner "prep-demo — reset  $TARGET  ->  $GOLDEN's exact tree   [remote: $REMOTE]"
echo "  golden  $GOLDEN : $GOLDEN_SHA"
echo "          tree     : $GOLDEN_TREE"
echo "  target  $TARGET : $TARGET_SHA"
echo ""

# Idempotency: if main already points at vulnerable's tree, a reset is a no-op.
ALREADY_CLEAN=0
if [ "$TARGET_EXISTS" -eq 1 ] && git diff --quiet "$REMOTE/$TARGET" "$REMOTE/$GOLDEN"; then
  ALREADY_CLEAN=1
  echo "  ✓ $TARGET is ALREADY identical to $GOLDEN's tree — reset is a no-op (idempotent)."
elif [ "$TARGET_EXISTS" -eq 1 ]; then
  echo "  $TARGET differs from $GOLDEN — a reset would change:"
  git diff --stat "$REMOTE/$TARGET" "$REMOTE/$GOLDEN" | sed 's/^/      /'
else
  echo "  $TARGET does not exist on $REMOTE — a reset would CREATE it from $GOLDEN."
fi
echo ""

# The exact ref update this performs (both dry-run and live print it, so there are no surprises).
PUSH_PLAN="git push --force-with-lease $REMOTE $REMOTE/$GOLDEN:refs/heads/$TARGET"

if [ "$EXECUTE" -ne 1 ]; then
  banner "DRY-RUN — nothing changed. Re-run with --execute to reset + force-push $TARGET."
  echo "  Would run:  $PUSH_PLAN"
  echo "  Result:     $TARGET points at $GOLDEN ($GOLDEN_SHA); tree byte-identical to the golden baseline."
  exit 0
fi

if [ "$ALREADY_CLEAN" -eq 1 ]; then
  banner "DONE (no-op) — $TARGET was already at $GOLDEN's tree. Nothing to push."
  exit 0
fi

# ── LIVE path (Gene's to run when demoing) ──────────────────────────────────────────────────
banner "!!  LIVE  —  about to FORCE-PUSH the branch '$TARGET' to '$GOLDEN's tree' on '$REMOTE'  !!"
echo "  This DISCARDS whatever is on $REMOTE/$TARGET (e.g. a prior demo's merged fix-PR)."
echo "  It NEVER touches $GOLDEN — the golden baseline is read-only here."
echo ""
if [ "$ASSUME_YES" -ne 1 ]; then
  printf "  Type the target branch name (%s) to confirm the force-push: " "$TARGET"
  read -r reply
  if [ "$reply" != "$TARGET" ]; then
    echo "  confirmation mismatch — aborted, nothing pushed." >&2
    exit 1
  fi
fi

# --force-with-lease guards against a surprise concurrent move of the remote target between the
# fetch above and this push. Pushing the remote-tracking golden ref makes the update atomic and
# deterministic: main becomes vulnerable's exact commit.
if [ "$TARGET_EXISTS" -eq 1 ]; then
  git push --force-with-lease="$TARGET:$TARGET_SHA" "$REMOTE" "$REMOTE/$GOLDEN:refs/heads/$TARGET"
else
  # Creating the branch for the first time — no lease (there is no prior value to guard).
  git push "$REMOTE" "$REMOTE/$GOLDEN:refs/heads/$TARGET"
fi

banner "DONE — $TARGET now points at $GOLDEN ($GOLDEN_SHA)."
echo "  Fire against $TARGET. NEVER fire against, or merge into, $GOLDEN."
