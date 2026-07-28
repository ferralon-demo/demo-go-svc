# Running demo-go-svc as a repeatable Tegron demo

This repo is a fireable Tegron fixture. This runbook is how you demo it **repeatably** — how to
reset it to a known-vulnerable baseline, fire the auto-prove pipeline against it, show the fix
land, and reset for the next time — without the baseline ever silently patching itself.

> **Why this document exists.** On 2026-07-13 an auto-prove synthesized DoS *fix* (an upper
> bound on `/expand`'s `count`) was merged back into the `vulnerable` branch (PR #9). The
> baseline patched *itself*, and every subsequent DoS fire honestly returned
> `reasoned_not_exploitable` against a target that was no longer vulnerable. The honesty wall
> was right; the fixture was wrong. The branch model below is what keeps that from recurring.
>
> **Read the model as a convention plus two CI backstops, not as a hard guarantee.** "Fire
> against `main`, never against `vulnerable`" is the *intended* deepest protection, but it is
> not enforced by any code in this repository or in the pipeline that fires at it. What
> actually holds today is described honestly under
> [The protection posture](#the-protection-posture-what-is-actually-enforced) below.

---

## The branch model

| Branch | Role | Rules |
|---|---|---|
| **`vulnerable`** | The **golden reference**. Hand-curated, honestly-vulnerable code for every demoed candidate (DoS unbounded sink, SSRF fetch route, the SSH `CVE-2024-45337` hero) plus the canary / [`FIRING.md`](FIRING.md) contract. | **Never fired against. Never accepts a fix-merge.** Auto-prove-headed PRs into it are **auto-closed by CI** ([source guard](.github/workflows/source-guard.yml)) — reactively, **not** branch-protected: protection and rulesets both 403 on this plan (see the Operator handoff below). It should not self-patch, because the fire is *supposed* to target `main` — but nothing enforces that choice, so read [The protection posture](#the-protection-posture-what-is-actually-enforced) before relying on it. |
| **`main`** (default) | The **disposable demo target**. Reset from `vulnerable` before each demo, fired against, then patched by the fix-PR. | Reset (force-push) from `vulnerable` before every demo. Fire here. Patched here. Wiped on the next reset. |
| **`patched`** | The **pre-baked safe state** — all candidates closed. | For the "here's a clean system" shortcut when there's no time for the ~10-min live pipeline. Presented as the *end-state*, not a live run. |
| **`*-autoprove-fix-*`** | **Transient pipeline output** — one branch per proven fire, produced by the auto-prove arc. | Never merged to `vulnerable`. GC periodically (see below). |

**The load-bearing rule: fire against a freshly-reset `main`, never against `vulnerable`.** Then
the fix-branch bases on `main`, the fix-PR targets `main`, and `vulnerable` is never fired
against and never receives a fix-branch.

That rule is the **intended** deepest protection — but it is a rule the pipeline is *asked* to
follow, not one it is *made* to follow. See
[The protection posture](#the-protection-posture-what-is-actually-enforced).

---

## The repeatable cycle

### 0. (Once, Operator) branch setup — see the handoff at the bottom of this file.

### 1. Reset `main` to the golden baseline

```bash
.demo/prep-demo.sh            # DRY-RUN — shows exactly what a reset would do, changes nothing
.demo/prep-demo.sh --execute  # LIVE — reset + force-push main to vulnerable's exact tree
```

`prep-demo.sh` points `main` at `vulnerable`'s exact commit, so `main`'s tree is byte-identical
to the golden baseline **every time** — deterministic and idempotent (running it twice yields an
identical vulnerable `main`; a second run is a clean no-op). It is dry-run by default and asks
you to type the branch name before it force-pushes. It uses a force-push, **not a merge**: a
merge accumulates history and cannot cleanly re-introduce the vuln over a previously-patched
`main`.

### 2. Fire against `main`

Run the Tegron auto-prove pipeline with `main` as the target ref (scan → PoE → patch synthesis →
PoNE → auto-prove fix-branch → fix-PR). The DoS candidate reaches a proven apex; the fix-PR
(`abp-*-autoprove-fix-*`) is opened **against `main`**.

> Fire references and expected honest outcomes for each candidate (DoS, SSRF, the SSH hero) are
> in [`FIRING.md`](FIRING.md).

### 3. Show the fix land on `main`

Merge the auto-prove fix-PR into `main`. Now `main` is patched — *"look, main is safe now"* — the
same code, minus the vulnerability. This is the payoff of the live run.

### 4. Reset for next time

Back to step 1: `.demo/prep-demo.sh --execute` wipes the merged fix off `main` and restores the
golden baseline. The demo is repeatable indefinitely.

---

## The `patched` shortcut (no time for a live run)

When there isn't ~10 minutes for the live pipeline, skip straight to the end-state: point the
audience at the **`patched`** branch, which has every candidate already closed (dependency bump +
correct callback usage for the SSH hero; the SSRF and `/expand` routes unregistered for the
SSRF/DoS canaries). Present it as *the end-state a fix-PR produces*, not as a live run — it is a
pre-baked safe system, not a fresh proof.

---

## Garbage-collecting the auto-prove fix-branches

Each proven fire leaves a transient `abp-*-autoprove-fix-*` branch on the remote. They are
disposable pipeline output — never merged to `vulnerable` — so GC them periodically:

```bash
# List them
git ls-remote --heads origin '*autoprove-fix*'

# Delete them all on the remote (they are regenerated by the next fire)
git ls-remote --heads origin '*autoprove-fix*' \
  | awk '{print $2}' | sed 's#refs/heads/##' \
  | while read -r b; do echo "deleting origin/$b"; git push origin --delete "$b"; done
```

---

## The honesty contract (CI)

`.github/workflows/honesty-contract.yml` runs `.demo/honesty-check.sh` on every push to
`vulnerable` and every PR **targeting** `vulnerable`. The check builds and runs the real service
and asserts, black-box, that the vulnerable sinks are still reachable and unguarded:

- **DoS** — `/expand?count=<MaxInt64>` must return **500** (the unbounded `make([]byte, n)` sink
  faulted). If it returns **400**, `/expand` has grown a bound — the drift PR #9 introduced — and
  the check fails loudly.
- **SSRF** — `/fetch?target=<arbitrary>` must return **502** (the unguarded outbound fetch was
  actually made). If it returns **400**, an allowlist was added and the check fails.

It is scoped to `vulnerable` only — it never runs on `main` (which is *supposed* to be patched).
So an accidental fix landing on the golden branch (a repeat of PR #9) fails at push/PR time, not
mid-demo. The check lives under `.demo/` (a dot-directory Go tooling and the scanner both skip),
so it never pollutes the scanned app surface.

---

## The source guard (CI)

`.github/workflows/source-guard.yml` is the **name-based** half of the drift protection (the
honesty contract above is the behavioural half). On a pull request into `vulnerable` whose head
branch name contains `autoprove`, it **closes the pull request** with a comment explaining why
and pointing the fix at `main`, then fails the job so the red X is on the record too.

It **closes** rather than merely failing because native branch protection is unavailable on this
repository — a private repo on the free plan, where the branch-protection API returns **403**. A
red check would be advisory only; a closed PR cannot be merged.

**Why it lives on `vulnerable`.** For a `pull_request` event GitHub matches the `on:` branch
filter against the **base** branch and runs the workflow as it exists in the PR's **merge
commit** (base ∪ head). Putting the file on the base therefore guarantees it is present for
*every* PR into `vulnerable`, whatever the head branch happens to contain. On `main` it would
not be.

**What it does not do — read this before relying on it.** It is **reactive, not a hard gate**:
there is a window between the PR opening and the job closing it, and a maintainer can simply
reopen. It does **not** cover direct pushes to `vulnerable` (that is the honesty contract's
job), and being name-based it does not cover a hand-made branch carrying the same patch, or a
future pipeline rename. It is **defence in depth**, not the foundation — and the structural rule
at the top of this file (**fire against a freshly-reset `main`, never against `vulnerable`**),
which earlier revisions of this runbook called the deepest guard, turns out not to be enforced
anywhere either. What is actually load-bearing today is set out immediately below; the recorded
decisions are in [`docs/DECISIONS.md`](docs/DECISIONS.md) § A1 and § A4.

---

## The protection posture — what is actually enforced

Earlier revisions of this runbook, and of the source guard's own header, described the
structural rule — *fire against a freshly-reset `main`, never against `vulnerable`* — as the
**deepest** guard, the one that made contamination impossible by construction. **That was not
true, and the correction is worth keeping visible rather than quietly editing away.** The rule
was written down and followed in practice, but nothing in this repository, and nothing in the
pipeline that fires at it, ever *checked* it: the fix-PR base is taken from whatever GitHub
reports as this repo's default branch, with no validation that it is not the golden branch, and
the unattended path fires at whatever ref a recorded scan run names.

So, honestly, what keeps `vulnerable` safe today is:

| # | What holds | How strong it is |
|---|---|---|
| 1 | **The repo's `default_branch` is `main`.** The fix-PR base is read from it, and the scan's run-recording steps only fire when the branch being scanned *is* the default branch. | **External, mutable GitHub configuration** — not code, not in this repo, and changeable in the settings UI without any review. This is the single load-bearing item. |
| 2 | **The scan no longer runs on a push to `vulnerable`.** [`ferralon-assay.yml`](.github/workflows/ferralon-assay.yml)'s push filter names `main`, so pushing the golden branch produces no scan run at all — nothing that could later be picked up as a fire target. | Real and in-repo, but scoped to the **push** path. The daily schedule always runs against whatever branch is currently the default, so item 1 still backstops it. |
| 3 | **The source guard** closes an auto-prove-headed PR into `vulnerable`. | Reactive, name-based, not a required check — limits above. |
| 4 | **The honesty contract** fails if the golden sinks stop being vulnerable. | A **detector, not a blocker** — it goes red after the fact. |

Layers 3 and 4 are genuine defence in depth and should stay. But note what the table says: the
deepest thing protecting the golden branch is a **GitHub repository setting**, and the durable
fix — making the pipeline refuse to target a golden ref rather than trusting it not to — is
tracked in the backend, not here.

### Verifying the close path (run once, after the guard is on `vulnerable`)

The PR that *introduces* the guard does **not** test it: that head is not an auto-prove branch,
so only the pass path runs. To verify the close path for real, from a checkout with `vulnerable`
up to date:

```bash
# 1. A throwaway head whose NAME triggers the guard; the content is irrelevant.
git checkout -b test-autoprove-guard origin/vulnerable
git commit --allow-empty -m "test: source guard close path (no content change)"
git push -u origin test-autoprove-guard

# 2. Open it against the golden branch — this is the thing the guard exists to stop.
gh pr create --base vulnerable --head test-autoprove-guard \
  --title "TEST: source guard close path" --body "Throwaway. Expect: auto-closed by the source guard."

# 3. Within ~a minute, expect the PR to be CLOSED with the guard's comment, and the
#    "no auto-prove fix into the golden branch" check to be red.
gh pr view test-autoprove-guard --json state,comments --jq '{state, comments: [.comments[].body][0][0:120]}'

# 4. Clean up.
git push origin --delete test-autoprove-guard
```

A **control** run is worth doing alongside it: any PR into `vulnerable` from a normally-named
branch should show the same check **green** and be left untouched.

---

## Operator handoff — GitHub settings (not a Builder action)

These are repo-settings changes only the Operator can make. They are load-bearing — item 1 in
particular is the single strongest thing protecting the golden branch today (see
[The protection posture](#the-protection-posture-what-is-actually-enforced)):

1. ~~**Make `main` the default branch.**~~ **DONE** — `main` exists and is the default branch.
   **Do not change it back.** The fix-PR base is read from this setting, and the scan's
   run-recording steps fire only on the default branch, so pointing it at `vulnerable` would
   re-open both paths at once.
   [`.github/workflows/ferralon-assay.yml`](.github/workflows/ferralon-assay.yml) now scans
   `push: branches: [main]`, matching that default: the scan measures the **disposable** target,
   and a push to the golden branch produces no scan run at all. The branch name is hardcoded
   (a `branches:` filter cannot read `default_branch`), so if the default ever moves again,
   update that filter in lockstep on **both** `vulnerable` and `main` — GitHub matches a push
   filter against the workflow file on the *pushed* branch.
2. ~~**Branch-protect `vulnerable`.**~~ **NOT POSSIBLE ON THIS PLAN — do not wait for it.**
   Verified 2026-07-21: both `repos/.../branches/vulnerable/protection` and `repos/.../rulesets`
   return **403 — "Upgrade to GitHub Pro or make this repository public to enable this
   feature."** So neither classic branch protection nor rulesets is available while this repo is
   private on the free plan. The reactive
   [source guard](.github/workflows/source-guard.yml) is what stands in for it, and it is
   **weaker** than a protected branch would be — see [`docs/DECISIONS.md`](docs/DECISIONS.md)
   § A1 for the honest posture. If the repo goes public or the org upgrades, add the real
   protected-branch rule with the source guard as a **required** check and supersede A1.

## Related follow-ups (tracked separately — not part of this runbook)

- **ABP / backend:** change the auto-prove default `base_ref` from `vulnerable` → `main`, so a
  fire always targets the reset disposable branch. Sequence it so `main` is always reset before a
  fire.
- **CON / ABP:** console tenant-state reset (assessments / `proof_verdicts` accumulate across
  runs) for a *truly* clean repeatable demo — or accept the pile-up.
