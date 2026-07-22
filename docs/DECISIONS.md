# Decisions index — demo-go-svc

This is the **single greppable index** of standing dispositions on this repository. It exists
so a decision is **durable and challengeable** — decided once, recorded, and never a silent
"ignore-forever" wall.

**How this index is meant to be used (the design):**

- **The decision record lives in the repo** — an inline decision-comment at the file it
  governs for the local set. This file is the *index* over those records, not a second copy.
- **The review-suppression signal lives in the review *invocation*, not in the `/review`
  skill.** A review run that should not re-raise these points its prompt at this file; a pass
  run **without** referencing this index deliberately re-pressure-tests every disposition.
- **Every Accepted/deferred disposition carries a revisit-trigger** (`Revisit:`), so it
  retires by **visible supersession** (flip `Status:`), not by silent calcification.

Status legend: **Accepted** (a standing decision with a live revisit-trigger) ·
**Non-issue** (a reviewed concern verified to be a non-issue) · **Fixed** (a bug a review
corrected; recorded for traceability, no revisit) · **Superseded** (a retired decision,
after its trigger fired).

---

## A. Accepted / deferred decisions (each carries a revisit-trigger)

### A1 — Drift protection for the golden `vulnerable` branch is REACTIVE CI, not a hard gate

- **Date:** 2026-07-21
- **Decision:** `vulnerable` is protected by two CI jobs plus one structural rule, and by
  **nothing else**. There is **no** native branch protection and **no** required-status gate
  on this repository.
- **Rationale:** Native branch protection is unavailable here — this is a **private repository
  on the free plan**, where the branch-protection API returns **403**. A failing status check
  would therefore be **advisory only**: nothing stops a maintainer merging past a red X. So the
  name-based guard was built to enforce by **reaction** — it *closes* the offending pull
  request (a closed PR cannot be merged) and then fails the job so the red X is on the record
  too. That genuinely prevents the 2026-07-13 drift mechanism on a free private repo, which a
  red X alone would not.
- **The honest posture — what is and is not enforced:**

  | Layer | What it is | What it covers | What it does NOT cover |
  |---|---|---|---|
  | **Structural** — fire against a freshly-reset `main`, never `vulnerable` | The **deepest** guard. No fix-branch is ever produced against the golden branch in the first place. | Every auto-prove arc run per `DEMO.md`. | An arc misconfigured to target `vulnerable` (the ABP-side `base_ref` default is the real lever). |
  | **Name-based** — `.github/workflows/source-guard.yml` | Reactive close of a PR into `vulnerable` whose head contains `autoprove`. | The exact PR #9 mechanism, both auto-prove branch-name generations. | Direct pushes; a hand-made branch carrying the same patch; a future pipeline rename. Reactive — a maintainer can reopen and merge; there is a window between "opened" and "closed". |
  | **Behavioural** — `.github/workflows/honesty-contract.yml` | Black-box assertion that the sinks are still reachable and unguarded, on push to `vulnerable` **and** PRs into it. | Drift by any route, **including direct push**, regardless of branch name. | It is a **detector, not a blocker** — it goes red, it does not stop the merge. |

  Nothing in this stack is cryptographic and nothing is a required-status gate. **State it
  this way; do not describe `vulnerable` as "protected" without qualification.**
- **Revisit:** when this repository moves to a plan where branch protection / rulesets are
  available (or is made public) — at which point `vulnerable` should get a real protected-branch
  rule with the source guard as a **required** check, and this entry flips to `Superseded`.
- **Status:** Accepted
- **Pointer:** [`.github/workflows/source-guard.yml`](../.github/workflows/source-guard.yml)
  (header) · [`.github/workflows/honesty-contract.yml`](../.github/workflows/honesty-contract.yml)
  · [`DEMO.md`](../DEMO.md) § The source guard (CI)

### A2 — The source guard matches `autoprove`, not the literal `autoprove-fix`

- **Date:** 2026-07-21
- **Decision:** the guard's condition is `contains(github.head_ref, 'autoprove')` — a strict
  **superset** of the originally-specified `autoprove-fix`.
- **Rationale:** the auto-prove pipeline has used **two** fix-branch naming conventions, both
  visible in this repository's own PR history: the PR #9 / PR #13 generation
  (`abp-129-dos-autoprove-fix-2d1301c571f2`) and the **current** generation
  (`ferralon/autoprove/ferralon-app-dos-0001`, PR #15). The current name contains `autoprove`
  but **not** `autoprove-fix` — so a guard keyed on the narrower literal would have missed
  exactly the branches the pipeline produces today, i.e. it would have shipped already-stale.
  Checked for false positives against every PR head ever opened on this repo (`teg-*`, `aga-*`,
  `abp-*`, `ferralon-assay-autobump-*`, `ferralon-canary-optin`): none contain `autoprove`.
- **Revisit:** when the auto-prove pipeline changes its fix-branch naming again — a name-based
  guard is only as current as the name it knows. A rename that drops the `autoprove` token
  silently disarms this layer, leaving only the behavioural contract.
- **Status:** Accepted
- **Pointer:** [`.github/workflows/source-guard.yml`](../.github/workflows/source-guard.yml)
  § THE CONDITION

### A3 — Prior §B posture record ("one enforceable guard + three advisory asks") was false — corrected

- **Date:** 2026-07-21
- **Decision:** the §B demo-repeatability posture is restated as: **before 2026-07-21 there
  were ZERO enforceable name-based guards on `vulnerable`** — the source guard described in the
  §B record had never been committed to any branch. As of this entry there is **exactly one**,
  with the reactive limits recorded in **A1**.
- **Rationale:** a reconcile pass (2026-07-21) read all three candidate branches first-hand and
  found no workflow anywhere keying on `github.head_ref` or `autoprove-fix`; the branch that
  was supposed to carry the guard was a pointer to `main`, not a distinct guard commit. The
  posture record was **aspirational, recorded as realised** — the most expensive kind of wrong,
  because it suppresses the very work that would fix it.
- **Revisit:** whenever a guard is claimed to exist, re-verify it **on the branch it must fire
  from** before recording the claim. Flip to `Superseded` if the enforcement stack changes shape
  (see A1's revisit-trigger).
- **Status:** Accepted
- **Pointer:** [`DEMO.md`](../DEMO.md) § The source guard (CI) · this file, A1

---

## B. Verified non-issues — recorded so reviews don't cold-raise them

### B1 — The source guard does not run on the pull request that introduces it (and that is fine)

- **Date:** 2026-07-21
- **Why it's a non-issue:** for a `pull_request` event GitHub evaluates the `on:` branch filter
  against the **base** branch and runs the workflow as it exists in the PR's **merge commit**
  (base ∪ head), so the introducing PR is *expected* to run it — but even if it does, the
  introducing head (`teg-054-source-guard-on-vulnerable`) does not contain `autoprove`, so only
  the **pass** branch is exercised. The introducing PR is therefore **not** evidence that the
  close path works, and is not claimed to be. The close path is verified separately by a
  deliberate post-merge test PR — the procedure is written down in
  [`DEMO.md`](../DEMO.md) § The source guard (CI).
- **Revisit:** if the guard is ever moved off `vulnerable` (e.g. onto `main`), base-branch
  resolution no longer guarantees it is present for PRs into `vulnerable` — re-derive.
- **Status:** Non-issue
- **Pointer:** [`.github/workflows/source-guard.yml`](../.github/workflows/source-guard.yml)
  § ACTIVATION SEMANTICS

### B2 — The `honesty-contract.yml` "placement gap" was a stale-read artefact, not a real gap

- **Date:** 2026-07-21
- **Why it's a non-issue:** a reconcile pass flagged that `honesty-contract.yml` sat on `main`
  but not on `vulnerable`, so it might never fire on the branch it guards. Re-read against the
  **remote** refs: `origin/vulnerable` (`54c2e69`) **does** carry
  `.github/workflows/honesty-contract.yml` — it landed via PR #10 and has been there since. The
  earlier finding read a **stale local `vulnerable` ref** (`410f697`, six commits behind). The
  workflow travels onto `main` only as a side effect of `prep-demo.sh` resetting `main` *from*
  `vulnerable`; `vulnerable` is the source, not the beneficiary, and its own branch filters
  (`push`/`pull_request` → `[vulnerable]`) keep it inert on `main`.
- **Revisit:** if the demo choreography ever stops treating `vulnerable` as the source of truth
  for `.demo/` and `.github/` tooling.
- **Status:** Non-issue
- **Pointer:** [`.github/workflows/honesty-contract.yml`](../.github/workflows/honesty-contract.yml)
  · [`.demo/prep-demo.sh`](../.demo/prep-demo.sh)

---

## C. Fixed (code change; no revisit)

| # | Fix | Site |
|---|-----|------|
| C1 | The honesty contract drove the **retired** `/preview` route. TEG-039 renamed the SSRF route to `/fetch` (PR #14) without updating the check, which `mux.HandleFunc("/", indexHandler)` then swallowed as a **200** — so the contract had been failing on every push/PR into `vulnerable` since PR #14, for a reason unrelated to drift (the sink was unguarded the whole time). A permanently-red contract cannot distinguish real drift from its own staleness. Route corrected; both assertions now pass. | [`.demo/honesty-check.sh`](../.demo/honesty-check.sh) |
