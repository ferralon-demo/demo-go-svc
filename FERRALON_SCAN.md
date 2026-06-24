# Ferralon Assessment

> **Name note.** "Ferralon Assessment" is a working placeholder. The final
> customer-facing scanner name is an open Operator decision (it will be
> Ferralon-branded — never an internal codename).

This repository runs a **free, deterministic dependency-advisory scan** in its own
GitHub Actions runner on every push and pull request
([`.github/workflows/ferralon-assessment.yml`](.github/workflows/ferralon-assessment.yml)).

## What it does — and what it does not

The scan reads this module's **dependency graph** and the **public advisory feeds**, and
reports, for each advisory it evaluates, one of three honest deterministic outcomes:

| Outcome | Meaning |
|---|---|
| **Reachable candidate** | A path to the vulnerable symbol was found. A **candidate** for review — *never* a claim that it is exploitable here. |
| **Not exploitable** | The advisory applies, but the vulnerable code is provably absent or unreachable in this codebase. |
| **Disqualified** | The advisory provably does not apply — the resolved version is outside the affected range. |

Reachability grade and EPSS/KEV are **evidence strength and in-the-wild context** — not
proofs of exploitability for this codebase. The free scan never emits an "exploitable"
verdict; that requires the consented, execution-backed **Prove** tier in the console.

**No source code leaves this repository.** The scan runs entirely in your runner. The
only thing sent off-repo is a **thin metadata allowlist** — the resolved package set
(purls), the GHSA/CVE advisories that matched, and which feed asserted them. Source
code, file contents, and developer identity are **never** transmitted (the request body
is closed to anything outside that allowlist by construction).

## Where the results go

- **`report.json`** — the full scan result, persisted to the `refs/tegron/state` git ref
  on push to `main`, and uploaded as the `ferralon-scan-report` build artifact.
- **The pivot Issue** — a pinned Issue summarizing the run and linking to the **Ferralon
  console**, where you can see the per-advisory reasoning, the call paths behind each
  reachable candidate, and (with consent) the paid **Prove** escalation.
- **The Ferralon console** — `https://console.ferralon.com/r/demo-go-svc`.
- **The Ferralon backend** — a thin metadata allowlist is POSTed to the backend's ingest
  endpoint, authenticated by a GitHub-signed Actions OIDC token bound to this
  repository's owner. (Activated once the endpoint variable is configured.)

## How the scanner is distributed (and the planned cleanup)

For this demo the scanner binaries are **vendored under [`bin/`](bin/)** and executed
directly — the simplest honest path to a working in-runner scan. This is a known
shortcut with two flagged follow-ons (tracked by the Operator, not solved here):

1. **Proper distribution** — fetch a pinned, checksummed release of the scanner at run
   time instead of committing ~23 MB of binary into the repository.
2. **Brand-hardened build** — the vendored build is not scrubbed of internal
   engine/import symbols at rest; a hardened (garble) or Ferralon-brand build should ship
   so the compiled artifact carries no internal codename either. (The *authored*
   surfaces — this workflow, the pivot Issue, this README — are already codename-clean,
   checked in CI by `.ferralon/check_branding.sh`.)
