#!/usr/bin/env python3
"""Project a tegron.report.v1 report.json into the Ferralon ingest-payload.v0 thin
allowlist body the scan workflow POSTs to the Ferralon Assessment backend's OIDC
ingest endpoint.

This is the data-plane minimizer. It carries ONLY what the documented v0 contract
allows (`ingest-payload.v0.schema.json`, additionalProperties:false at every level):

  - subject {owner_id, repo_id, run_id}  — declared-intent run identity, taken from
    the standard GitHub Actions env vars. The backend cross-checks every field against
    the *verified* OIDC token claims (repository_owner_id / repository_id / run_id) and
    rejects on mismatch — the token, not this block, is authoritative.
  - components []{ref, purl, version}    — the resolved dependency set (the SBOM).
  - advisories []{id, aliases}           — the GHSA/CVE advisories that matched a
    component, referenced by findings.
  - findings []{component_ref, advisory_id, provenance{feed, asserted_at}}
                                          — component <-> advisory matches + which feed
                                            asserted them.

It deliberately omits, by construction:
  - source code, file contents, developer identity / PII (never read);
  - reachability verdicts, call paths, entry points, EPSS/KEV (stays in report.json on
    refs/tegron/state — NOT exfiltrated to the hot ingest path);
  - any advisory whose only identifier is a non-GHSA/CVE id. The free-scan engine seeds
    two SYNTHETIC demo advisories (the SSRF + DoS exploitability candidates the paid
    Prove tier later detonates) whose ids are not GHSA/CVE and which carry no resolved
    package. The v0 `advisory_id` pattern (`^(GHSA-...|CVE-...)$`) rejects them, so they
    are filtered here. This is the honest mapping, NOT a fabricated one: a thin
    dependency-graph allowlist correctly omits a non-package, non-GHSA/CVE synthetic
    entry. (See AGA-003 report, STOP fence 2 — advisory->ingest coherence.)

Usage:  build_ingest_payload.py <report.json>  > payload.json
Env:    GITHUB_REPOSITORY_OWNER_ID, GITHUB_REPOSITORY_ID, GITHUB_RUN_ID
"""

import json
import os
import re
import sys

GHSA = re.compile(r"^GHSA-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")

# tegron.report.v1 advisory.source -> the v0 provenance.feed identifier.
FEED = {
    "osv": "osv.dev",
    "ghsa": "github-advisory-database",
}


def pick_advisory_id(advisory):
    """Return (id, aliases) for the v0 payload, preferring a GHSA id, else a CVE id.
    Returns (None, []) when the advisory carries no GHSA/CVE identifier at all
    (e.g. a synthetic demo advisory) — the caller filters those out."""
    ids = [advisory.get("id", "")] + list(advisory.get("aliases", []))
    ghsa = [x for x in ids if GHSA.match(x)]
    cve = [x for x in ids if CVE.match(x)]
    chosen = ghsa[0] if ghsa else (cve[0] if cve else None)
    if chosen is None:
        return None, []
    aliases = [x for x in ids if x and x != chosen and (GHSA.match(x) or CVE.match(x))]
    return chosen, aliases


def require_env(name):
    v = os.environ.get(name, "")
    if not re.fullmatch(r"[0-9]{1,20}", v or ""):
        sys.exit(
            f"build_ingest_payload: env {name}={v!r} is not a digit string; "
            "this script runs inside GitHub Actions where it is set."
        )
    return v


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: build_ingest_payload.py <report.json>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)

    if report.get("schema_version") not in ("tegron.report.v1", "tegron.report.v2"):
        sys.exit(
            f"build_ingest_payload: unexpected schema_version "
            f"{report.get('schema_version')!r}; refuse to project."
        )

    # Components: one per resolved SBOM package, indexed by purl so findings can
    # reference them without repeating the purl.
    components = []
    ref_by_purl = {}
    for i, pkg in enumerate(report.get("sbom", {}).get("packages", []), start=1):
        purl = pkg.get("purl")
        if not purl:
            continue
        ref = f"c{i}"
        comp = {"ref": ref, "purl": purl}
        if pkg.get("version"):
            comp["version"] = pkg["version"]
        components.append(comp)
        ref_by_purl[purl] = ref

    # Advisories + findings: only for advisory findings that (a) resolve to a GHSA/CVE
    # id and (b) matched a package present in the SBOM (so a component_ref exists).
    advisories = {}
    findings = []
    for f in report.get("advisories", []):
        adv = f.get("advisory", {})
        adv_id, aliases = pick_advisory_id(adv)
        if adv_id is None:
            continue  # synthetic / non-GHSA-CVE advisory — not allowlisted
        pkg = f.get("package") or {}
        purl = pkg.get("purl")
        ref = ref_by_purl.get(purl)
        if ref is None:
            continue  # package-less or non-SBOM match — no component to reference
        if adv_id not in advisories:
            entry = {"id": adv_id}
            if aliases:
                entry["aliases"] = aliases
            advisories[adv_id] = entry
        prov = {"feed": FEED.get(adv.get("source"), adv.get("source") or "unknown")}
        # report provenance has a snapshot date; the contract wants asserted_at RFC3339.
        snap = report.get("provenance", {}).get("generated_at") or f.get("priority", {}).get("snapshot")
        if snap and re.search(r"T.*Z", str(snap)):
            prov["asserted_at"] = snap
        findings.append(
            {"component_ref": ref, "advisory_id": adv_id, "provenance": prov}
        )

    payload = {
        "schema_version": "v0",
        "subject": {
            "owner_id": require_env("GITHUB_REPOSITORY_OWNER_ID"),
            "repo_id": require_env("GITHUB_REPOSITORY_ID"),
            "run_id": require_env("GITHUB_RUN_ID"),
        },
        "components": components,
    }
    if advisories:
        payload["advisories"] = sorted(advisories.values(), key=lambda a: a["id"])
    if findings:
        payload["findings"] = findings

    json.dump(payload, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
