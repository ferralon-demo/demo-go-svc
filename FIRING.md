# Firing demo-go-svc as a Tegron PoE fixture

`demo-go-svc@vulnerable` is authored as a **fireable** fixture: a live `tegrond` fire crosses
stage 8/10 `sandbox_observability` and emits a real proven apex, produced by execution.

## Recommended fire — TEGRON-SSRF-0001 (cleanest)

| Field (tegron-tui)        | Value                                          |
|---------------------------|------------------------------------------------|
| Vulnerability ID          | `TEGRON-SSRF-0001`                             |
| Source (osv\|nvd\|ghsa)   | the source the free scan keys it under (the TEGRON-* advisory feed) |
| Repo URL                  | `git@github.com:ferralon-demo/demo-go-svc.git`|
| Ref                       | `vulnerable`                                    |
| Execution                 | `image`                                         |
| Ownership token           | any non-empty value (e.g. `owner-token`) — `api.go` only requires non-empty |

**Expected honest outcome:** `Outcome == signal_fired`, `Attribution == intrinsic_canary`,
`Replication.Fired >= 1` (of 3 trials). The proof is the SSRF sink's own outbound request
carrying the planted seed to the OOB endpoint.

> ExecKind note: the pipeline builds the repo-root `Dockerfile` whenever one is present;
> `image` is the implemented semantic. `compose` (the tui default) currently behaves
> identically because the build keys on Dockerfile presence, not on `Kind`.

## How it fires (the canary contract)

1. The sandbox builds the repo-root `Dockerfile` → workload image (the hypothesis `image` input).
2. It plants a per-assessment secret at `/tmp/tegron_canary` and injects `TEGRON_OOB_URL`
   (its callback listener) into the container.
3. A model-generated trigger drives the ingress — e.g.
   `sh -c "/server & sleep 1; wget -qO- 'http://127.0.0.1:8080/preview?target=internal'"`.
   The trigger never references the seed path or `TEGRON_OOB_URL` (fail-closed guard).
4. `fetchHandler` → `resolveTarget("internal")` reads the seed and the **server's own
   `http.Get`** (the SSRF sink, CWE-918) beacons it to `$TEGRON_OOB_URL?kind=canary&data=<seed>`.
   The seed surfacing at the OOB listener is the intrinsic, attributable signal.

## PoNE second trace (proves the fix is not exploitable)

- **Ref:** `patched` — fix **mode 2 (code-fix patched ref)**: the `/preview` (SSRF) and
  `/expand` (DoS) endpoints are removed, so the same trigger 404s and nothing is beaconed →
  `not_exploitable`. The `patched` ref carries the same `Dockerfile` so it builds and runs.
- For the dependency-advisory vuln **GO-2021-0113** the fix would instead be **mode 1 (go.mod
  version bump** `golang.org/x/text v0.3.6 → v0.3.7`); it is not the recommended fire because
  its path is reachable-but-untainted (constant input), not attacker-tainted.

## Alternative fire — TEGRON-DOS-0001 (also fires)

Same form, `Vulnerability ID = TEGRON-DOS-0001`. Trigger drives `/expand?count=9223372036854775807`
(at MaxInt64 to trip the **recoverable** `makeslice` panic — a smaller count would OOM-kill the
process before recover runs). The deferred recover path beacons `kind=fault&data=<seed>`. SSRF
is recommended over DoS because it needs no panic-vs-OOM boundary to land deterministically.

## Local verification performed

The engine's canary protocol was reproduced directly against the built images
(plant seed → inject `TEGRON_OOB_URL` → run the trigger inside the container):

- `vulnerable` + `/preview?target=internal` → OOB received `/cb?kind=canary&data=<seed>` — **FIRED**.
- `vulnerable` + `/expand?count=MaxInt64`   → OOB received `/cb?kind=fault&data=<seed>`  — **FIRED**.
- `patched`    + same SSRF trigger          → 404, no beacon — **DARK** (negative control holds).
