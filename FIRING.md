# Firing demo-go-svc as a Tegron PoE fixture

`demo-go-svc@vulnerable` is authored as a **fireable** fixture: a live `tegrond` fire crosses
stage 8/10 `sandbox_observability` and emits a real proven apex, produced by execution.

## Pinned tags

This is a synthetic fixture (Ferralon-authored, no upstream code). Annotated git tags pin the
vulnerable and proven-fixed commits below so the PoE/PoNE narrative has stable references even as
branches move.

| Tag | Commit | Pins |
|---|---|---|
| [`poe`](https://github.com/ferralon-demo/demo-go-svc/tree/poe) | `8616dbab` | `vulnerable`-branch ancestor, still vulnerable-shaped (fireable, PoE for CVE-2024-45337) |
| [`pone-cve-2024-45337`](https://github.com/ferralon-demo/demo-go-svc/tree/pone-cve-2024-45337) | see `fix-cve-2024-45337` branch | the CORRECT CVE-2024-45337 fix: `x/crypto`→v0.31.0 + `handleSSHConn` reads `sconn.Permissions`, `ssh.go` kept intact (confirmed dark reproduction, PoNE) |

**`pone` (published, STALE for this CVE — do not fire CVE-2024-45337 against it):** `pone` /
`proven-pone` (`f2252151`) pins a fix for a *different, older* fixture (GO-2021-0113, the
`x/text` BCP-47 parser fault) that deletes `ssh.go`/`fetch.go`/`expand.go`/`auth.go` entirely.
Firing CVE-2024-45337 against it returns a **false PoNE** (`not_exploitable` because the code
was removed, not because the bypass was patched). This PR does not move or delete the
published `pone`/`proven-pone` tag/branch — re-pointing them for the prod fire lane to
`pone-cve-2024-45337`'s commit is a separate, flagged action (see PR description).

## Recommended fire — CVE-2024-45337 (the hero, x/crypto/ssh authorization bypass)

| Field (tegron-tui)        | Value                                          |
|---------------------------|------------------------------------------------|
| Vulnerability ID          | `CVE-2024-45337`                              |
| Source (osv\|nvd\|ghsa)   | the source the free scan keys it under (osv/ghsa) |
| Repo URL                  | `git@github.com:ferralon-demo/demo-go-svc.git`|
| Ref                       | `vulnerable`                                    |
| Execution                 | `image`                                         |
| Ownership token           | any non-empty value (e.g. `owner-token`)       |

**Expected honest outcome:** `Outcome == signal_fired`, `Attribution == intrinsic_canary`,
`Replication.Fired >= 1` (of 3 trials). The proof is an SSH session that was authorized as
**admin** despite authenticating with only the low-privilege **user** key, then reading the
planted seed and beaconing it — a genuine authorization bypass reached through the vulnerable
`PublicKeyCallback`.

## The reachability condition this fixture embodies

CVE-2024-45337 is a *misuse* advisory: `golang.org/x/crypto/ssh` < v0.31.0 lets
`ServerConfig.PublicKeyCallback` be invoked for keys that are merely **offered** (query
phase, before any signature is verified), and the order of those callbacks does not identify
the key that ultimately authenticated. An application that records the key seen in the
callback and makes authorization decisions from it — instead of from the `*ssh.Permissions`
the library binds to the authenticated key — can be driven to authorize the wrong identity.

`ssh.go` embodies exactly that anti-pattern, reachable from a real listener:

1. **Vulnerable dependency** — `golang.org/x/crypto` pinned `v0.30.0` (< v0.31.0), see `go.mod`.
2. **The callback misuse** — `handleSSHConn`'s `PublicKeyCallback` writes the offered key's
   role into a per-connection `recordedRole` on **every** invocation (last-key-wins).
3. **The vulnerable authorization decision** — after `ssh.NewServerConn`, the session's
   privilege is taken from `recordedRole` (the last offered key) rather than from
   `sconn.Permissions.Extensions["role"]` (the key that actually authenticated).
4. **A privileged sink** — an admin session may run commands (`runExec` → `adminRunner`),
   including reading the planted seed; a user session may not.

Because both the `admin` and `user` public keys are in the embedded allowlist
(`demo_authorized_keys`) and public keys are not secrets, an attacker holding only the
**user** private key can offer the **admin** public key to drive `recordedRole` to `admin`,
authenticate with the user key, and land an admin session.

## How it fires (the canary contract)

1. The sandbox builds the repo-root `Dockerfile` → workload image (the hypothesis `image` input).
2. It plants a per-assessment secret at `/tmp/tegron_canary` and injects `TEGRON_OOB_URL`.
3. A model-generated trigger connects to `127.0.0.1:2022` with a **crafted SSH client** that
   offers the admin public key (query) and authenticates with the user private key
   (`.ferralon/demo-keys/user_ed25519`, committed as the low-privilege demo credential), then
   runs `read-seed` (or `cat /tmp/tegron_canary`) over the admin session. The trigger never
   references the seed path or `TEGRON_OOB_URL` directly (fail-closed guard).
4. `adminRunner` reads the seed and `beaconSSH` emits it to `$TEGRON_OOB_URL?kind=canary&data=<seed>`.
   Reaching that line proves the bypass conferred admin — the intrinsic, attributable signal.

> A stock `ssh` client cannot reproduce the bypass (it only signs with keys it holds); the
> fire uses a crafted client that offers a public key it cannot sign, exactly as the real
> advisory describes. A stock `ssh -i user_ed25519 … whoami` returns "permission denied"
> (user role), and `-i admin_ed25519 … whoami` returns "admin" — the legitimate baselines.

## PoNE second trace (proves the fix is not exploitable)

- **Ref:** `fix-cve-2024-45337` (tag `pone-cve-2024-45337`) — fix **mode 1 (dependency version
  bump) + correct callback usage**: `golang.org/x/crypto` → **v0.31.0** and `handleSSHConn`
  reads the role from `sconn.Permissions.Extensions["role"]` (bound to the authenticated key)
  instead of the `recordedRole` side effect written for merely-offered keys. The same crafted
  trigger now lands a **user** session (its real identity); `read-seed` is denied and nothing
  is beaconed → `not_exploitable`. `ssh.go`, the routes, and the `Dockerfile` are unchanged, so
  it builds and runs identically (clean two-trace: predecessor fires, fixed build dark).

  **Correction:** the `patched`/`proven-pone` refs previously cited here for this trace are a
  *different* fixture (GO-2021-0113, `x/text`) that deletes `ssh.go` outright — they do not
  exercise this bypass at all and must not be pinned for CVE-2024-45337 (see "Pinned tags"
  above).

## The other advisories (static verdicts — not fired)

- **CVE-2020-36569 (`github.com/nanobox-io/golang-nanoauth`) → `reachable_candidate`.**
  nanoauth at this version globally disables token validation when started with an empty
  token. The dependency and version match, and the vulnerable listener symbol is statically
  reachable from `main` (control-flow-only grade). `startAdminAuth` (see `auth.go`) does add a
  runtime guard — it refuses to start any nanoauth listener without a non-empty `ADMIN_TOKEN`,
  which mitigates the empty-token bypass at run time — but a static reachability scan does not
  credit that runtime value-check, so the free scan honestly reports a reachable_candidate (a
  candidate for review, never a claim of exploitability).
- **CVE-2026-39821 (`golang.org/x/net/idna`) → `reachable_candidate`.** `idna` is genuinely
  imported and reached from `/normalize` (attacker-tainted grade), and `golang.org/x/net` is
  pinned `v0.32.0` — INSIDE the advisory's affected range (`< v0.55.0`) — so it is a reachable
  candidate, not disqualified by version.

## Alternate fires — FERRALON-APP-SSRF-0001 / FERRALON-APP-DOS-0001 (also fire)

The HTTP service still exposes the code-level SSRF and DoS canary surfaces:

- **SSRF** — `GET /fetch?target=internal` drives `fetchHandler` → `resolveTarget` → the
  server's own `http.Get` (CWE-918), which beacons `kind=canary&data=<seed>`.
- **DoS** — `GET /expand?count=9223372036854775807` trips the recoverable `makeslice` panic;
  the deferred recover beacons `kind=fault&data=<seed>` (CWE-400).

Both sinks are removed on the `patched` ref (mode 2, code-fix): the `/fetch` and `/expand`
routes are unregistered, so those requests fall through to the catch-all index (`/`) and never
reach `http.Get` / `make([]byte, n)` — nothing is beaconed → `not_exploitable`.

## Local verification performed

`go build ./...` and `go vet ./...` pass; the binary serves HTTP on `:8080` and SSH on
`:2022`. Confirmed directly: `/healthz`→`ok`, `/normalize?host=münchen.de`→`xn--mnchen-3ya.de`,
`ssh -i user_ed25519 … whoami`→"permission denied" (user), `ssh -i admin_ed25519 … whoami`→
"admin". The crafted-client bypass fire and the OOB canary reproduction are the engine's step
(run by Tegron/Eric), as with the SSRF/DOS canaries.
