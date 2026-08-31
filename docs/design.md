# Design notes — dsh-plugin-eval

This document records the design decisions behind the plugin so a maintainer can
extend or critique it without reading the whole engine.

## Goal

Before installing a DSH plugin, answer: *is this plugin trustworthy?* We borrow
two well-known mental models:

- **npm audit** — a verdict that is dominated by security findings and can
  *block* an install.
- **Lighthouse** — a weighted composite of category scores (0–100), a letter
  grade, and graceful handling of categories that produced no data.

## Non-goals (explicit)

- **Never execute the target plugin.** Timing a plugin by importing/running it
  would hand unknown code a chance to act — the exact supply-chain risk we are
  trying to reduce. "Performance" is therefore a *footprint* proxy, not a
  runtime benchmark. If a real runtime benchmark is ever wanted, it belongs in a
  separate, opt-in, sandboxed harness — out of scope here.
- Not a malware sandbox. Static regex scans flag *patterns*; they are heuristics
  with a documented false-positive rate, not proof of malice.

## Scoring model

`lib/engine/score.js` defines five weighted categories:

| key | weight | source |
| --- | --- | --- |
| security | 0.40 | security scan + manifest audit |
| compatibility | 0.25 | compatibility check |
| performance | 0.15 | footprint benchmark |
| community | 0.10 | optional GitHub/npm aggregation |
| documentation | 0.10 | docs/quality signals |

`computeComposite` renormalizes over the categories that actually produced a
finite score, so `community: null` offline doesn't skew the total. Grades:
A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below. Verdict:

- `blocked` — security < 40 (or composite < 40)
- `caution` — security < 60, or composite in [40, 60)
- `acceptable` — composite in [60, 75)
- `recommended` — composite ≥ 75

Security is checked twice (once alone, once in the composite) because a green
footprint must not rescue a plugin leaking credentials.

## Static analysis boundaries

- `collectLocalSource` walks with depth ≤ 8, ≤ 2000 files, ≤ 64 MiB total,
  reads text only for candidate extensions ≤ 256 KiB.
- Secret rules cover: private keys, AWS `AKIA/ASIA`, GitHub `ghp_`/`gho_`…,
  npm `_authToken`, Slack `xox*`, Google `AIza`, Stripe `sk_live_`, JWTs, and a
  generic hardcoded-credential assignment.
- Risk rules cover `eval`/`Function`, `child_process`, `vm.runIn*`, dynamic
  require/import, plain-HTTP endpoints (https is not flagged), env mutation,
  `Math.random` in a security context, and base64-decoded execution.
- Manifest audit flags floating/unpinned specs, lifecycle scripts
  (`postinstall` = high; `prepare` = low because it is the normal git-install
  build hook), and missing repository/license/description.

## Compatibility

- `engines.node` is checked with a minimal semver-range matcher (`^`, `~`,
  `>=`, `<=`, `<`, `>`, exact, `x`/`*` wildcards, `||` groups, `&&`/`,` ANDs).
  Unparseable ranges return `unknown` rather than guessing.
- DSH peerDependencies (`@deepseek-ai/*`) are compared against the runtime's
  DSH version when known.
- Dependency pin ratio: < 50% pinned exact → medium finding.

## Community dimension

Uses the optional `web` service (never `fetch` globals). Endpoints:
`api.github.com/repos/{repo}`, `/releases`, `registry.npmjs.org/{name}`,
`api.npmjs.org/downloads/point/last-month/{name}`. Every call is time-bounded
(8 s default) and aborts on the tool's signal. No credentials are sent.

## Known-vulnerability lookup (OSV) — the "npm audit" half

`lib/engine/vulns.js` queries `api.osv.dev/v1/query` for every *pinned*
`name@version` gathered from the manifest (exact-version runtime/optional/peer
deps) plus every resolution recorded in lockfiles. Because the DSH `web`
service is read-only GET, the query uses OSV's GET form with bracket-encoded
params:

```
GET https://api.osv.dev/v1/query?package[name]=<name>&package[ecosystem]=npm&version=<ver>
→ { "vulns": [ { "id", "summary", "aliases", "affected", "modified", "published" } ] }
```

Each found advisory becomes a `high` finding, is shown in the report, and
caps the security score (`security = min(heuristic, osv)`). The lookup is
bounded (≤ 24 queries, ≤ 6 s each), abortable, and any individual failure is
ignored — the dimension degrades to `available:false` rather than failing the
evaluation.

## Lockfile audit

`lib/engine/lockfile.js` parses `package-lock.json` / `npm-shrinkwrap.json`
(JSON), `pnpm-lock.yaml` and `yarn.lock` (line-based heuristics — no YAML
dependency). It reports presence, pinned resolution count, and integrity
records; a missing lockfile is a `medium` finding ("installs not
reproducible"). The pinned set also feeds the OSV lookup, since the lockfile
records what actually installs rather than the loose ranges in package.json.

## Remote deep scan

`lib/engine/remote.js` lets `owner/repo` targets be scanned without cloning:
repo metadata → default branch → recursive git tree → raw text for small text
blobs (`raw.githubusercontent.com`), all through the read-only `web` service.
Bounded (800 files / 16 MiB / depth 6 / per-call 8 s), skips `node_modules`
and binary names, and degrades to metadata-only on any failure. This makes
`plugin_eval(target: "owner/repo")` a real pre-install scan, not just stars.

## DSH version detection

`lib/engine/runtime.js` resolves the running DSH version with
`createRequire` on `@deepseek-ai/dsh/package.json` (the package ships no
`exports` map, so the subpath resolves when the package is reachable), and
falls back to `undefined` (reported as a low finding) or an explicit
`dsh_version` tool argument. The compatibility dimension uses this to verify
`@deepseek-ai/*` peerDependencies against the actual runtime instead of
always reporting "unknown".

## Integration

`lib/index.js` is the Cordis entry: `name`, `inject: ['tools']`, `apply(ctx)`
registers one `defineTool` from `@deepseek-ai/dsh-tools`. `execute` reads
optional `fs`/`web` via `ctx.get`, runs `evaluatePlugin`, and returns a small
JSON `{ target, composite, report }` so the model gets the readable report and
the composite without the whole payload. `cordis.patch.yml` mounts the package
as one row; `dsh.bundle.patch` points at it for git/npm installs.

## Test strategy

`test/` has three node:test files and two fixture plugins:

- `good-plugin` — pinned deps, engines, license, README, no risky patterns.
- `risky-plugin` — real secrets, `eval`, `child_process`, `postinstall`,
  floating/file: deps.

An in-memory `fs` shim (`test/helpers/fs-shim.mjs`) matches the DSH `fs` entry
shape (`{ name, type, target, size }`) so engine tests never touch disk/real
services. A mock `web` shim returns canned GitHub/npm JSON for the community
tests. `node --test` spawns per-file processes; run files directly if your
sandbox blocks that (as the DSH sandbox does).
