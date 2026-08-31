# dsh-plugin-eval

Comprehensive **pre-install evaluation** for DeepSeek Harness (DSH) plugins — a supply-chain gate in the spirit of `npm audit` + Lighthouse. It scores a plugin across security, compatibility, footprint/performance, community signal and documentation, and returns a **0–100 reliability score**, a letter grade, and an install verdict (recommended / acceptable / caution / blocked).

> **Static analysis only.** The engine never executes the target plugin's code — it reads files through the `fs` service and public GitHub/npm metadata through the optional `web` service. Evaluating a hostile plugin cannot run anything on your machine.

## What it does

Registers one model tool, `plugin_eval`, callable during a conversation:

```
plugin_eval(target: <local path | owner/repo | npm package>)
```

| Dimension | Weight | What it measures |
| --- | --- | --- |
| Security | 40% | secret material (private keys, AWS/GitHub/npm/Slack tokens, JWTs…), risky code patterns (`eval`, `child_process`, `vm`, dynamic require, plain-HTTP endpoints), **known vulnerabilities from the OSV database** (npm-audit style), dependency pinning, lifecycle scripts (`postinstall` etc.), manifest hygiene |
| Compatibility | 25% | `engines.node` vs runtime, **DSH `peerDependencies` vs the detected DSH version**, dependency pin ratio, manifest identity |
| Footprint / Performance | 15% | file count, effective source size, source/dependency ratio, tests/docs presence (Lighthouse-style static benchmark — we do not execute to time it) |
| Community | 10% | GitHub stars/forks/activity/archived, npm downloads/versions/last publish (optional network; skipped & renormalized offline) |
| Documentation & Quality | 10% | README, LICENSE, tests, examples, changelog, contributing |

Plus a **lockfile audit** (package-lock.json / pnpm-lock.yaml / yarn.lock): missing lockfile lowers reproducibility, and every pinned resolution recorded in a lockfile feeds the OSV lookup too.

Missing dimensions are **dropped and weights renormalized** (Lighthouse behaviour), so an offline run still yields a composite.

The verdict is security-dominant, like `npm audit`: a security score below 40 forces `blocked` even when everything else is green.

## Install

The package is a standard DSH plugin (entry `lib/index.js` is committed, no build step) and declares `dsh.bundle.patch` → `./cordis.patch.yml`, so it installs and mounts as a Cordis row from git or npm:

```bash
dsh plugin add <this-repo-or-package>
```

It depends only on the Host-provided `@deepseek-ai/dsh-tools` (peer) and uses `fs`/`web` services when present.

## Usage

From the model, point it at a **local checkout** for the deepest scan:

```
plugin_eval(target: "/path/to/plugin-checkout")
plugin_eval(target: "owner/repo")          # remote deep scan (git tree + raw text, no clone, no execution)
plugin_eval(target: "some-npm-package")    # manifest + community only
```

When a GitHub `owner/repo` is given and networking is enabled, the plugin
deep-scans the repository remotely (git tree + raw text via the `web` service)
instead of stopping at metadata. Optional `dsh_version` overrides the
auto-detected DSH version used for `peerDependencies` checks.

Example output shape:

```jsonc
{
  "target": "/path/to/plugin",
  "composite": { "score": 90.1, "grade": "A", "verdict": "recommended" },
  "report": "# Plugin Reliability Report — …\n## Composite: **90.1/100 (A)** …"
}
```

## Development

```bash
node test/util.test.mjs       # semver + pinning helpers
node test/engine.test.mjs     # full pipeline over fixtures (offline)
node test/community.test.mjs  # community aggregation with a mocked web service
node test/advanced.test.mjs   # OSV lookup, lockfile audit, remote deep scan, DSH version detection
```

(`node --test` spawns per-file processes; run files directly if your sandbox blocks that.)

## Project layout

```
lib/
  index.js          Cordis plugin entry (registers plugin_eval)
  engine/
    index.js        evaluatePlugin() orchestrator + report renderer
    util.js         semver / pinning / local source collection
    security.js     secret + risky-pattern scan, manifest audit
    performance.js  footprint benchmark
    community.js    GitHub/npm aggregation (optional web)
    compatibility.js version compatibility check
    score.js        composite scoring, grade, verdict
    vulns.js        OSV known-vulnerability lookup (npm-audit style)
    lockfile.js     package-lock / pnpm / yarn lockfile audit
    remote.js       remote GitHub deep scan (tree + raw text, no clone)
    runtime.js      DSH version detection for peer checks
test/               node:test suite + fixtures (good vs risky)
cordis.patch.yml    bundle patch (dsh.bundle.patch target)
```

## Security model

- Never executes the target plugin.
- Bounded reads (max files / bytes) and depth-limited directory walk.
- Network only for public metadata; every call time-bounded.
- All results are owned JSON; live DSH objects are never serialized.

## License

MIT
