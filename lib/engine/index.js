// Engine orchestrator for dsh-plugin-eval.
//
// evaluatePlugin() is the single entry point used both by the Cordis Tool and
// by tests. It never executes the target plugin: local targets are read
// statically through the `fs` service, remote metadata through the optional
// `web` service.

import { collectLocalSource } from './util.js'
import { scanSecurity, auditManifest } from './security.js'
import { benchmarkPerformance } from './performance.js'
import { collectCommunity } from './community.js'
import { checkCompatibility } from './compatibility.js'
import { computeComposite, summarizeFindings } from './score.js'
import { queryKnownVulnerabilities } from './vulns.js'
import { auditLockfile, findLockfile } from './lockfile.js'
import { collectRemoteSource } from './remote.js'

const DEFAULT_RUNTIME = {
  nodeVersion: typeof process !== 'undefined' && process.versions?.node ? process.versions.node : undefined,
  dshVersion: undefined,
}

/**
 * @param {object} args
 * @param {string} args.target local directory path, `owner/repo`, or package name
 * @param {object} [args.deps] optional `{ fs, web }` service handles
 * @param {object} [args.runtime] `{ nodeVersion?, dshVersion? }`
 * @param {object} [args.opts] `{ allowNetwork?, timeoutMs? }`
 */
export async function evaluatePlugin(args) {
  const { target } = args
  const deps = args.deps ?? {}
  const runtime = { ...DEFAULT_RUNTIME, ...(args.runtime ?? {}) }
  const opts = args.opts ?? {}
  const allowNetwork = opts.allowNetwork !== false
  const signal = opts.signal
  const startedAt = Date.now()

  const { manifest, source } = await loadTarget(target, deps, opts)

  // 1) Security: secrets + risky patterns + manifest audit
  const securityScan = scanSecurity(source)
  const manifestAudit = auditManifest(manifest)
  let securityScore = Math.round((securityScan.score * 0.6 + manifestAudit.score * 0.4) * 10) / 10

  // 1b) Known-vulnerability lookup (npm-audit half) + lockfile audit.
  const pinned = collectPinned(manifest, source)
  const osv = allowNetwork
    ? await queryKnownVulnerabilities(deps, pinned, { signal, timeoutMs: opts.timeoutMs })
    : { available: false, reason: 'network disabled', checked: 0, vulns: [], byPackage: {}, score: null, detail: 'network disabled' }
  const lockfile = auditLockfile(source)
  if (osv.available && typeof osv.score === 'number') {
    // Known CVEs hit security hard, regardless of the heuristic scan.
    securityScore = Math.round(Math.min(securityScore, osv.score) * 10) / 10
  }

  // 2) Footprint / performance
  const performance = benchmarkPerformance({ ...source, manifest })

  // 3) Compatibility
  const compatibility = checkCompatibility(manifest, runtime)

  // 4) Community (optional)
  const repo = repoOf(manifest, target)
  const npmName = npmNameOf(manifest, target)
  const community = allowNetwork
    ? await collectCommunity(deps, repo, npmName, { signal, timeoutMs: opts.timeoutMs })
    : { available: false, reason: 'network disabled' }

  const documentation = scoreDocumentation(source, manifest)

  // 5) Composite
  const scores = {
    security: securityScore,
    compatibility: compatibility.score,
    performance: performance.score,
    community: community.score,
    documentation: documentation.score,
  }
  const composite = computeComposite(scores)

  const allFindings = [
    ...securityScan.secrets.map((s) => ({ severity: s.severity, label: s.label, reason: `secret in ${s.file}` })),
    ...securityScan.risks.map((r) => ({ severity: r.severity, label: r.label, reason: r.reason })),
    ...(osv?.vulns ?? []).map((v) => ({
      severity: 'high',
      label: `Known vulnerability ${v.id ?? '?'}: ${v.summary ?? ''} (${v.package}@${v.version})`,
      reason: 'affected dependency has a published advisory in the OSV database',
    })),
    ...manifestAudit.findings,
    ...(lockfile.present ? [] : [{ severity: 'medium', label: 'No lockfile found', reason: 'installs are not reproducible; resolved dependency tree is unverifiable' }]),
    ...compatibility.findings,
  ]

  return {
    schema: 1,
    target,
    evaluatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    runtime: {
      nodeVersion: runtime.nodeVersion ?? null,
      dshVersion: runtime.dshVersion ?? null,
    },
    source: {
      kind: source.kind,
      root: source.root ?? null,
      fileCount: source.files?.length ?? 0,
      totalBytes: source.totalBytes ?? 0,
      readError: source.error ?? null,
    },
    manifest: manifestAudit.manifest ?? null,
    manifestAudit,
    scores,
    composite,
    findings: summarizeFindings(allFindings),
    security: {
      score: securityScore,
      scan: securityScan,
      manifest: manifestAudit,
      osv,
      lockfile,
    },
    performance,
    compatibility,
    community,
    documentation,
    report: renderReport({
      target,
      manifest: manifestAudit.manifest,
      scores,
      composite,
      findings: summarizeFindings(allFindings),
      security: securityScan,
      manifestAudit,
      osv,
      lockfile,
      performance,
      compatibility,
      community,
      documentation,
    }),
  }
}

async function loadTarget(target, deps, opts) {
  const fs = deps?.fs
  if (!target || typeof target !== 'string') {
    throw new Error('evaluatePlugin requires a target: local directory path, owner/repo, or npm package name')
  }

  const looksLikeLocal = /^[A-Za-z]:[\\/]|^[\\/]|^\.{1,2}[\\/]/.test(target) || /\.\w+$/.test(target.split(/[\\/]/).pop() ?? '')
  if (looksLikeLocal && fs) {
    const source = await collectLocalSource(fs, target, {
      signal: opts.signal,
      maxFiles: opts.maxFiles,
      maxBytes: opts.maxBytes,
    })
    const manifest = parseManifest(findManifestText(source))
    if (manifest) source.manifest = manifest
    return { manifest, source }
  }

  if (looksLikeLocal && !fs) {
    // Local-looking target but no fs service: degrade gracefully.
    return {
      manifest: undefined,
      source: { kind: 'local-unavailable', root: target, files: [], texts: {}, totalBytes: 0 },
    }
  }

  // GitHub owner/repo: deep-scan the repository remotely when the network is
  // enabled and a `web` service exists. This is read-only (git trees + raw
  // text), never a clone and never an execution.
  const remote = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(target ?? '')
  if (remote && opts.allowNetwork !== false && deps?.web) {
    const source = await collectRemoteSource(deps, remote[1], remote[2], { signal: opts.signal })
    const manifest = parseManifest(findManifestText(source))
    if (manifest) source.manifest = manifest
    return { manifest, source }
  }

  // Remote target without a local checkout and no remote scan: metadata only.
  return {
    manifest: undefined,
    source: { kind: 'remote', root: null, files: [], texts: {}, totalBytes: 0, remoteTarget: target },
  }
}

export function parseManifest(text) {
  if (!text) return undefined
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? parsed : undefined
  } catch {
    return undefined
  }
}

/** Find the package.json text from a collected source (root-most preferred). */
export function findManifestText(source) {
  const texts = source.texts ?? {}
  // Prefer a package.json at the source root, then any nested one.
  const candidates = Object.keys(texts).filter((p) => /(^|\/)package\.json$/.test(p))
  if (candidates.length === 0) return undefined
  candidates.sort((a, b) => a.split('/').length - b.split('/').length)
  return texts[candidates[0]]
}

function repoOf(manifest, target) {
  if (manifest?.repository) {
    const url = typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url
    const m = /github\.com[/:]([^/]+)\/([^/#.]+)/.exec(url ?? '')
    if (m) return `${m[1]}/${m[2]}`
  }
  const remote = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(target ?? '')
  return remote ? `${remote[1]}/${remote[2]}` : undefined
}

function npmNameOf(manifest, target) {
  if (manifest?.name && /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(manifest.name)) {
    return manifest.name
  }
  const looksLikePackage = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(target ?? '')
  return looksLikePackage ? target : undefined
}

/**
 * Collect the set of pinned name@version pairs to feed the OSV lookup:
 * exact-version runtime/optional deps from the manifest plus every pinned
 * resolution recorded in a lockfile (the source of truth for what actually
 * installs).
 * @param {object|undefined} manifest
 * @param {object} source
 */
export function collectPinned(manifest, source) {
  const pinned = []
  const seen = new Set()
  const push = (name, version) => {
    if (!name || !/^\d+\.\d+\.\d+$/.test(version ?? '')) return
    const key = `${name}@${version}`
    if (seen.has(key)) return
    seen.add(key)
    pinned.push({ name, version })
  }
  for (const bucket of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(manifest?.[bucket] ?? {})) {
      if (/^\d+\.\d+\.\d+$/.test(spec ?? '')) push(name, spec)
    }
  }
  const lockfile = findLockfile(source)
  for (const d of lockfile?.pinned ?? []) push(d.name, d.version)
  return pinned
}

function scoreDocumentation(source, manifest) {
  const files = source.files ?? []
  const texts = source.texts ?? {}
  let score = 0
  const signals = {}

  const readme = files.find((f) => /readme/i.test(f.name))
  signals.hasReadme = Boolean(readme)
  if (readme) {
    const text = texts[readme.path] ?? ''
    score += Math.min(40, 20 + Math.floor(text.length / 400))
  }

  signals.hasLicense = Boolean(files.find((f) => /^license(\.|$)/i.test(f.name)) || manifest?.license)
  if (signals.hasLicense) score += 20

  signals.hasTests = Boolean(files.find((f) => /(^|\/)(test|tests|__tests__|spec)(\/|\.)/.test(f.path)))
  if (signals.hasTests) score += 20

  signals.hasExample = Boolean(files.find((f) => /(example|examples|demo)/i.test(f.path)))
  if (signals.hasExample) score += 10

  signals.hasContributing = Boolean(files.find((f) => /contributing/i.test(f.name)))
  if (signals.hasContributing) score += 5

  signals.hasChangelog = Boolean(files.find((f) => /changelog|changes/i.test(f.name)))
  if (signals.hasChangelog) score += 5

  return {
    score: Math.min(100, score),
    detail: `documentation & quality: ${Math.min(100, score)}/100`,
    signals,
  }
}

// ---------------------------------------------------------------------------
// Human-readable report (used by the Tool render and the report field)
// ---------------------------------------------------------------------------

export function renderReport(r) {
  const lines = []
  lines.push(`# Plugin Reliability Report — ${r.target}`)
  lines.push('')
  if (r.manifest?.name) lines.push(`**${r.manifest.name}** ${r.manifest.version ?? ''}${r.manifest.license ? ` · ${r.manifest.license}` : ''}`)
  lines.push('')
  lines.push(`## Composite: **${r.composite.score}/100 (${r.composite.grade})** — verdict: **${r.composite.verdict}**`)
  lines.push('')
  for (const cat of r.composite.categories) {
    const bar = barOf(r.scores[cat.key] ?? 0)
    lines.push(`- ${cat.label}: ${r.scores[cat.key]} ${bar}`)
  }
  for (const miss of r.composite.missing) {
    lines.push(`- ${miss}: _no data (skipped)_`)
  }
  lines.push('')
  const findings = r.findings
  lines.push(`## Findings: ${findings.total} (${Object.entries(findings.bySeverity).map(([k, v]) => `${k}:${v}`).join(', ')})`)
  for (const f of findings.top) {
    lines.push(`- **[${f.severity}]** ${f.label}${f.reason ? ` — ${f.reason}` : ''}`)
  }
  if (r.osv?.available) {
    lines.push('')
    lines.push(`## Known vulnerabilities (OSV): ${r.osv.vulns?.length ?? 0} in ${r.osv.checked ?? 0} pinned package(s)`)
    for (const v of (r.osv.vulns ?? []).slice(0, 8)) {
      lines.push(`- ${v.id ?? '?'} — ${v.summary ?? ''} (${v.package}@${v.version})`)
    }
  } else if (r.osv) {
    lines.push('')
    lines.push(`## Known vulnerabilities (OSV): unavailable (${r.osv.reason ?? 'no data'})`)
  }
  if (r.lockfile) {
    lines.push('')
    lines.push(`## Lockfile: ${r.lockfile.present ? `${r.lockfile.files.length} file(s), ${r.lockfile.pinned.length} pinned` : 'not found — installs not reproducible'}`)
  }
  lines.push('')
  lines.push(`> Static analysis only; the plugin was **not executed**. Evaluated at ${new Date().toISOString()}.`)
  return lines.join('\n')
}

function barOf(score) {
  const filled = Math.round(score / 10)
  return '█'.repeat(filled) + '░'.repeat(10 - filled)
}
