// Security scanner for dsh-plugin-eval.
//
// Static analysis only: the target plugin's code is never executed. We scan
// collected source text for secret material, dangerous host/network patterns,
// and audit the manifest's dependencies + lifecycle scripts.

import { isFloating, isPinned } from './util.js'

// ---------------------------------------------------------------------------
// Secret patterns
// ---------------------------------------------------------------------------

const SECRET_RULES = [
  {
    id: 'private-key',
    label: 'Private key material',
    severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/i,
  },
  {
    id: 'aws-access-key',
    label: 'AWS access key ID',
    severity: 'critical',
    re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    severity: 'critical',
    re: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  },
  {
    id: 'npm-token',
    label: 'npm auth token',
    severity: 'critical',
    re: /\/\/registry\.npmjs\.org\/:_authToken=[0-9a-f-]{30,}/i,
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    severity: 'critical',
    re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    severity: 'high',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    id: 'stripe-secret',
    label: 'Stripe secret key',
    severity: 'high',
    re: /\bsk_live_[0-9a-zA-Z]{16,}\b/,
  },
  {
    id: 'jwt',
    label: 'JWT (JSON Web Token)',
    severity: 'high',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    id: 'generic-secret-assignment',
    label: 'Hardcoded credential assignment',
    severity: 'high',
    re: /(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][^"'\s]{10,}["']/i,
  },
]

// ---------------------------------------------------------------------------
// Dangerous / risky code patterns
// ---------------------------------------------------------------------------

const RISK_RULES = [
  {
    id: 'eval',
    label: 'eval() / new Function()',
    severity: 'high',
    reason: 'dynamic code execution makes static analysis unreliable and can be abused for obfuscation',
    re: /\b(?:eval|new Function|Function)\s*\(/,
  },
  {
    id: 'child-process',
    label: 'child_process execution',
    severity: 'high',
    reason: 'spawns OS processes; a hostile plugin could run arbitrary commands with agent privileges',
    re: /\b(?:execSync|execFileSync|spawnSync|exec|execFile|spawn|fork)\s*\(/,
  },
  {
    id: 'vm',
    label: 'vm sandbox escape surface',
    severity: 'medium',
    reason: 'vm.runIn* can be used as an escape/obfuscation primitive',
    re: /\bvm\.runIn(?:ThisContext|NewContext|Context)\s*\(/,
  },
  {
    id: 'dynamic-require',
    label: 'Dynamic require/import',
    severity: 'medium',
    reason: 'computed module names make dependencies opaque at install time',
    re: /\b(?:require|import)\s*\(\s*[^"'`]+\)/,
  },
  {
    id: 'insecure-http',
    label: 'Plain HTTP endpoint',
    severity: 'medium',
    reason: 'credentials or telemetry sent over cleartext HTTP could be intercepted',
    re: /\bhttp:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)/,
  },
  {
    id: 'process-env-write',
    label: 'Writes to process environment',
    severity: 'low',
    reason: 'mutating env may affect sibling sessions or leak between agents',
    re: /\bprocess\.env\.[A-Z_]+(?:\s*=(?!=))/,
  },
  {
    id: 'crypto-from-rand',
    label: 'Non-cryptographic randomness for security',
    severity: 'low',
    reason: 'Math.random() used where a cryptographic primitive would be expected',
    re: /Math\.random\(\)/,
  },
  {
    id: 'base64-obfuscation',
    label: 'Base64-decoded execution',
    severity: 'high',
    reason: 'decoding then executing a string is a classic payload-obfuscation pattern',
    re: /(?:atob|Buffer\.from)\s*\([^)]*,\s*["']base64["']\s*\)\s*\)?\s*$/m,
  },
]

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

/**
 * Scan collected source for secrets and risky patterns.
 * @param {{ texts: Record<string,string>, files: Array<{path:string,name:string,size:number}> }} source
 * @returns {{ secrets: Array, risks: Array, score: number, detail: string }}
 */
export function scanSecurity(source) {
  const secrets = []
  const risks = []
  const texts = source.texts ?? {}
  const fileNames = new Set((source.files ?? []).map((f) => f.name))

  for (const [path, content] of Object.entries(texts)) {
    // skip our own test fixtures never happen here; real evaluation only
    for (const rule of SECRET_RULES) {
      let m
      // reset lastIndex for global regexes
      rule.re.lastIndex = 0
      const found = []
      while ((m = rule.re.exec(content)) !== null) {
        found.push(m[0].slice(0, 80))
        if (found.length >= 3) break
        // guard against zero-length matches
        if (m[0].length === 0) rule.re.lastIndex++
      }
      if (found.length > 0) {
        secrets.push({
          rule: rule.id,
          label: rule.label,
          severity: rule.severity,
          file: path,
          sample: found,
          count: (content.match(rule.re) ?? []).length,
        })
      }
    }

    for (const rule of RISK_RULES) {
      const m = rule.re.exec(content)
      if (m) {
        risks.push({
          rule: rule.id,
          label: rule.label,
          severity: rule.severity,
          reason: rule.reason,
          file: path,
          snippet: content.slice(Math.max(0, m.index - 40), m.index + 60),
        })
      }
    }
  }

  const score = computeSecurityScore(secrets, risks, fileNames)
  return { secrets, risks, ...score }
}

// ---------------------------------------------------------------------------
// Manifest / dependency audit
// ---------------------------------------------------------------------------

/**
 * Audit the plugin manifest: dependency pinning, lifecycle scripts, manifest
 * hygiene. `manifest` is the parsed package.json (or undefined).
 * @param {object|undefined} manifest
 */
export function auditManifest(manifest) {
  const findings = []
  const scope = { score: 0, detail: '' }

  if (!manifest) {
    return {
      hasManifest: false,
      findings: [{ severity: 'high', label: 'No package.json manifest found', reason: 'cannot verify identity, dependencies, or lifecycle scripts' }],
      score: 0,
      detail: 'manifest missing',
    }
  }

  const deps = {
    dependencies: manifest.dependencies ?? {},
    devDependencies: manifest.devDependencies ?? {},
    peerDependencies: manifest.peerDependencies ?? {},
    optionalDependencies: manifest.optionalDependencies ?? {},
  }

  const flat = []
  for (const [bucket, map] of Object.entries(deps)) {
    for (const [name, spec] of Object.entries(map ?? {})) flat.push({ name, spec, bucket })
  }

  const pinned = flat.filter((d) => isPinned(d.spec))
  const floating = flat.filter((d) => isFloating(d.spec))

  for (const d of floating) {
    findings.push({
      severity: 'medium',
      label: `Floating dependency: ${d.name}@${d.spec} (${d.bucket})`,
      reason: 'loose range / tag / git / workspace spec means installs are not reproducible and can change behavior between versions',
    })
  }

  const lifecycle = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly']
  for (const script of lifecycle) {
    if (manifest.scripts?.[script]) {
      findings.push({
        severity: script === 'prepare' || script === 'prepublish' || script === 'prepublishOnly' ? 'low' : 'high',
        label: `Lifecycle script "${script}" present`,
        reason: 'runs arbitrary shell during install; common supply-chain attack vector — review it before installing',
      })
    }
  }

  // pinned-package percentage: a rough supply-chain health signal
  const total = flat.length
  const pinRatio = total === 0 ? 1 : pinned.length / total

  if (!manifest.repository) {
    findings.push({
      severity: 'low',
      label: 'Missing repository metadata',
      reason: 'cannot trace provenance or compare releases',
    })
  }
  if (!manifest.license) {
    findings.push({
      severity: 'low',
      label: 'Missing license',
      reason: 'unclear redistribution rights; prefer a declared OSS license',
    })
  }
  if (!manifest.description) {
    findings.push({ severity: 'low', label: 'Missing description', reason: 'reduces discoverability and makes intent opaque' })
  }

  const score = Math.round(
    100
    - floating.length * 12
    - findings.filter((f) => f.severity === 'high').length * 15
    - findings.filter((f) => f.severity === 'medium').length * 6
    - findings.filter((f) => f.severity === 'low').length * 3
  )

  return {
    hasManifest: true,
    manifest: {
      name: manifest.name,
      version: manifest.version,
      description: manifest.description,
      license: manifest.license,
      repository: typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url,
      keywords: manifest.keywords ?? [],
    },
    dependencies: {
      total,
      pinned: pinned.length,
      floating: floating.length,
      pinRatio: Number(pinRatio.toFixed(2)),
    },
    findings,
    score: clamp(score),
    detail: `manifest audit: ${total} deps, ${pinned.length} pinned, ${floating.length} floating; ${findings.length} finding(s)`,
  }
}

function computeSecurityScore(secrets, risks, _fileNames) {
  const sev = { critical: 45, high: 25, medium: 10, low: 3 }
  let penalty = 0
  for (const s of secrets) penalty += sev[s.severity] ?? 15
  for (const r of risks) penalty += sev[r.severity] ?? 8
  const score = clamp(100 - penalty)
  const top = [...secrets, ...risks].sort((a, b) => sev[b.severity] - sev[a.severity])
  const detail =
    secrets.length === 0 && risks.length === 0
      ? 'no secrets or risky patterns detected'
      : `${secrets.length} secret(s), ${risks.length} risky pattern(s)`
  return { score, detail }
}

function clamp(n) {
  return Math.max(0, Math.min(100, n))
}
