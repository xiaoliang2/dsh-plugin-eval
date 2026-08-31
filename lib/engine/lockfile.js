// Lockfile audit for dsh-plugin-eval.
//
// Supply-chain attacks frequently hide in the *resolved* dependency tree that
// the lockfile records, not the loose ranges in package.json. We parse the
// common lockfile formats (package-lock.json JSON, pnpm-lock.yaml and
// yarn.lock heuristically — no YAML dependency) and report:
//   - whether a lockfile exists at all (reproducibility signal)
//   - the resolved pinned name@version set (feeds the OSV lookup)
//   - integrity / registry signals we can read without installing anything

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'npm-shrinkwrap.json']

/**
 * Find lockfile text from a collected source.
 * @param {{ texts: Record<string,string>, files: Array<{name:string}> }} source
 */
export function findLockfile(source) {
  const texts = source.texts ?? {}
  const hits = []
  for (const [path, text] of Object.entries(texts)) {
    const name = path.split('/').pop() ?? ''
    if (LOCKFILE_NAMES.includes(name)) hits.push({ path, name, text })
  }
  return hits.sort((a, b) => a.path.split('/').length - b.path.split('/').length)[0]
}

/**
 * Audit lockfiles present in the source.
 * @param {{ texts: Record<string,string> }} source
 */
export function auditLockfile(source) {
  const texts = source.texts ?? {}
  const found = Object.keys(texts).filter((p) => {
    const name = p.split('/').pop() ?? ''
    return LOCKFILE_NAMES.includes(name)
  })

  if (found.length === 0) {
    return {
      present: false,
      files: [],
      pinned: [],
      score: 30,
      detail: 'no lockfile found — installs are not reproducible',
      signals: { reproducibility: 'low' },
    }
  }

  const pinned = []
  const files = []
  let hasIntegrity = false
  let registrySignals = 0

  for (const path of found.sort((a, b) => a.split('/').length - b.split('/').length)) {
    const name = path.split('/').pop() ?? ''
    const text = texts[path]
    const parsed = parseLockfile(name, text)
    pinned.push(...parsed.pinned)
    hasIntegrity = hasIntegrity || parsed.hasIntegrity
    registrySignals += parsed.registrySignals
    files.push({ path, name, count: parsed.pinned.length, hasIntegrity: parsed.hasIntegrity })
  }

  // A lockfile alone is good; integrity entries make it much stronger.
  let score = 55
  if (hasIntegrity) score += 25
  if (files.length >= 2) score += 10
  if (pinned.length === 0) score = 40

  return {
    present: true,
    files,
    pinned,
    score: Math.max(0, Math.min(100, score)),
    detail: `${files.length} lockfile(s), ${pinned.length} pinned resolution(s)${hasIntegrity ? ', integrity recorded' : ', no integrity records'}`,
    signals: {
      hasIntegrity,
      reproducibility: hasIntegrity ? 'high' : 'medium',
      registrySignals,
    },
  }
}

/**
 * Parse a lockfile into pinned name@version pairs. Pure string parsing so we
 * need no YAML dependency; unknown formats return an empty result.
 * @param {string} name lockfile file name
 * @param {string} text content
 */
export function parseLockfile(name, text) {
  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
    return parsePackageLock(text)
  }
  if (name === 'pnpm-lock.yaml') {
    return parsePnpmLock(text)
  }
  if (name === 'yarn.lock') {
    return parseYarnLock(text)
  }
  return { pinned: [], hasIntegrity: false, registrySignals: 0 }
}

function parsePackageLock(text) {
  let root
  try {
    root = JSON.parse(text)
  } catch {
    return { pinned: [], hasIntegrity: false, registrySignals: 0 }
  }
  const pinned = []
  let hasIntegrity = false
  // npm v7+ uses `packages` (keyed by path, includes root); v1 used `dependencies`.
  const deps = root?.packages ?? root?.dependencies ?? {}
  for (const [key, entry] of Object.entries(deps ?? {})) {
    if (!entry || typeof entry !== 'object') continue
    // npm v7+ keys look like "", "node_modules/lodash", "node_modules/@scope/pkg"
    const name = entry.name ?? key.split('node_modules/').pop() ?? key
    if (typeof entry.version === 'string' && /^\d+\.\d+\.\d+$/.test(entry.version)) {
      pinned.push({ name, version: entry.version })
    }
    if (typeof entry.integrity === 'string' && entry.integrity.length > 0) hasIntegrity = true
  }
  return { pinned, hasIntegrity, registrySignals: hasIntegrity ? 1 : 0 }
}

function parsePnpmLock(text) {
  // pnpm-lock.yaml shape (v6+):
  //   packages:
  //     /lodash@4.17.21:
  //       resolution: {integrity: sha512-...}
  const pinned = []
  let hasIntegrity = false
  let registrySignals = 0
  // pnpm-lock.yaml v6+ package keys are indented under `packages:`, e.g.
  //   packages:
  //     /lodash@4.17.21:
  //       resolution: {integrity: sha512-...}
  const lineRe = /^\s+\/(.+?)@(\d+\.\d+\.\d+):\s*$/
  for (const line of text.split('\n')) {
    const m = lineRe.exec(line)
    if (m) {
      pinned.push({ name: m[1], version: m[2] })
    } else if (/integrity\s*:/.test(line)) {
      hasIntegrity = true
    } else if (/^registry\s*:/.test(line) || /tarball\s*:/.test(line)) {
      registrySignals++
    }
  }
  return { pinned, hasIntegrity, registrySignals }
}

function parseYarnLock(text) {
  // yarn.lock v1 shape:
  //   "lodash@^4.17.21":
  //     version "4.17.21"
  const pinned = []
  let hasIntegrity = false
  let currentRange = null
  for (const line of text.split('\n')) {
    const header = /^"?([^"\s]+)@([^"\s]+)"?:$/.exec(line.trim())
    if (header) {
      currentRange = header[1]
      continue
    }
    const ver = /^\s+version\s+"(\d+\.\d+\.\d+)"/.exec(line)
    if (ver && currentRange) {
      pinned.push({ name: currentRange, version: ver[1] })
      currentRange = null
    }
    if (/integrity\s+sha/.test(line)) hasIntegrity = true
  }
  return { pinned, hasIntegrity, registrySignals: hasIntegrity ? 1 : 0 }
}
