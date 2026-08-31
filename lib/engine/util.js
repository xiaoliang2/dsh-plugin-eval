// Shared helpers for dsh-plugin-eval engine. Pure JavaScript, no external deps.

// ---------------------------------------------------------------------------
// Semver helpers (subset is enough for compatibility checks)
// ---------------------------------------------------------------------------

/** Parse a strict `x.y.z` version. Returns [major, minor, patch] or null. */
export function parseVersion(input) {
  if (typeof input !== 'string') return null
  const m = /^\s*v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?\s*$/.exec(input)
  if (!m) return null
  return [Number(m[1]), Number(m[2]), Number(m[3])]
}

function cmpVersion(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1
  }
  return 0
}

/**
 * Minimal range matcher supporting: exact, `>=x`, `<=x`, `>x`, `<x`,
 * `^x`, `~x`, `x` with minor/patch wildcards (`1.x`, `1.2.x`), `*`, and
 * space-separated AND / `||` OR groups. This is intentionally conservative:
 * an unparseable range reports `unknown` instead of guessing.
 */
export function satisfiesRange(version, range) {
  const parsed = parseVersion(version)
  if (!parsed) return null
  if (typeof range !== 'string' || range.trim() === '' || range.trim() === '*') return true
  const groups = range.split('||').map((g) => g.trim())
  let anyParseable = false
  for (const group of groups) {
    if (group === '') continue
    const result = matchGroup(parsed, group)
    if (result === true) return true
    if (result === null) anyParseable = true
  }
  // A range whose tokens were all unparseable (e.g. a tag like "latest")
  // is unknown rather than unsatisfied.
  return anyParseable ? null : false
}

function matchGroup(version, group) {
  const parts = group.split(/\s+/).filter(Boolean).filter((t) => t !== '&&' && t !== ',')
  if (parts.length === 0) return true
  let sawUnknown = false
  for (const part of parts) {
    const r = matchSingle(version, part)
    if (r === null) {
      sawUnknown = true
      continue
    }
    if (!r) return false
  }
  return sawUnknown ? null : true
}

function matchSingle(version, token) {
  if (token === '*' || token === 'x') return true
  const m = /^(>=|<=|>|<|\^|~)?([v]?)(\d+|\*|x)(?:\.(\d+|\*|x))?(?:\.(\d+|\*|x))?$/.exec(token.trim())
  if (!m) return null // not a parseable semver token (e.g. "latest")
  const [, op, , maj, min, pat] = m
  const num = (s) => (s === undefined || s === '*' || s === 'x' ? null : Number(s))
  const target = [num(maj), num(min), num(pat)]

  if (op === '>=' || op === '<=' || op === '>' || op === '<') {
    // Partial ranges like `>=12` mean `>=12.0.0`.
    const targetFull = [target[0] ?? 0, target[1] ?? 0, target[2] ?? 0]
    const c = cmpVersion(version, targetFull)
    if (op === '>=') return c >= 0
    if (op === '<=') return c <= 0
    if (op === '>') return c > 0
    return c < 0
  }

  if (op === '^') {
    // >= target, and < next breaking major (or minor when major is 0)
    if (target[0] === null) return true
    const [ma, mi = 0, pa = 0] = target
    if (ma === 0) {
      const lower = [0, mi, pa]
      const upper = mi === 0 ? [0, 1, 0] : [0, mi + 1, 0]
      return cmpVersion(version, lower) >= 0 && cmpVersion(version, upper) < 0
    }
    return cmpVersion(version, [ma, mi, pa]) >= 0 && cmpVersion(version, [ma + 1, 0, 0]) < 0
  }

  if (op === '~') {
    const [ma, mi = 0, pa = 0] = target
    const lower = [ma, mi, pa]
    const upper = [ma, mi + 1, 0]
    return cmpVersion(version, lower) >= 0 && cmpVersion(version, upper) < 0
  }

  // Exact or wildcard
  if (target[0] !== null && version[0] !== target[0]) return false
  if (target[1] !== null && version[1] !== target[1]) return false
  if (target[2] !== null && version[2] !== target[2]) return false
  return true
}

/** Report whether a dependency version spec is "pinned" to an exact version. */
export function isPinned(spec) {
  return typeof spec === 'string' && /^\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\s*$/.test(spec)
}

/** Report whether a spec is floating (loose range, star, tag, git/url/workspace). */
export function isFloating(spec) {
  if (typeof spec !== 'string' || spec.trim() === '') return true
  const trimmed = spec.trim()
  if (/^(github:|git\+|file:|link:|workspace:|npm:|http)/.test(trimmed)) return true
  if (trimmed === 'latest' || trimmed === '*') return true
  return /[~^><|\s]/.test(trimmed) || /\.x$/i.test(trimmed)
}

// ---------------------------------------------------------------------------
// Size / count formatting
// ---------------------------------------------------------------------------

export function formatBytes(n) {
  if (!Number.isFinite(n)) return '0 B'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n
  let u = -1
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024
    u++
  }
  return `${v.toFixed(1)} ${units[u]}`
}

// ---------------------------------------------------------------------------
// Source model
//
// The engine never executes the target plugin. It only reads metadata and
// small text files, so a hostile plugin cannot run anything during evaluation.
// ---------------------------------------------------------------------------

/**
 * Walk a local directory (bounded) and collect file paths, sizes, and the text
 * of small text files. Uses the optional `fs` service; returns an owned plain
 * object. Matches the real DSH `fs` Service Definition: resolve once to an
 * opaque `FsTarget`, then `listDir` returns entries shaped
 * `{ name, type: 'file'|'directory'|'other', target, size?, version? }`.
 *
 * @param {{ resolve: Function, processPath: Function, readText: Function, listDir: Function }} fs
 * @param {string} root absolute path to the plugin directory
 * @param {{ signal?: AbortSignal, maxFiles?: number, maxBytes?: number, maxTextBytes?: number, maxDepth?: number }} opts
 */
export async function collectLocalSource(fs, root, opts = {}) {
  const maxFiles = opts.maxFiles ?? 2000
  const maxBytes = opts.maxBytes ?? 64 * 1024 * 1024
  const maxTextBytes = opts.maxTextBytes ?? 256 * 1024
  const maxDepth = opts.maxDepth ?? 8

  const files = []
  const texts = new Map()
  let totalBytes = 0

  let rootTarget
  try {
    rootTarget = await fs.resolve(root, { signal: opts.signal })
  } catch {
    return { kind: 'local', root, error: 'resolve-failed', files: [], texts: {}, totalBytes: 0 }
  }

  async function walk(target, depth) {
    if (depth > maxDepth || files.length >= maxFiles || totalBytes >= maxBytes) return
    let entries
    try {
      entries = await fs.listDir(target, opts.signal)
    } catch {
      return
    }
    for (const entry of entries ?? []) {
      if (opts.signal?.aborted) return
      const name = entry.name
      if (name === '.git' || name === 'node_modules' || name === 'dist' || name === '.DS_Store' || name === '.cache') continue
      if (entry.type === 'directory') {
        await walk(entry.target, depth + 1)
        continue
      }
      if (entry.type !== 'file') continue
      const size = typeof entry.size === 'number' ? entry.size : 0
      let path
      try {
        path = fs.processPath(entry.target).replaceAll('\\', '/')
      } catch {
        path = `${String(root).replaceAll('\\', '/')}/${name}`
      }
      totalBytes += size
      files.push({ path, name, size })
      if (size > 0 && size <= maxTextBytes && isTextCandidate(name)) {
        try {
          const text = await fs.readText(entry.target, opts.signal)
          if (typeof text === 'string' && text.length > 0) texts.set(path, text)
        } catch {
          // keep going; a file we cannot read is not an evaluation failure
        }
      }
    }
  }

  await walk(rootTarget, 0)
  return {
    kind: 'local',
    root,
    files,
    texts: Object.fromEntries(texts),
    totalBytes,
  }
}

/** Rough filter for files we want to read as text (avoid binaries). */
export function isTextCandidate(name) {
  if (/\.(png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|tgz|jar|wasm|lock)$/i.test(name)) return false
  if (/\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|json|ya?ml|yml|md|txt|toml|xml|html|css|scss|sh|ps1|bat|py|rb|go|rs|java|c|h|cpp|hpp|ipynb|patch|diff|sql|env|properties|cfg|ini|gitignore)$/i.test(name)) return true
  return false
}

/**
 * Best-effort anonymous anonymous-user-id avoidance: compute a stable hash of a
 * string using only built-in primitives (no crypto dependency required on Host).
 */
export function simpleHash(input) {
  let h = 2166136261
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return (h >>> 0).toString(16)
}
