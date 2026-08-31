// OSV known-vulnerability lookup for dsh-plugin-eval.
//
// This is the "npm audit" half of the comparison: instead of only flagging
// floating ranges and lifecycle scripts heuristically, we query the OSV
// database (api.osv.dev) for *known vulnerabilities* affecting the plugin's
// pinned dependencies.
//
// The DSH `web` service is read-only GET, and OSV exposes the same query via
// GET with bracket-encoded parameters:
//
//   GET https://api.osv.dev/v1/query?package[name]=<name>&package[ecosystem]=npm&version=<version>
//   -> { "vulns": [ { "id", "summary", "aliases", "affected", "modified", ... } ] }
//
// Everything is defensive: bounded queries, per-call timeout, abort on the
// tool signal, and graceful degradation to `available:false` on any failure.

const OSV_QUERY = 'https://api.osv.dev/v1/query'
const MAX_QUERIES = 24
const DEFAULT_TIMEOUT_MS = 6000

/**
 * Look up known vulnerabilities for a set of pinned dependency versions.
 *
 * @param {{ web?: { fetch: Function } }} deps
 * @param {Array<{name:string, version:string}>} pinned deps with exact versions
 * @param {{ signal?: AbortSignal, timeoutMs?: number, maxQueries?: number }} [opts]
 * @returns {Promise<{ available: boolean, checked: number, vulns: Array<object>, byPackage: Record<string, number>, score: number|null, detail: string, error?: string }>}
 */
export async function queryKnownVulnerabilities(deps, pinned, opts = {}) {
  const web = deps?.web
  if (!web || typeof web.fetch !== 'function') {
    return empty('no network service')
  }
  const maxQueries = opts.maxQueries ?? MAX_QUERIES
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS

  const vulns = []
  const byPackage = {}
  let checked = 0

  // De-duplicate by name@version and bound the total work.
  const seen = new Set()
  const unique = []
  for (const d of pinned ?? []) {
    if (!d?.name || !/^\d+\.\d+\.\d+$/.test(d.version ?? '')) continue
    const key = `${d.name}@${d.version}`
    if (seen.has(key)) continue
    seen.add(key)
    unique.push(d)
    if (unique.length >= maxQueries) break
  }

  for (const d of unique) {
    if (opts.signal?.aborted) break
    checked++
    try {
      const url =
        `${OSV_QUERY}?package%5Bname%5D=${encodeURIComponent(d.name)}` +
        `&package%5Becosystem%5D=npm&version=${encodeURIComponent(d.version)}`
      const body = await fetchJson(web, url, timeoutMs, opts.signal)
      const found = Array.isArray(body?.vulns) ? body.vulns : []
      for (const v of found) {
        vulns.push({
          id: v?.id,
          summary: v?.summary ?? '',
          aliases: Array.isArray(v?.aliases) ? v.aliases : [],
          modified: v?.modified ?? null,
          published: v?.published ?? null,
          package: d.name,
          version: d.version,
        })
      }
      byPackage[d.name] = (byPackage[d.name] ?? 0) + found.length
    } catch {
      // individual query failure does not fail the whole lookup
    }
  }

  if (checked === 0) {
    return { ...empty('no pinned dependencies to query'), checked: 0, available: true }
  }

  // Score: each known vuln on a pinned dep is a hard security hit.
  const score = Math.max(0, Math.round(100 - vulns.length * 20))
  return {
    available: true,
    checked,
    vulns,
    byPackage,
    score,
    detail: `OSV: ${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} across ${checked} pinned package(s)`,
  }
}

function empty(reason) {
  return { available: false, reason, checked: 0, vulns: [], byPackage: {}, score: null, detail: reason }
}

async function fetchJson(web, url, timeoutMs, signal) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const onAbort = () => controller.abort()
  signal?.addEventListener?.('abort', onAbort)
  try {
    const res = await web.fetch({ url }, controller.signal)
    if (typeof res?.body === 'string') return JSON.parse(res.body)
    if (res?.body?.kind === 'text' && typeof res.body.content === 'string') return JSON.parse(res.body.content)
    throw new Error('unexpected fetch body')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener?.('abort', onAbort)
  }
}
