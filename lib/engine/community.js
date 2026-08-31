// Community review aggregation for dsh-plugin-eval.
//
// Pulls public metadata — GitHub stars/forks/issues/activity and npm
// downloads/versions — through the optional `web` service. Network is optional:
// when unavailable, the dimension reports `available: false` and the composite
// score renormalizes without it. We only read public JSON; no credentials.

/**
 * @param {{ web?: { fetch: Function } }} deps
 * @param {string} repo `owner/repo`
 * @param {string} [npmName] package name on npm
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} [opts]
 */
export async function collectCommunity(deps, repo, npmName, opts = {}) {
  const web = deps?.web
  if (!web || typeof web.fetch !== 'function') {
    return { available: false, reason: 'no network service' }
  }
  const timeoutMs = opts.timeoutMs ?? 8000
  const github = {}
  const npm = {}

  if (repo && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    try {
      github.raw = await fetchJson(web, `https://api.github.com/repos/${encodeURIComponent(repo)}`, timeoutMs, opts.signal)
      github.ok = Boolean(github.raw?.full_name)
    } catch (err) {
      github.error = String(err?.message ?? err)
    }
    if (github.raw?.full_name) {
      try {
        const releases = await fetchJson(web, `https://api.github.com/repos/${encodeURIComponent(repo)}/releases?per_page=5`, timeoutMs, opts.signal)
        github.latestRelease = Array.isArray(releases) && releases.length > 0 ? releases[0] : null
      } catch {
        github.latestRelease = null
      }
    }
  }

  if (npmName) {
    try {
      const reg = await fetchJson(web, `https://registry.npmjs.org/${encodeURIComponent(npmName).replace(/%2F/g, '/')}`, timeoutMs, opts.signal)
      if (reg?.name && typeof reg.time?.modified === 'string') {
        npm.ok = true
        npm.name = reg.name
        npm.latest = reg['dist-tags']?.latest ?? null
        npm.modified = reg.time?.modified ?? null
        npm.versionCount = Array.isArray(reg.versions) ? 0 : Object.keys(reg.versions ?? {}).length
        npm.maintainers = Array.isArray(reg.maintainers) ? reg.maintainers.length : 0
      } else {
        npm.error = 'not found'
      }
    } catch (err) {
      npm.error = String(err?.message ?? err)
    }
    if (npm.ok) {
      try {
        const dl = await fetchJson(web, `https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(npmName)}`, timeoutMs, opts.signal)
        npm.downloadsLastMonth = typeof dl?.downloads === 'number' ? dl.downloads : null
      } catch {
        npm.downloadsLastMonth = null
      }
    }
  }

  const hasData = github.ok || npm.ok
  if (!hasData) {
    return { available: true, fetched: false, github, npm, score: null, detail: 'no community data found' }
  }

  return {
    available: true,
    fetched: true,
    github,
    npm,
    ...scoreCommunity(github, npm),
  }
}

function scoreCommunity(github, npm) {
  // 0..100 community signal. Heuristic, clearly labelled as such.
  let score = 30 // neutral baseline

  if (github.ok) {
    const stars = github.raw.stargazers_count ?? 0
    const forks = github.raw.forks_count ?? 0
    const openIssues = github.raw.open_issues_count ?? 0
    const archived = github.raw.archived === true
    const pushed = github.raw.pushed_at ? Date.parse(github.raw.pushed_at) : NaN

    score += Math.min(35, Math.log10(1 + stars) * 12)
    score += Math.min(10, Math.log10(1 + forks) * 5)
    if (archived) score -= 25
    const ageDays = (Date.now() - (Number.isFinite(pushed) ? pushed : Date.now())) / 86400000
    if (Number.isFinite(ageDays)) {
      if (ageDays < 90) score += 12
      else if (ageDays < 365) score += 4
      else if (ageDays > 730) score -= 10
    }
    if (openIssues > 200) score -= 5
  }

  if (npm.ok) {
    const dl = npm.downloadsLastMonth ?? 0
    score += Math.min(15, Math.log10(1 + dl) * 2.2)
    if (npm.versionCount > 1) score += 3
  }

  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  return {
    score: clamped,
    detail: `community signal: ${clamped}/100 (${github.ok ? 'github' : ''}${github.ok && npm.ok ? ' + ' : ''}${npm.ok ? 'npm' : ''})`,
  }
}

async function fetchJson(web, url, timeoutMs, signal) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const onAbort = () => controller.abort()
  signal?.addEventListener?.('abort', onAbort)
  try {
    // Real web Service Definition: fetch(request: WebFetchRequest, signal?).
    const res = await web.fetch({ url }, controller.signal)
    if (typeof res?.body === 'string') return JSON.parse(res.body)
    if (res?.body?.kind === 'text' && typeof res.body.content === 'string') return JSON.parse(res.body.content)
    throw new Error('unexpected fetch body')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener?.('abort', onAbort)
  }
}
