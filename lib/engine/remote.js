// Remote GitHub deep scan for dsh-plugin-eval.
//
// When the target is `owner/repo` and the `web` service is available, we can
// scan the repository remotely without cloning or executing anything:
//
//   1. GET https://api.github.com/repos/{owner}/{repo}            -> default_branch
//   2. GET https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1
//      -> { tree: [ { path, type: 'blob'|'tree', size, url } ] }
//   3. For text blobs under the size bound, GET
//      https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}  -> text
//
// Bounded (files / bytes / depth), time-bounded per call, abortable, and
// degrades gracefully: any failure returns the files we already collected plus
// an error note, never throwing.

const MAX_FILES = 800
const MAX_BYTES = 16 * 1024 * 1024
const MAX_TEXT_BYTES = 256 * 1024
const MAX_TREE_DEPTH = 6
const PER_CALL_TIMEOUT_MS = 8000

/**
 * @param {{ web?: { fetch: Function } }} deps
 * @param {string} owner
 * @param {string} repo
 * @param {{ signal?: AbortSignal }} [opts]
 * @returns {Promise<{ kind:'remote', root:string, defaultBranch?:string, files:Array, texts:Record<string,string>, totalBytes:number, error?:string }>}
 */
export async function collectRemoteSource(deps, owner, repo, opts = {}) {
  const web = deps?.web
  const empty = {
    kind: 'remote',
    root: `https://github.com/${owner}/${repo}`,
    files: [],
    texts: {},
    totalBytes: 0,
  }
  if (!web || typeof web.fetch !== 'function') {
    return { ...empty, error: 'no network service' }
  }

  let meta
  try {
    meta = await fetchJson(web, `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, opts.signal)
  } catch (err) {
    return { ...empty, error: `repo meta: ${String(err?.message ?? err)}` }
  }
  if (!meta?.full_name) {
    return { ...empty, error: `repo not found or not accessible (${owner}/${repo})` }
  }
  const branch = meta.default_branch ?? 'main'

  let tree
  try {
    const res = await fetchJson(
      web,
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      opts.signal,
    )
    tree = Array.isArray(res?.tree) ? res.tree : []
  } catch (err) {
    return { ...empty, defaultBranch: branch, error: `tree: ${String(err?.message ?? err)}` }
  }

  const files = []
  const texts = {}
  let totalBytes = 0

  const blobs = tree
    .filter((t) => t?.type === 'blob' && t?.path && !/(^|\/)node_modules\//.test(t.path))
    .sort((a, b) => (a.path ?? '').localeCompare(b.path ?? ''))

  for (const blob of blobs) {
    if (opts.signal?.aborted) break
    if (files.length >= MAX_FILES || totalBytes >= MAX_BYTES) break
    const path = blob.path
    const name = path.split('/').pop() ?? ''
    const depth = path.split('/').length - 1
    if (depth > MAX_TREE_DEPTH) continue
    const size = typeof blob.size === 'number' ? blob.size : 0

    // Skip obvious binary / vendored junk by name.
    if (/\.(png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|tgz|jar|wasm|lockb)$/i.test(name)) continue

    totalBytes += size
    files.push({ path, name, size })

    if (size > 0 && size <= MAX_TEXT_BYTES && isTextName(name)) {
      try {
        const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`
        const res = await web.fetch({ url: rawUrl }, opts.signal)
        const text =
          typeof res?.body === 'string'
            ? res.body
            : res?.body?.kind === 'text'
              ? res.body.content
              : undefined
        if (typeof text === 'string' && text.length > 0) texts[path] = text
      } catch {
        // keep going; unreadable files are not an evaluation failure
      }
    }
  }

  return { kind: 'remote', root: `https://github.com/${owner}/${repo}`, defaultBranch: branch, files, texts, totalBytes }
}

function isTextName(name) {
  if (/\.(png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|tgz|jar|wasm|lockb)$/i.test(name)) return false
  if (/\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|json|ya?ml|yml|md|txt|toml|xml|html|css|scss|sh|ps1|bat|py|rb|go|rs|java|c|h|cpp|hpp|ipynb|patch|diff|sql|env|properties|cfg|ini|gitignore|lock|lockb|LICENSE)$/i.test(name)) return true
  return false
}

async function fetchJson(web, url, signal) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PER_CALL_TIMEOUT_MS)
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
