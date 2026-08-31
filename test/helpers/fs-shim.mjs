// In-memory `fs` shim matching the DSH `fs` Service Definition surface the
// engine uses: resolve() -> opaque target, processPath(), listDir(), readText().
// Entries are shaped like the real backend: { name, type, target, size }.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, sep, isAbsolute } from 'node:path'

export function createFsShim(root) {
  return {
    async resolve(path) {
      // Accept both absolute targets and paths relative to the shim root.
      const abs = isAbsolute(path) ? path : join(root, path)
      return { targetKey: abs, displayPath: abs }
    },
    processPath(target) {
      return target.displayPath
    },
    async listDir(target, _signal) {
      const entries = readdirSync(target.displayPath, { withFileTypes: true })
      return entries.map((e) => {
        const p = join(target.displayPath, e.name)
        const st = statSync(p)
        return {
          name: e.name,
          type: e.isDirectory() ? 'directory' : e.isFile() ? 'file' : 'other',
          target: { targetKey: p, displayPath: p },
          ...(e.isFile() ? { size: st.size } : {}),
        }
      })
    },
    async readText(target, _signal) {
      return readFileSync(target.displayPath, 'utf8')
    },
  }
}

export function absolute(fixture) {
  // Path separator on Windows; keep it simple with join from cwd-relative.
  return join(process.cwd(), 'test', 'fixtures', fixture).split(sep).join('/')
}
