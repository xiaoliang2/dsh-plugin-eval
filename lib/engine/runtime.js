// Runtime facts resolution for dsh-plugin-eval.
//
// The compatibility dimension needs the *current* DSH version to verify a
// plugin's `@deepseek-ai/*` peerDependencies. The Host does not expose a
// version constant, so we resolve it from the installed `@deepseek-ai/dsh`
// package when reachable, and otherwise degrade to "unknown" (which the
// compatibility check already reports as a low-severity finding rather than a
// hard failure). Every strategy is wrapped so resolution can never throw.

import { createRequire } from 'node:module'

/**
 * Best-effort resolution of the running DSH version.
 * Strategy order:
 *   1. explicit value (config / tool arg)
 *   2. createRequire from this plugin's location for `@deepseek-ai/dsh/package.json`
 *   3. undefined (unknown)
 *
 * @param {string|undefined} explicit optional known value
 * @returns {string|undefined}
 */
export function resolveDshVersion(explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) return explicit
  try {
    const require = createRequire(import.meta.url)
    // `@deepseek-ai/dsh` ships no `exports` map, so the package.json subpath is
    // directly resolvable when the package is installed in a reachable tree.
    const pkg = require('@deepseek-ai/dsh/package.json')
    if (pkg && typeof pkg.version === 'string' && pkg.version.length > 0) return pkg.version
  } catch {
    // not reachable from this install — fall through
  }
  return undefined
}

/**
 * @param {string|undefined} [explicit]
 * @returns {{ nodeVersion: string|undefined, dshVersion: string|undefined }}
 */
export function resolveRuntimeFacts(explicit) {
  return {
    nodeVersion: typeof process !== 'undefined' && process.versions?.node ? process.versions.node : undefined,
    dshVersion: resolveDshVersion(explicit),
  }
}
