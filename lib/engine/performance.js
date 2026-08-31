// Performance / quality benchmark for dsh-plugin-eval.
//
// A Lighthouse-style "performance" category for a plugin is approximated from
// static footprint signals — we deliberately do not execute the plugin to
// time it, since running unknown code during evaluation would defeat the
// whole point of a pre-install check. Signals: file count, total bytes,
// source-vs-dependency ratio, manifest weight, and presence of tests/docs.

import { formatBytes } from './util.js'

const EXT_WEIGHT = {
  '.js': 1,
  '.mjs': 1,
  '.cjs': 1,
  '.ts': 1,
  '.mts': 1,
  '.cts': 1,
  '.jsx': 1,
  '.tsx': 1,
  '.json': 0.2,
  '.md': 0.1,
  '.yml': 0.15,
  '.yaml': 0.15,
  '.css': 0.4,
  '.html': 0.2,
  '.sh': 0.5,
  '.ps1': 0.5,
  '.py': 0.8,
}

/** Rough "effective source size" — bytes weighted by extension. */
export function effectiveSourceBytes(files) {
  let total = 0
  for (const f of files ?? []) {
    const ext = '.' + (f.name.split('.').pop() ?? '').toLowerCase()
    const w = EXT_WEIGHT[ext] ?? 0.5
    total += (f.size ?? 0) * w
  }
  return total
}

/**
 * Benchmark the plugin's footprint.
 * @param {{ files: Array<{path:string,name:string,size:number}>, texts: Record<string,string>, totalBytes: number, manifest?: object }} source
 */
export function benchmarkPerformance(source) {
  const files = source.files ?? []
  const texts = source.texts ?? {}
  const totalBytes = source.totalBytes ?? files.reduce((a, f) => a + (f.size ?? 0), 0)
  const effBytes = effectiveSourceBytes(files)

  const extensions = {}
  for (const f of files) {
    const ext = '.' + (f.name.split('.').pop() ?? '').toLowerCase()
    extensions[ext] = (extensions[ext] ?? 0) + 1
  }

  const sourceFiles = files.filter((f) => /\.(js|mjs|cjs|ts|mts|cts|jsx|tsx)$/.test(f.name))
  const largest = [...files].sort((a, b) => (b.size ?? 0) - (a.size ?? 0)).slice(0, 5)

  const hasTests = files.some((f) => /(^|\/)(test|tests|__tests__|spec)(\/|\.)/.test(f.path))
  const hasDocs = files.some((f) => /readme/i.test(f.name))
  const hasManifest = Boolean(source.manifest)

  // Scores
  const fileScore = files.length === 0 ? 0 : clamp(100 - Math.max(0, files.length - 5) * 2)
  const sizeScore = clamp(100 - Math.log10(Math.max(1, effBytes)) * 22)
  const sourceRatio = effBytes === 0 ? 1 : Math.min(1, sourceFiles.length / Math.max(1, files.length))
  const ratioScore = clamp(sourceRatio * 100)
  const docsScore = (hasDocs ? 40 : 0) + (hasTests ? 40 : 0) + (hasManifest ? 20 : 0)

  const score = Math.round(fileScore * 0.25 + sizeScore * 0.3 + ratioScore * 0.15 + docsScore * 0.3)

  const detail = `${files.length} file(s), ${formatBytes(totalBytes)} total (${formatBytes(effBytes)} effective source)`

  return {
    score: clamp(score),
    detail,
    signals: {
      fileCount: files.length,
      totalBytes,
      effectiveSourceBytes: Math.round(effBytes),
      sourceFiles: sourceFiles.length,
      hasTests,
      hasDocs,
      hasManifest,
      largest,
      extensions,
    },
  }
}

function clamp(n) {
  return Math.max(0, Math.min(100, n))
}
