// Version compatibility verification for dsh-plugin-eval.
//
// Checks the target plugin's declared compatibility surface against the
// runtime it is about to run on: Node engine range, peerDependencies on DSH
// packages, manifest identity, and dependency pinning.

import { parseVersion, satisfiesRange } from './util.js'

const DSH_PEER_PREFIXES = ['@deepseek-ai/']

/**
 * @param {object|undefined} manifest parsed package.json
 * @param {{ nodeVersion?: string, dshVersion?: string }} runtime
 */
export function checkCompatibility(manifest, runtime = {}) {
  const findings = []
  const checks = {}

  if (!manifest) {
    return {
      compatible: false,
      score: 0,
      detail: 'no manifest to verify',
      checks: { hasManifest: false },
      findings: [{ severity: 'high', label: 'No manifest — cannot verify version compatibility', reason: 'engines, peerDependencies and identity are all unknown' }],
    }
  }

  checks.hasManifest = true
  checks.manifestVersion = manifest.version ?? null

  // --- engines.node ---
  const enginesNode = manifest.engines?.node
  if (enginesNode) {
    const nodeOk = satisfiesRange(runtime.nodeVersion ?? process?.versions?.node, enginesNode)
    checks.enginesNode = { range: enginesNode, runtime: runtime.nodeVersion ?? process?.versions?.node ?? null, ok: nodeOk }
    if (nodeOk === false) {
      findings.push({
        severity: 'high',
        label: `Node engine mismatch: requires "${enginesNode}", runtime is ${runtime.nodeVersion ?? 'unknown'}`,
        reason: 'the plugin declares a Node range the current runtime does not satisfy',
      })
    } else if (nodeOk === null) {
      findings.push({
        severity: 'low',
        label: `Unparseable Node engine range "${enginesNode}"`,
        reason: 'we could not verify the range against the runtime',
      })
    }
  } else {
    checks.enginesNode = { range: null, runtime: runtime.nodeVersion ?? process?.versions?.node ?? null, ok: null }
  }

  // --- peerDependencies on DSH packages ---
  const dshPeers = Object.entries(manifest.peerDependencies ?? {}).filter(([name]) =>
    DSH_PEER_PREFIXES.some((p) => name.startsWith(p)),
  )
  checks.dshPeers = dshPeers.map(([name, range]) => ({ name, range }))
  if (dshPeers.length === 0) {
    checks.dshPeersDeclared = false
  } else {
    checks.dshPeersDeclared = true
    const dshVersion = runtime.dshVersion
    for (const [name, range] of dshPeers) {
      if (!dshVersion) {
        findings.push({
          severity: 'low',
          label: `Cannot verify DSH peer "${name}@${range}" — current DSH version unknown`,
          reason: 'install it and re-run to confirm the peer range is satisfied',
        })
        continue
      }
      const ok = satisfiesRange(dshVersion, range)
      if (ok === false) {
        findings.push({
          severity: 'high',
          label: `DSH peer mismatch: "${name}" requires "${range}", current DSH is ${dshVersion}`,
          reason: 'the plugin declares a DSH package version the running DSH does not provide',
        })
      }
    }
  }

  // --- identity sanity ---
  if (!manifest.name || !/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(manifest.name)) {
    findings.push({ severity: 'low', label: 'Invalid or missing package name', reason: 'cannot reliably identify the plugin' })
  }
  if (!parseVersion(manifest.version)) {
    findings.push({ severity: 'low', label: `Invalid package version "${manifest.version}"`, reason: 'version cannot be compared or tracked' })
  }

  // --- dependencies pinned enough to be compatible across installs ---
  const allDeps = { ...manifest.dependencies, ...manifest.peerDependencies, ...manifest.optionalDependencies }
  const specs = Object.values(allDeps).filter((s) => typeof s === 'string')
  const pinned = specs.filter((s) => /^\s*\d+\.\d+\.\d+\s*$/.test(s))
  const ratio = specs.length === 0 ? 1 : pinned.length / specs.length
  checks.dependencyPinRatio = Number(ratio.toFixed(2))
  if (ratio < 0.5 && specs.length > 0) {
    findings.push({
      severity: 'medium',
      label: 'Less than half of dependencies are pinned to exact versions',
      reason: 'unpinned ranges can resolve differently on the target machine and break compatibility later',
    })
  }

  const severityWeight = { high: 30, medium: 12, low: 4 }
  const penalty = findings.reduce((a, f) => a + (severityWeight[f.severity] ?? 5), 0)
  const score = Math.max(0, Math.min(100, 100 - penalty))
  const compatible = !findings.some((f) => f.severity === 'high')

  return {
    compatible,
    score,
    detail: compatible
      ? 'compatibility surface verified: no blocking mismatches'
      : `compatibility issues found (${findings.length})`,
    checks,
    findings,
  }
}
