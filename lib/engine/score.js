// Composite reliability scoring for dsh-plugin-eval.
//
// Mirrors the npm-audit + Lighthouse mental model: several weighted category
// scores combine into one 0..100 reliability score, plus a letter grade and an
// install verdict. Categories that produced no data (e.g. community when the
// network is off) are dropped and the weights renormalize, exactly like
// Lighthouse missing a category.

export const CATEGORIES = [
  { key: 'security', label: 'Security', weight: 0.4 },
  { key: 'compatibility', label: 'Compatibility', weight: 0.25 },
  { key: 'performance', label: 'Footprint / Performance', weight: 0.15 },
  { key: 'community', label: 'Community', weight: 0.1 },
  { key: 'documentation', label: 'Documentation & Quality', weight: 0.1 },
]

/**
 * @param {Record<string, number>} scores key -> 0..100
 * @param {{ categoryWeights?: Array<{key:string,weight:number}> }} [opts]
 */
export function computeComposite(scores, opts = {}) {
  const categories = opts.categoryWeights ?? CATEGORIES
  const available = categories.filter((c) => Number.isFinite(scores[c.key]))
  const totalWeight = available.reduce((a, c) => a + c.weight, 0)
  if (totalWeight <= 0) {
    return { score: 0, grade: 'F', verdict: 'blocked', detail: 'no evaluable dimensions', categories: [] }
  }

  const weighted = available.reduce((a, c) => a + (scores[c.key] ?? 0) * c.weight, 0)
  const score = Math.round((weighted / totalWeight) * 10) / 10

  return {
    score,
    grade: gradeOf(score),
    verdict: verdictOf(score, scores),
    detail: `composite reliability ${score}/100 from ${available.length} dimension(s)`,
    categories: available.map((c) => ({
      key: c.key,
      label: c.label,
      weight: c.weight,
      normalizedWeight: Number((c.weight / totalWeight).toFixed(3)),
      score: scores[c.key],
    })),
    missing: categories.filter((c) => !Number.isFinite(scores[c.key])).map((c) => c.key),
  }
}

export function gradeOf(score) {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

export function verdictOf(score, scores) {
  // Security dominates the verdict: a bad security score blocks the install
  // even if everything else is green — this is the "npm audit" behaviour.
  if (Number.isFinite(scores.security) && scores.security < 40) return 'blocked'
  if (Number.isFinite(scores.security) && scores.security < 60) return 'caution'
  if (score >= 75) return 'recommended'
  if (score >= 60) return 'acceptable'
  if (score >= 40) return 'caution'
  return 'blocked'
}

/**
 * @param {Array<{severity:string,label:string,reason:string}>} findings
 */
export function summarizeFindings(findings) {
  const bySeverity = {}
  for (const f of findings ?? []) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
  }
  return {
    total: (findings ?? []).length,
    bySeverity,
    top: [...(findings ?? [])]
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      .slice(0, 8),
  }
}

function severityRank(s) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] ?? 0
}
