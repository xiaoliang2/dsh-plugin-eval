import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createFsShim, absolute } from './helpers/fs-shim.mjs'
import { evaluatePlugin } from '../lib/engine/index.js'
import { computeComposite, gradeOf, verdictOf } from '../lib/engine/score.js'

async function evalFixture(name, extra = {}) {
  const fs = createFsShim(absolute(name))
  return evaluatePlugin({
    target: absolute(name),
    deps: { fs, web: undefined },
    runtime: { nodeVersion: '22.0.0', dshVersion: '0.1.0' },
    opts: { allowNetwork: false, ...extra },
  })
}

test('good plugin evaluates to recommended with high security', async () => {
  const r = await evalFixture('good-plugin')
  assert.equal(r.schema, 1)
  assert.equal(r.manifest.name, 'demo-good-plugin')
  assert.ok(r.security.scan.secrets.length === 0, 'no secrets in good plugin')
  assert.ok(r.security.scan.risks.length === 0, 'no risky patterns in good plugin')
  assert.ok(r.security.score >= 80, `security score high: ${r.security.score}`)
  assert.ok(r.composite.score >= 70, `composite high: ${r.composite.score}`)
  assert.ok(['recommended', 'acceptable'].includes(r.composite.verdict))
})

test('risky plugin is flagged with risky patterns, lifecycle scripts, floating deps', async () => {
  const r = await evalFixture('risky-plugin')
  const labels = r.findings.top.map((f) => f.label).join('\n')
  // The fixture intentionally avoids literal secret strings (they would trip
  // GitHub Push Protection on the repo); secret detection is covered by
  // test/security.test.mjs. Here we assert the risky code patterns.
  assert.ok(r.security.scan.risks.some((x) => x.rule === 'eval'), 'eval detected')
  assert.ok(r.security.scan.risks.some((x) => x.rule === 'child-process'), 'child_process detected')
  assert.ok(r.security.scan.risks.some((x) => x.rule === 'insecure-http'), 'plain-http detected')
  assert.ok(r.manifestAudit.findings.some((f) => /postinstall/.test(f.label)), 'postinstall flagged')
  assert.ok(r.compatibility.score < 90, `compatibility penalized: ${r.compatibility.score}`)
  assert.equal(r.composite.verdict, 'blocked')
  assert.ok(labels.length > 0)
})

test('missing network degrades community but keeps composite', async () => {
  const r = await evalFixture('good-plugin')
  assert.equal(r.community.available, false)
  assert.ok(r.composite.missing.includes('community'))
  // weights renormalize so composite is still computed
  assert.equal(typeof r.composite.score, 'number')
})

test('composite scoring drops missing categories and renormalizes', () => {
  const c = computeComposite({ security: 100, compatibility: 100, performance: 100 })
  assert.equal(c.score, 100)
  assert.equal(c.grade, 'A')
  assert.equal(c.verdict, 'recommended')
  assert.ok(c.missing.includes('community'))
})

test('grade and verdict mapping', () => {
  assert.equal(gradeOf(95), 'A')
  assert.equal(gradeOf(80), 'B')
  assert.equal(gradeOf(65), 'C')
  assert.equal(gradeOf(45), 'D')
  assert.equal(gradeOf(20), 'F')
  assert.equal(verdictOf(80, { security: 90 }), 'recommended')
  assert.equal(verdictOf(80, { security: 50 }), 'caution')
  assert.equal(verdictOf(90, { security: 20 }), 'blocked')
})

test('report renders a readable summary', async () => {
  const r = await evalFixture('good-plugin')
  assert.match(r.report, /# Plugin Reliability Report/)
  assert.match(r.report, /Composite:/)
  assert.match(r.report, /not executed/)
})
