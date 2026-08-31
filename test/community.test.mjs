import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createFsShim, absolute } from './helpers/fs-shim.mjs'
import { evaluatePlugin } from '../lib/engine/index.js'

// A mock `web` service that returns canned GitHub + npm JSON, shaped like the
// real DSH `web` Service Definition: fetch(request, signal) -> { body }.
function createWebShim(overrides = {}) {
  return {
    async fetch(req) {
      const url = req.url ?? ''
      if (url.includes('api.github.com/repos/')) {
        if (url.includes('/releases')) {
          return { url, statusCode: 200, body: { kind: 'text', content: JSON.stringify(overrides.releases ?? [{ tag_name: 'v1.2.3', published_at: '2024-01-15T00:00:00Z' }]) } }
        }
        return {
          url,
          statusCode: 200,
          body: {
            kind: 'text',
            content: JSON.stringify(
              overrides.repo ?? {
                full_name: 'demo/good-plugin',
                stargazers_count: 120,
                forks_count: 30,
                open_issues_count: 5,
                archived: false,
                pushed_at: new Date(Date.now() - 10 * 86400000).toISOString(),
                license: { spdx_id: 'MIT' },
              },
            ),
          },
        }
      }
      if (url.includes('registry.npmjs.org/')) {
        return {
          url,
          statusCode: 200,
          body: {
            kind: 'text',
            content: JSON.stringify(
              overrides.npm ?? {
                name: 'demo-good-plugin',
                'dist-tags': { latest: '1.2.3' },
                time: { modified: '2024-01-20T00:00:00Z' },
                versions: { '1.0.0': {}, '1.2.3': {} },
                maintainers: [{ name: 'demo' }],
              },
            ),
          },
        }
      }
      if (url.includes('api.npmjs.org/downloads/')) {
        return { url, statusCode: 200, body: { kind: 'text', content: JSON.stringify({ downloads: 4800 }) } }
      }
      throw new Error(`unexpected url ${url}`)
    },
  }
}

test('community dimension aggregates GitHub and npm metadata over the web service', async () => {
  const root = absolute('good-plugin')
  const fs = createFsShim(root)
  const web = createWebShim()
  const r = await evaluatePlugin({
    target: root,
    deps: { fs, web },
    runtime: { nodeVersion: '22.0.0', dshVersion: '0.1.0' },
    opts: { allowNetwork: true },
  })

  assert.equal(r.community.available, true)
  assert.equal(r.community.fetched, true)
  assert.equal(r.community.github.ok, true)
  assert.equal(r.community.github.raw.stargazers_count, 120)
  assert.equal(r.community.npm.ok, true)
  assert.equal(r.community.npm.downloadsLastMonth, 4800)
  assert.equal(typeof r.community.score, 'number')
  assert.ok(r.community.score >= 0 && r.community.score <= 100)
  // network enabled => community participates in the composite
  assert.ok(!r.composite.missing.includes('community'))
  assert.ok(r.report.includes('Community'))
})

test('plugin_eval result stays small and readable', async () => {
  const root = absolute('good-plugin')
  const r = await evaluatePlugin({
    target: root,
    deps: { fs: createFsShim(root), web: createWebShim() },
    runtime: { nodeVersion: '22.0.0' },
    opts: { allowNetwork: true },
  })
  // The model-facing shape keeps only the essentials
  assert.equal(r.schema, 1)
  assert.equal(typeof r.composite.score, 'number')
  assert.ok(r.report.length > 100)
  assert.ok(r.report.length < 6000)
})
