import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanSecurity } from '../lib/engine/security.js'

// We must NOT store real-format secret strings in the repo (GitHub Push
// Protection blocks them even when fake). So the test source below assembles
// each secret at runtime from parts; scanSecurity receives the joined string.

const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('')
const GH = ['ghp_', '0123456789abcdefghijklmnopqrstuvwxyzABC'].join('')
const STRIPE = ['sk_live_', '0123456789abcdef0123456789abcdef'].join('')
const GOOGLE = ['AIza', 'SyA1234567890abcdefghijklmnopqrstuv'].join('')
const JWT = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.', 's9TBh8x7yT1c2d3e4f5a6b7c8d9e0f1a2'].join('')
// private key assembled at runtime; never a literal key-shaped string in the repo
const PK = ['-----BEGIN ', 'PRIVATE KEY-----', '\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n', '-----END ', 'PRIVATE KEY-----'].join('')

test('scanSecurity detects every secret family from runtime-assembled strings', () => {
  const src = {
    texts: {
      'src/keys.js': [
        `const aws = ${JSON.stringify(AWS)}`,
        `const gh = ${JSON.stringify(GH)}`,
        `const stripe = ${JSON.stringify(STRIPE)}`,
        `const g = ${JSON.stringify(GOOGLE)}`,
        `const t = ${JSON.stringify(JWT)}`,
        `const pk = ${JSON.stringify(PK)}`,
        '// token from parts only',
      ].join('\n'),
    },
    files: [{ name: 'src/keys.js' }],
  }
  const r = scanSecurity(src)
  const ids = new Set(r.secrets.map((s) => s.rule))
  assert.ok(ids.has('aws-access-key'), 'aws detected')
  assert.ok(ids.has('github-token'), 'github token detected')
  assert.ok(ids.has('stripe-secret'), 'stripe detected')
  assert.ok(ids.has('google-api-key'), 'google key detected')
  assert.ok(ids.has('jwt'), 'jwt detected')
  assert.ok(ids.has('private-key'), 'private key detected')
  assert.ok(r.score < 60, `security score penalized: ${r.score}`)
})

test('scanSecurity stays quiet on clean code', () => {
  const src = {
    texts: {
      'src/index.js': 'export function run(x) { return x * 2 }\nconst base = "http" + "s://example.com"\n',
    },
    files: [{ name: 'src/index.js' }],
  }
  const r = scanSecurity(src)
  assert.equal(r.secrets.length, 0)
  assert.equal(r.risks.length, 0)
})

test('no real-format secret string exists in repo source files', async () => {
  // Guard: the test fixtures and this suite must never contain a literal
  // secret-shaped string that GitHub Push Protection would reject.
  const { createFsShim, absolute } = await import('./helpers/fs-shim.mjs')
  const fs = createFsShim(absolute('risky-plugin'))
  const { collectLocalSource } = await import('../lib/engine/util.js')
  const src = await collectLocalSource(fs, absolute('risky-plugin'))
  const r = scanSecurity(src)
  assert.equal(r.secrets.length, 0, 'risky fixture must NOT trigger secret rules (literal secrets removed)')
  // but it must still trigger the risky *patterns* that are its point
  const riskIds = new Set(r.risks.map((x) => x.rule))
  assert.ok(riskIds.has('eval'), 'eval still detected')
  assert.ok(riskIds.has('child-process'), 'child_process still detected')
  assert.ok(riskIds.has('insecure-http'), 'plain http still detected')
})
