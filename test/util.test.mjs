import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseVersion, satisfiesRange, isPinned, isFloating } from '../lib/engine/util.js'

test('parseVersion parses strict semver and rejects garbage', () => {
  assert.deepEqual(parseVersion('1.2.3'), [1, 2, 3])
  assert.deepEqual(parseVersion('v2.0.0'), [2, 0, 0])
  assert.deepEqual(parseVersion('1.2.3-beta.1'), [1, 2, 3])
  assert.equal(parseVersion('1.2'), null)
  assert.equal(parseVersion('abc'), null)
  assert.equal(parseVersion(undefined), null)
})

test('satisfiesRange handles common operators', () => {
  assert.equal(satisfiesRange('18.0.0', '>=18.0.0'), true)
  assert.equal(satisfiesRange('16.0.0', '>=18.0.0'), false)
  assert.equal(satisfiesRange('18.5.0', '^18.0.0'), true)
  assert.equal(satisfiesRange('19.0.0', '^18.0.0'), false)
  assert.equal(satisfiesRange('18.5.1', '~18.5.0'), true)
  assert.equal(satisfiesRange('18.6.0', '~18.5.0'), false)
  assert.equal(satisfiesRange('18.5.1', '18.x'), true)
  assert.equal(satisfiesRange('19.0.0', '18.x'), false)
  assert.equal(satisfiesRange('18.0.0', '*'), true)
  assert.equal(satisfiesRange('18.0.0', ''), true)
  // OR groups
  assert.equal(satisfiesRange('14.0.0', '>=16 || >=12 && <15'), true)
  // unparseable
  assert.equal(satisfiesRange('18.0.0', 'latest'), null)
})

test('isPinned / isFloating classify dependency specs', () => {
  assert.equal(isPinned('4.17.21'), true)
  assert.equal(isPinned('^4.17.21'), false)
  assert.equal(isPinned('~4.17.21'), false)
  assert.equal(isFloating('^1.3.0'), true)
  assert.equal(isFloating('*'), true)
  assert.equal(isFloating('latest'), true)
  assert.equal(isFloating('file:../local'), true)
  assert.equal(isFloating('github:foo/bar'), true)
  assert.equal(isFloating('4.17.21'), false)
})
