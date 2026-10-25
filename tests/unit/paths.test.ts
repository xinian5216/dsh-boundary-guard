import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizePath, isInside, splitAds } from '../../src/boundary/paths.ts'

test('normalizePath resolves relative paths against the base', () => {
  assert.equal(normalizePath('./a/b.ts', '/ws', 'posix'), '/ws/a/b.ts')
  assert.equal(normalizePath('../b.ts', '/ws/sub', 'posix'), '/ws/b.ts')
  assert.equal(normalizePath('/abs/x', '/ws', 'posix'), '/abs/x')
})

test('isInside compares segments, not string prefixes', () => {
  assert.equal(isInside('/ws', '/ws/a/b', 'posix'), true)
  assert.equal(isInside('/ws', '/ws', 'posix'), true)
  assert.equal(isInside('/ws', '/ws-evil/a', 'posix'), false)
  assert.equal(isInside('/ws', '/other', 'posix'), false)
})

test('isInside is case-insensitive on Windows', () => {
  assert.equal(isInside('C:\\WS', 'c:\\ws\\a', 'win32'), true)
  assert.equal(isInside('c:\\ws', 'C:\\WS-EVIL', 'win32'), false)
})

test('splitAds splits Windows alternate data streams', () => {
  assert.deepEqual(splitAds('C:\\dir\\file.txt:zone', 'win32'), { base: 'C:\\dir\\file.txt', stream: 'zone' })
  assert.deepEqual(splitAds('C:\\dir\\file.txt', 'win32'), { base: 'C:\\dir\\file.txt' })
  assert.deepEqual(splitAds('/dir/file.txt', 'posix'), { base: '/dir/file.txt' })
})
