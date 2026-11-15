import assert from 'node:assert/strict'
import test from 'node:test'
import { api } from './api.js'

test('API requests include same-origin credentials and the JSON content type', async (context) => {
  const fetch = context.mock.method(globalThis, 'fetch', async () => new Response('{"ok":true}'))

  assert.deepEqual(await api('/api/admin/session'), { ok: true })
  assert.deepEqual(fetch.mock.calls[0].arguments, [
    '/api/admin/session',
    { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } },
  ])
})

test('API forwards request options without modifying them', async (context) => {
  const fetch = context.mock.method(globalThis, 'fetch', async () => new Response('{}'))
  const options = { method: 'POST', body: '{"name":"example"}', credentials: 'omit' }

  await api('/api/admin/domains', options)

  assert.deepEqual(fetch.mock.calls[0].arguments[1], {
    ...options,
    headers: { 'Content-Type': 'application/json' },
  })
  assert.deepEqual(options, { method: 'POST', body: '{"name":"example"}', credentials: 'omit' })
})

for (const body of ['', 'not JSON']) {
  test(`API returns null for a successful ${body ? 'non-JSON' : 'empty'} response`, async (context) => {
    context.mock.method(globalThis, 'fetch', async () => new Response(body))
    assert.equal(await api('/api/admin/logout'), null)
  })
}

for (const [body, statusText, message] of [
  ['{"error":"duplicate hostname"}', 'Conflict', 'duplicate hostname'],
  ['upstream unavailable', 'Service Unavailable', 'upstream unavailable'],
  ['', 'Unauthorized', 'Unauthorized'],
]) {
  test(`API exposes the response status and message: ${message}`, async (context) => {
    context.mock.method(
      globalThis,
      'fetch',
      async () => new Response(body, { status: 409, statusText }),
    )
    await assert.rejects(api('/api/admin/clients'), (error) => {
      assert.equal(error.status, 409)
      assert.equal(error.message, message)
      return true
    })
  })
}

test('API preserves network failures', async (context) => {
  const failure = new Error('network unavailable')
  context.mock.method(globalThis, 'fetch', async () => {
    throw failure
  })
  await assert.rejects(api('/api/admin/session'), failure)
})
