import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createAppServer } from '../server.js'

test('POST /api/analyze/url returns structured URL analysis', async (context) => {
  const server = createAppServer()
  context.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  const response = await fetch(`http://127.0.0.1:${address.port}/api/analyze/url`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'http://localhost:8080/account/verify-login?next=%2Faccount' }),
  })
  const result = await response.json()

  assert.equal(response.status, 200)
  assert.equal(result.success, true)
  assert.equal(result.url.hostname, 'localhost')
  assert.equal(result.url.port, '8080')
  assert.equal(result.url.path, '/account/verify-login')
  assert.deepEqual(result.url.query, [['next', '/account']])
  assert.equal(result.verdict.label, 'suspicious')
})

test('POST /api/analyze/url validates its request shape', async (context) => {
  const server = createAppServer()
  context.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/analyze/url`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'missing url field' }),
  })
  assert.equal(response.status, 400)
  assert.equal((await response.json()).success, false)
})
