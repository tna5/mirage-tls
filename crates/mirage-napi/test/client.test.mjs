// Offline tests against a local HTTP/1.1 server (runs under `node --test` and `bun test`).
// test/peet.mjs is a manual smoke test against real endpoints and is not run in CI.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import zlib from 'node:zlib'
import { fetch, Session, profiles } from '../index.mjs'

let server
let base
const sockets = new Set()

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x')
    switch (url.pathname) {
      case '/gzip': {
        res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' })
        res.end(zlib.gzipSync('hello '.repeat(1000)))
        break
      }
      case '/redirect':
        res.writeHead(302, { location: '/final', 'set-cookie': 'sid=abc; Path=/' })
        res.end('moved')
        break
      case '/final':
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ cookie: req.headers.cookie ?? null }))
        break
      case '/echo': {
        const chunks = []
        req.on('data', c => chunks.push(c))
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ method: req.method, body: Buffer.concat(chunks).toString(), ua: req.headers['user-agent'] }))
        })
        break
      }
      case '/chunked':
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.write('a'.repeat(10))
        setTimeout(() => res.end('b'.repeat(10)), 20)
        break
      case '/slow':
        setTimeout(() => res.end('late'), 2000)
        break
      default:
        res.writeHead(404)
        res.end()
    }
  })
  server.on('connection', s => sockets.add(s))
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => {
  for (const s of sockets) s.destroy()
  server.close()
})

test('decodes gzip bodies', async () => {
  const res = await fetch(`${base}/gzip`)
  assert.equal(res.status, 200)
  assert.equal(res.httpVersion, 'HTTP/1.1')
  assert.equal(await res.text(), 'hello '.repeat(1000))
})

test('follows redirects and keeps cookies in a session', async () => {
  const s = new Session({ browser: 'chrome' })
  const res = await s.fetch(`${base}/redirect`)
  assert.equal(res.status, 200)
  assert.equal(res.redirected, true)
  assert.equal(res.url, `${base}/final`)
  assert.deepEqual(await res.json(), { cookie: 'sid=abc' })
  assert.equal(s.getCookies(base).sid, 'abc')
  s.close()
})

test('manual redirect mode returns the 3xx', async () => {
  const res = await fetch(`${base}/redirect`, { redirect: 'manual' })
  assert.equal(res.status, 302)
  assert.equal(res.headers.get('location'), '/final')
})

test('sends a POST body and the profile user-agent', async () => {
  const res = await fetch(`${base}/echo`, { method: 'POST', body: 'ping', browser: 'firefox' })
  const d = await res.json()
  assert.equal(d.method, 'POST')
  assert.equal(d.body, 'ping')
  assert.match(d.ua, /Firefox\//)
})

test('reads chunked bodies and reuses keep-alive connections', async () => {
  const s = new Session({ browser: 'chrome' })
  const before = sockets.size
  for (let i = 0; i < 3; i++) {
    const res = await s.fetch(`${base}/chunked`)
    assert.equal(await res.text(), 'a'.repeat(10) + 'b'.repeat(10))
  }
  assert.equal(sockets.size - before, 1, 'all requests should share one connection')
  s.close()
})

test('times out', async () => {
  await assert.rejects(fetch(`${base}/slow`, { timeout: 200 }), /ETIMEDOUT/)
})

test('lists the built-in profile families', () => {
  const families = profiles().map(f => f.family)
  for (const f of ['chrome', 'edge', 'firefox', 'safari', 'safari_ios']) assert.ok(families.includes(f), f)
})
