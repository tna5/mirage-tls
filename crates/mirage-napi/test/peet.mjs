import { fetch, Session, profiles } from '../index.mjs'

const runtime = typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.version}`
const res = await fetch('https://tls.peet.ws/api/all', { browser: 'chrome_157' })
const d = await res.json()
console.log(runtime, '|', res.httpVersion, res.status)
console.log('ja4      ', d.tls.ja4)
console.log('peetprint', d.tls.peetprint_hash)
console.log('akamai   ', d.http2.akamai_fingerprint, d.http2.akamai_fingerprint_hash)
console.log('ua       ', d.user_agent)

const s = new Session({ browser: 'firefox_windows' })
const r = await s.fetch('https://httpbin.org/cookies/set?x=42')
console.log('session cookies', await r.json(), s.getCookies('https://httpbin.org'))
const p = await s.fetch('https://httpbin.org/post', { method: 'POST', json: { hello: 'mirage' } })
console.log('post', (await p.json()).json)
console.log('families', profiles().map(f => f.family).join(','))
