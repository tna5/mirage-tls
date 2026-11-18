'use strict'

const native = require('./native.js')

const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304])

function toPairs(headers) {
  if (!headers) return []
  if (typeof Headers !== 'undefined' && headers instanceof Headers) return [...headers.entries()]
  if (Array.isArray(headers)) return headers.map(([k, v]) => [String(k), String(v)])
  if (typeof headers[Symbol.iterator] === 'function') return [...headers].map(([k, v]) => [String(k), String(v)])
  const out = []
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || v === null) continue
    if (Array.isArray(v)) v.forEach((x) => out.push([k, String(x)]))
    else out.push([k, String(v)])
  }
  return out
}

function hasHeader(pairs, name) {
  const n = name.toLowerCase()
  return pairs.some(([k]) => k.toLowerCase() === n)
}

/** Serialize any fetch() BodyInit (string, Buffer, Blob, FormData, URLSearchParams, stream...). */
async function encodeBody(body, pairs) {
  if (body === undefined || body === null) return undefined
  if (typeof body === 'string') return Buffer.from(body)
  if (Buffer.isBuffer(body)) return body
  if (body instanceof ArrayBuffer) return Buffer.from(body)
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength)
  // Let the platform serialize it and pick the content-type (multipart boundary, etc.).
  const r = new Response(body)
  const type = r.headers.get('content-type')
  if (type && !hasHeader(pairs, 'content-type')) pairs.push(['content-type', type])
  return Buffer.from(await r.arrayBuffer())
}

function abortError(signal) {
  if (signal.reason !== undefined) return signal.reason
  const e = new Error('This operation was aborted')
  e.name = 'AbortError'
  return e
}

function buildResponse(res, method) {
  const headers = new Headers()
  for (const [k, v] of res.headers) {
    try {
      headers.append(k, v)
    } catch {
      /* invalid header value from server: skip */
    }
  }
  const nullBody = NULL_BODY_STATUS.has(res.status) || method === 'HEAD'
  const status = res.status >= 200 && res.status <= 599 ? res.status : 200
  const response = new Response(nullBody ? null : res.body, {
    status,
    statusText: res.statusText,
    headers,
  })
  Object.defineProperties(response, {
    url: { value: res.url, enumerable: true },
    redirected: { value: res.redirected, enumerable: true },
    httpVersion: { value: res.version, enumerable: true },
  })
  return response
}

/** `browser` + `os` → built-in profile name ("chrome" + "windows" → "chrome_windows"). */
function withOs({ browser, os, profile }) {
  if (os === undefined || os === null || os === '') return browser
  if (typeof os !== 'string' || !/^[a-z]+$/i.test(os)) throw new TypeError(`invalid os: ${os}`)
  if (profile !== undefined) throw new TypeError('`os` applies to a built-in `browser`, not to a custom `profile`')
  // The engine validates the result (unknown platform for the family, two platforms...).
  return `${browser || 'chrome'}_${os.toLowerCase()}`
}

class Session {
  /**
   * @param {import('./index').SessionOptions} [options]
   */
  constructor(options = {}) {
    const profile =
      options.profile && typeof options.profile === 'object' ? JSON.stringify(options.profile) : options.profile
    this._native = new native.NativeSession({
      browser: withOs(options),
      profile,
      proxy: options.proxy,
      insecure: options.insecure,
      ca: options.ca,
      timeout: options.timeout,
      connectTimeout: options.connectTimeout,
      redirect: options.redirect,
      maxRedirects: options.maxRedirects,
      cookies: options.cookies,
      http1Only: options.http1Only,
      defaultHeaders: options.defaultHeaders,
      headers: toPairs(options.headers),
    })
  }

  /**
   * Same signature as the global fetch(), returns a standard Response.
   * @param {string | URL | Request} input
   * @param {import('./index').RequestInit} [init]
   */
  async fetch(input, init = {}) {
    let url
    let method = init.method
    let headers = toPairs(init.headers)
    let body = init.body
    if (typeof Request !== 'undefined' && input instanceof Request) {
      url = input.url
      method = method || input.method
      if (!init.headers) headers = toPairs(input.headers)
      if (body === undefined && input.body) body = await input.arrayBuffer()
    } else {
      url = String(input)
    }
    method = (method || 'GET').toUpperCase()
    if (init.json !== undefined) {
      body = JSON.stringify(init.json)
      if (!hasHeader(headers, 'content-type')) headers.push(['content-type', 'application/json'])
    }

    const signal = init.signal
    if (signal && signal.aborted) throw abortError(signal)

    const request = this._native.request({
      url,
      method,
      headers,
      body: await encodeBody(body, headers),
      timeout: init.timeout,
      redirect: init.redirect === 'error' ? 'manual' : init.redirect,
      defaultHeaders: init.defaultHeaders,
    })

    let res
    if (signal) {
      let onAbort
      const aborted = new Promise((_, reject) => {
        onAbort = () => reject(abortError(signal))
        signal.addEventListener('abort', onAbort, { once: true })
      })
      try {
        res = await Promise.race([request, aborted])
      } finally {
        signal.removeEventListener('abort', onAbort)
      }
    } else {
      res = await request
    }

    if (init.redirect === 'error' && res.status >= 300 && res.status < 400 && res.headers.some(([k]) => k.toLowerCase() === 'location')) {
      throw new TypeError(`redirect mode is "error" but the server redirected (${res.status})`)
    }
    return buildResponse(res, method)
  }

  /** Cookies that would be sent to `url`, as { name: value }. */
  getCookies(url) {
    return Object.fromEntries(this._native.getCookies(String(url)))
  }

  /** Store a cookie using Set-Cookie syntax, e.g. "sid=abc; Path=/; Secure". */
  setCookie(url, cookie) {
    this._native.setCookie(String(url), cookie)
  }

  clearCookies() {
    this._native.clearCookies()
  }

  /** The resolved fingerprint profile. */
  get profile() {
    return JSON.parse(this._native.profile)
  }

  /** Close idle pooled connections. */
  close() {
    this._native.close()
  }
}

const SESSION_KEYS = [
  'browser', 'os', 'profile', 'proxy', 'insecure', 'ca', 'connectTimeout', 'maxRedirects', 'http1Only',
]
const sessions = new Map()

/**
 * One-shot fetch with a browser fingerprint. Sessions (and connections) are reused per
 * configuration; no cookie jar is kept, like the standard fetch().
 */
function fetch(input, init = {}) {
  const sessionOpts = { cookies: false }
  for (const k of SESSION_KEYS) if (init[k] !== undefined) sessionOpts[k] = init[k]
  const key = JSON.stringify(sessionOpts)
  let s = sessions.get(key)
  if (!s) {
    s = new Session(sessionOpts)
    sessions.set(key, s)
  }
  return s.fetch(input, init)
}

/** Built-in browser families: name, default version, supported versions and platforms. */
function profiles() {
  return JSON.parse(native.listProfiles())
}

/** Full fingerprint definition for a profile name, e.g. "chrome_157_windows". */
function resolveProfile(name) {
  return JSON.parse(native.resolveProfile(name))
}

module.exports = { fetch, Session, profiles, resolveProfile }
module.exports.default = module.exports
