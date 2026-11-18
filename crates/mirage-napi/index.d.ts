/**
 * Built-in profile name: `<family>[_<version>][_<platform>]`.
 * Families: chrome, edge, firefox, safari, safari_ios, okhttp.
 * Examples: "chrome", "chrome_157", "chrome_157_windows", "chrome_android",
 * "edge_157", "firefox_158_linux", "safari_26", "safari_ios_26_ipad", "okhttp_4".
 */
export type BrowserProfile =
  | 'chrome'
  | 'edge'
  | 'firefox'
  | 'safari'
  | 'safari_ios'
  | 'okhttp'
  | (string & {})

/**
 * Operating system the browser profile runs on (User-Agent, sec-ch-ua-platform...).
 * chrome: macos (default), windows, linux, android. edge: windows (default), macos.
 * firefox: macos (default), windows, linux, android. safari_ios: iphone (default), ipad.
 */
export type BrowserOs = 'windows' | 'macos' | 'linux' | 'android' | 'iphone' | 'ipad' | (string & {})

export type HeadersLike = Headers | Record<string, string | string[] | undefined> | Array<[string, string]>

export interface SessionOptions {
  /** Built-in profile, default "chrome" (latest). */
  browser?: BrowserProfile
  /** OS of the browser, e.g. `{ browser: 'chrome', os: 'windows' }` (= "chrome_windows"). */
  os?: BrowserOs
  /** Custom profile object/JSON. Use `extends: "<builtin>"` to override only some fields. */
  profile?: CustomProfile | string
  /** http://user:pass@host:port, socks5://host:port, socks5h://host:port */
  proxy?: string
  /** Skip TLS certificate verification. */
  insecure?: boolean
  /** Extra trusted CA certificates (PEM). */
  ca?: string
  /** Request timeout in ms (0 disables). Default 30000. */
  timeout?: number
  /** Connect timeout in ms (0 disables). Default 10000. */
  connectTimeout?: number
  /** Default "follow". */
  redirect?: 'follow' | 'manual'
  /** Default 20. */
  maxRedirects?: number
  /** Keep a cookie jar. Default true for Session, false for the top-level fetch(). */
  cookies?: boolean
  /** Only offer http/1.1 via ALPN. */
  http1Only?: boolean
  /** Send the browser's default navigation headers. Default true. */
  defaultHeaders?: boolean
  /** Headers added to every request (they override the browser defaults). */
  headers?: HeadersLike
}

export interface RequestInit {
  method?: string
  headers?: HeadersLike
  body?: string | ArrayBuffer | ArrayBufferView | Blob | FormData | URLSearchParams | ReadableStream | null
  /** Shortcut: JSON.stringify + content-type: application/json. */
  json?: unknown
  redirect?: 'follow' | 'manual' | 'error'
  signal?: AbortSignal
  /** Per-request timeout in ms. */
  timeout?: number
  /** Send the browser's default headers for this request. */
  defaultHeaders?: boolean
}

export interface FetchInit extends RequestInit, Omit<SessionOptions, 'headers' | 'redirect' | 'timeout' | 'cookies' | 'defaultHeaders'> {}

export interface MirageResponse extends Response {
  /** "HTTP/2" | "HTTP/1.1" | "HTTP/1.0" */
  readonly httpVersion: string
}

export declare class Session {
  constructor(options?: SessionOptions)
  fetch(input: string | URL | Request, init?: RequestInit): Promise<MirageResponse>
  getCookies(url: string | URL): Record<string, string>
  setCookie(url: string | URL, cookie: string): void
  clearCookies(): void
  readonly profile: ResolvedProfile
  close(): void
}

export declare function fetch(input: string | URL | Request, init?: FetchInit): Promise<MirageResponse>

export interface FamilyInfo {
  family: string
  default_major: number
  min_major: number
  max_major: number
  default_platform: string
  platforms: string[]
  verified: boolean
}

export declare function profiles(): FamilyInfo[]
export declare function resolveProfile(name: BrowserProfile): ResolvedProfile

export interface Priority {
  weight: number
  depends_on?: number
  exclusive?: boolean
}

export interface ResolvedProfile {
  name: string
  tls: {
    min_version: string
    max_version: string
    ciphers: string[]
    curves: string[]
    sigalgs: string[]
    alpn: string[]
    alps: string[]
    alps_new_codepoint: boolean
    grease: boolean
    permute_extensions: boolean
    extension_order?: string[] | null
    ech_grease: boolean
    cert_compression: Array<'brotli' | 'zlib' | 'zstd'>
    ocsp_stapling: boolean
    signed_cert_timestamps: boolean
    session_ticket: boolean
    resumption: boolean
    record_size_limit?: number | null
    delegated_credentials?: string[] | null
    key_shares_limit?: number | null
    aes_hw_override?: boolean | null
  }
  http2: {
    settings: Array<[number, number]>
    window_update: number
    pseudo_header_order: string[]
    headers_priority?: Priority | null
    priority_frames: Array<Priority & { stream_id: number }>
    initial_stream_id?: number | null
  }
  headers: {
    default: Array<[string, string]>
    order: string[]
    h1_case: string[]
  }
  meta: { family: string; major: number; platform: string; verified: boolean; notes: string }
}

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] }

export type CustomProfile = DeepPartial<ResolvedProfile> & { extends?: BrowserProfile }
