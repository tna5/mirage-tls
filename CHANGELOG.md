# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2]

### Fixed

- README banner on npmjs.com (404): the banner now ships in the package and the
  published README loads it from jsDelivr.

### Added

- The package is also published to GitHub Packages as `@tna5/mirage-tls`.

## [0.1.1]

First single-package release (0.1.0 was published as one npm package per platform).

### Added

- `os` option for `fetch()` and `Session` (`{ browser: 'chrome', os: 'windows' }`),
  equivalent to the `<family>_<platform>` profile name.
- `Client::request_stream` in `mirage-core`: streaming, decoded response bodies.

### Changed

- One npm package: `mirage-tls` ships every prebuilt binary and loads the one for
  the current OS / architecture (no more `mirage-tls-<platform>` packages).
- Linux binaries are built without debug info (~6 MB instead of ~41 MB).

## [0.1.0]

First public release.

### Added

- `fetch()` and `Session` for Node.js (>= 18) and Bun, through a napi-rs native
  addon; prebuilt binaries for macOS (arm64, x64), Linux glibc (x64, arm64) and
  Windows (x64, MSVC).
- Rust engine (`mirage-core`) on BoringSSL with the boring2 patches plus
  `mirage.patch` (GREASE / ML-DSA in `signature_algorithms`, `trust_anchors`
  extension), reproducing the TLS ClientHello (JA3 / JA4), HTTP/2 connection
  (Akamai fingerprint) and header order of the selected browser.
- Browser profiles as TOML files in `profiles/`: Chrome, Edge, Firefox, Safari,
  Safari iOS, OkHttp. Custom profiles as JSON, optionally extending a built-in.
- Sessions with cookies and connection reuse; HTTP, SOCKS5 and SOCKS5h proxies
  with credentials; redirects, timeouts, custom CA, HTTP/1.1-only mode.

### Known limitations

- Only the Chrome 157 macOS profile has been verified against a real browser
  capture; the other profiles are unverified.
- Response bodies are buffered (no streaming yet). No WebSocket, no HTTP/3.

[Unreleased]: https://github.com/tna5/mirage-tls/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/tna5/mirage-tls/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tna5/mirage-tls/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tna5/mirage-tls/releases/tag/v0.1.0
