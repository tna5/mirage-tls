# Contributing

Issues and pull requests are welcome.

## Building

Requirements: Rust (stable), Node.js >= 18, CMake, Clang / libclang (used by
bindgen), git. BoringSSL is built from source by the vendored `boring-sys2`
crate (`vendor/boring-sys2`), which applies its patches with `git apply`.
Go, Perl and NASM are not needed.

```bash
cargo test -p mirage-core
cd crates/mirage-napi && npm install && npm run build && npm test
```

Network tests (against tls.peet.ws and similar) only run with
`MIRAGE_ONLINE_TESTS=1`.

## Adding / verifying a browser profile

Profiles are TOML files in [`profiles/`](profiles), one per browser family
(`chrome.toml`, `firefox.toml`, ...), with a `[meta]` table, `[tls]`,
`[http2]` and `[headers]` sections and `[platforms.<name>]` overlays. They are
embedded into the binary at compile time, so rebuild after editing.

1. **Capture the real browser.** Open <https://tls.peet.ws/api/all> in the
   exact browser, version and OS you want to reproduce (no extensions, no
   proxy) and save the JSON.
2. **Capture mirage-tls** with the same profile name:
   ```bash
   cargo run -p mirage-core --example fetch -- chrome_157 https://tls.peet.ws/api/all
   ```
3. **Compare the hashes**, not only the raw lists:
   - `tls.ja4` (and `tls.ja3_hash`; JA3 changes on every connection when
     extension permutation is on, which is expected for Chrome)
   - `tls.peetprint_hash`
   - `http2.akamai_fingerprint` and `http2.akamai_fingerprint_hash`
   - header order and values (`user_agent`, `sec-ch-ua*`, `accept*`)
4. If anything differs, fix the TOML (cipher / curve / extension / sigalg
   order, HTTP/2 SETTINGS, WINDOW_UPDATE, priority, pseudo-header order, header
   order) and repeat.
5. When all hashes match, set `verified = true` in `[meta]` and record what
   was checked and when in `notes` (browser version, OS, capture date). Mention
   the browser build in the pull request and attach both JSON captures if you
   can (strip any personal data such as IP addresses).

Profiles that were not compared against a real capture must keep
`verified = false`.

## Releasing

Maintainers: bump `version` in `crates/mirage-napi/package.json` with
`npm version <x.y.z> --no-git-tag-version` (the `version` script runs
`napi version` to update `npm/*/package.json`), update `CHANGELOG.md`, commit,
then push a tag `v<x.y.z>`. The `Release` workflow builds every target and
publishes to npm.
