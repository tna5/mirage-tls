# Security policy

## Supported versions

Only the latest released version of `mirage-tls` receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately
through GitHub's "Report a vulnerability" button (Security tab → Advisories)
on the repository. Include a description, the affected version and a way to
reproduce it. You should get an answer within a few days.

Issues in BoringSSL itself should be reported upstream
(<https://boringssl.googlesource.com/boringssl>); we will update the vendored
copy once a fix is available.

## Scope notes

mirage-tls imitates browser fingerprints; it does not make traffic anonymous.
`insecure: true` disables certificate verification and must not be used in
production.
