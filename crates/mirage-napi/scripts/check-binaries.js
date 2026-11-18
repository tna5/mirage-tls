// prepublishOnly: mirage-tls ships every prebuilt binary in the one package, and
// native.js loads ./mirage-tls.<platform>.node for the current OS / arch. Refuse to
// publish if one is missing (e.g. a CI target failed), so no platform breaks at runtime.
const fs = require('fs')
const path = require('path')
const pkg = require('../package.json')

const expected = pkg.files.filter(f => f.endsWith('.node'))
const missing = expected.filter(f => !fs.existsSync(path.join(__dirname, '..', f)))
if (missing.length) {
  console.error(`missing prebuilt binaries: ${missing.join(', ')}`)
  process.exit(1)
}
for (const f of expected) {
  const size = fs.statSync(path.join(__dirname, '..', f)).size
  console.log(`${f}  ${(size / 1048576).toFixed(1)} MB`)
}
