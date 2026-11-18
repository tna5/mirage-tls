// prepack: copy README.md / LICENSE / THIRD_PARTY_NOTICES.md and the banner from the
// repository root into the package. Relative image paths in the README cannot work on
// npmjs.com (npm rewrites them to the GitHub repository, which is private), so the copied
// README points at the banner shipped in this very package version, served by jsDelivr.
const fs = require('fs')
const path = require('path')

const root = path.join(__dirname, '..', '..', '..')
const pkgDir = path.join(__dirname, '..')
const pkg = require('../package.json')

for (const f of ['LICENSE', 'THIRD_PARTY_NOTICES.md']) {
  fs.copyFileSync(path.join(root, f), path.join(pkgDir, f))
}

fs.mkdirSync(path.join(pkgDir, 'assets'), { recursive: true })
fs.copyFileSync(path.join(root, 'assets', 'banner.svg'), path.join(pkgDir, 'assets', 'banner.svg'))

// jsDelivr only serves packages from npmjs.com, under the unscoped name.
const cdn = `https://cdn.jsdelivr.net/npm/mirage-tls@${pkg.version}/assets/banner.svg`
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8')
const out = readme.replace(/src="assets\/banner\.svg"/g, `src="${cdn}"`)
if (out === readme) {
  console.error('prepack: banner <img src="assets/banner.svg"> not found in README.md')
  process.exit(1)
}
fs.writeFileSync(path.join(pkgDir, 'README.md'), out)
