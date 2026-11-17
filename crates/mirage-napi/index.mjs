import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const mirage = require('./index.js')

export const { fetch, Session, profiles, resolveProfile } = mirage
export default mirage
