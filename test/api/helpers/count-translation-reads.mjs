import fs from 'node:fs'

const reads = []
const bodyKind = new Map()
let parses = 0
let directoryLists = 0
let watching = false
let wrapperHits = 0

function asPath (value) {
  if (typeof value === 'string') return value.replace(/\\/g, '/')
  if (value instanceof URL) return value.pathname
  return ''
}

function kindOf (value) {
  const filePath = asPath(value)
  if (!filePath.endsWith('.json')) return null
  if (filePath.includes('frontend/dist/frontend/assets/i18n/')) return 'frontend'
  if (filePath.includes('data/static/i18n/') || filePath.includes('frontend/src/assets/i18n/')) return null
  if (/(^|\/)i18n\/[^/]+\.json$/.test(filePath)) return 'backend'
  return null
}

function noteRead (value, data) {
  const kind = kindOf(value)
  if (!watching || kind === null) return
  reads.push({ kind, file: asPath(value) })
  const text = typeof data === 'string' ? data : Buffer.isBuffer(data) ? data.toString('utf8') : null
  if (text !== null) bodyKind.set(text, kind)
}

const originalParse = JSON.parse
JSON.parse = function (text, reviver) {
  const value = reviver === undefined ? originalParse(text) : originalParse(text, reviver)
  if (watching && typeof text === 'string' && bodyKind.has(text)) parses++
  return value
}

const originalReadFile = fs.promises.readFile
fs.promises.readFile = async function (...args) {
  wrapperHits++
  const data = await originalReadFile.apply(fs.promises, args)
  noteRead(args[0], data)
  return data
}

const originalReadFileSync = fs.readFileSync
fs.readFileSync = function (...args) {
  const data = originalReadFileSync.apply(fs, args)
  noteRead(args[0], data)
  return data
}

const originalCallbackReadFile = fs.readFile
fs.readFile = function (...args) {
  const callback = args[args.length - 1]
  if (typeof callback === 'function') {
    args[args.length - 1] = (err, data) => {
      if (err == null) noteRead(args[0], data)
      callback(err, data)
    }
  }
  return originalCallbackReadFile.apply(fs, args)
}

const originalReaddir = fs.promises.readdir
fs.promises.readdir = async function (...args) {
  const data = await originalReaddir.apply(fs.promises, args)
  if (watching && asPath(args[0]).includes('frontend/dist/frontend/assets/i18n')) directoryLists++
  return data
}

const promises = await import('node:fs/promises')
if (promises.readFile === originalReadFile) {
  throw new Error('node:fs/promises readFile was linked before the wrapper was installed')
}

function snapshot () {
  return {
    frontendReads: reads.filter((entry) => entry.kind === 'frontend').length,
    backendReads: reads.filter((entry) => entry.kind === 'backend').length,
    parses,
    directoryLists,
    wrapperHits
  }
}

function resetCounts () {
  reads.length = 0
  parses = 0
  directoryLists = 0
  bodyKind.clear()
}

globalThis.__translationReadProbe = {
  snapshot,
  resetCounts,
  setWatching (value) { watching = value },
  get wrapperHits () { return wrapperHits }
}
