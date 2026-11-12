#!/usr/bin/env node
// Stand-in for docker-ce 5:20.10.17~3-0~ubuntu-impish (the package
// `apt-get install docker-ce` installs on the Vagrant box). Resolution
// follows the Docker 20.10.17 sources cited on each step. Image bytes
// stand in for registry manifests: sha256(bytes) is the manifest digest
// checked by schema2ManifestDigest.

import { createHash, randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'

const statePath = process.env.DOCKER_STUB_STATE
if (!statePath) {
  process.stderr.write('DOCKER_STUB_STATE is not set\n')
  process.exit(1)
}

const state = JSON.parse(readFileSync(statePath, 'utf8'))

// A later command sees a tag that moved after the previous command returned.
// Local tag refs move too, which is what a pull of that tag would store
// (reference/store.go AddTag). Digest refs are left alone.
if (state.commandCount > 0 && process.env.DOCKER_STUB_RETARGET_TO) {
  const moved = process.env.DOCKER_STUB_RETARGET_TO
  for (const key of Object.keys(state.remoteTags)) {
    if (key.endsWith(':latest')) state.remoteTags[key] = moved
  }
  for (const key of Object.keys(state.local)) {
    if (key.endsWith(':latest')) state.local[key] = moved
  }
}
state.commandCount = (state.commandCount || 0) + 1
writeFileSync(statePath, JSON.stringify(state))

function sha256 (bytes) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

// distribution/reference normalize.go TagNameOnly (v2.8.1): a name with no
// tag and no digest gets the default tag "latest".
function parseRef (input) {
  const at = input.lastIndexOf('@')
  let namePart = input
  let digest = null
  if (at !== -1) {
    namePart = input.slice(0, at)
    digest = input.slice(at + 1)
    if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
      throw new Error('invalid reference format')
    }
  }
  const slash = namePart.lastIndexOf('/')
  const colon = namePart.lastIndexOf(':')
  let name = namePart
  let tag = null
  if (colon > slash) {
    name = namePart.slice(0, colon)
    tag = namePart.slice(colon + 1)
  }
  if (name !== name.toLowerCase() || name.length === 0) {
    throw new Error('invalid reference format')
  }
  if (!digest && !tag) tag = 'latest'
  const familiar = digest ? `${name}@${digest}` : `${name}:${tag}`
  return { name, tag, digest, familiar }
}

function payloadFor (digest) {
  if (process.env.DOCKER_STUB_CORRUPT_DIGEST === digest) return 'corrupted-manifest-bytes'
  if (!Object.prototype.hasOwnProperty.call(state.blobs, digest)) return null
  return state.blobs[digest]
}

// pull_v2.go pullV2Tag + schema2ManifestDigest. A digest ref must match the
// hash of the manifest bytes. A tag ref resolves through the tag service,
// then the manifest digest is the hash of those bytes.
function pull (imageArg) {
  const ref = parseRef(imageArg)
  let digest = ref.digest
  if (!digest) {
    const tagged = `${ref.name}:${ref.tag}`
    digest = state.remoteTags[tagged]
    if (!digest) throw new Error(`manifest for ${tagged} not found`)
  }
  const payload = payloadFor(digest)
  if (payload == null) throw new Error(`manifest unknown: ${digest}`)
  const actual = sha256(payload)
  if (ref.digest) {
    if (actual !== ref.digest) {
      throw new Error(`manifest verification failed for digest ${ref.digest}`)
    }
  }
  const stored = ref.digest ? ref.digest : actual
  state.local[`${ref.name}@${stored}`] = stored
  if (!ref.digest) state.local[`${ref.name}:${ref.tag}`] = stored
  return { ref, digest: stored, payload: state.blobs[stored] }
}

// reference/store.go Get: digest wins over a tag; a name-only ref is stored
// and read as :latest. Missing refs are not found, which is what makes
// `docker run` pull (cli create.go, pull default "missing").
function lookup (imageArg) {
  const ref = parseRef(imageArg)
  const key = ref.digest ? `${ref.name}@${ref.digest}` : `${ref.name}:${ref.tag}`
  const digest = state.local[key]
  if (!digest) return null
  return { ref, digest, payload: state.blobs[digest] }
}

function remember (entry) {
  state.commands.push(entry)
  writeFileSync(statePath, JSON.stringify(state))
}

function fail (error) {
  remember({ argv: process.argv.slice(2), error: error.message })
  process.stderr.write(error.message + '\n')
  process.exit(1)
}

function digestLine (digest, familiar) {
  return `Digest: ${digest}\nStatus: Downloaded newer image for ${familiar}\n${familiar}\n`
}

let argv = process.argv.slice(2)
let group = null
if (argv[0] === 'image' || argv[0] === 'container') {
  group = argv[0]
  argv = argv.slice(1)
}
const command = argv[0]
const rest = argv.slice(1)

const valueFlags = new Set([
  '-p', '--publish', '--name', '--restart', '--pull', '-e', '--env',
  '-v', '--volume', '--network', '--hostname', '--user', '--entrypoint',
  '-w', '--workdir', '-u', '--memory', '-m', '--cpus', '-l', '--label',
  '--add-host', '--mount', '--format', '--platform'
])

function parseArgs (args) {
  const opts = {}
  let image = null
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--') {
      image = args[i + 1]
      break
    }
    if (arg.startsWith('--') && arg.includes('=')) {
      const eq = arg.indexOf('=')
      opts[arg.slice(0, eq)] = arg.slice(eq + 1)
      continue
    }
    if (valueFlags.has(arg)) {
      opts[arg] = args[++i]
      continue
    }
    if (arg.startsWith('-')) {
      opts[arg] = true
      continue
    }
    image = arg
    break
  }
  return { opts, image }
}

try {
  if (command === 'pull') {
    const { image } = parseArgs(rest)
    const pulled = pull(image)
    remember({ argv: process.argv.slice(2), image, digest: pulled.digest })
    process.stdout.write(digestLine(pulled.digest, `${pulled.ref.name}@${pulled.digest}`))
    process.exit(0)
  }

  if (command === 'inspect') {
    const { opts, image } = parseArgs(rest)
    const found = lookup(image)
    if (!found) fail(new Error(`Error: No such image: ${image}`))
    const repoDigests = [`${found.ref.name}@${found.digest}`]
    const repoTags = []
    const latestKey = `${found.ref.name}:latest`
    if (state.local[latestKey] === found.digest) repoTags.push(latestKey)
    const viewed = { Id: found.digest, RepoDigests: repoDigests, RepoTags: repoTags }
    const format = opts['--format']
    let text
    if (!format) text = JSON.stringify([viewed])
    else if (format === '{{.Id}}') text = viewed.Id
    else if (format === '{{index .RepoDigests 0}}') text = viewed.RepoDigests[0]
    else if (format === '{{.RepoDigests}}') text = '[' + viewed.RepoDigests.join(' ') + ']'
    else if (format === '{{json .RepoDigests}}') text = JSON.stringify(viewed.RepoDigests)
    else fail(new Error(`unsupported format ${format}`))
    remember({ argv: process.argv.slice(2), image, digest: found.digest, group })
    process.stdout.write(text + '\n')
    process.exit(0)
  }

  if (command === 'run') {
    const { opts, image } = parseArgs(rest)
    if (!image) fail(new Error('docker: "docker run" requires at least 1 argument'))
    // cli/command/container/create.go: pull default is "missing".
    // Content trust stays off because the bootstrap does not set
    // DOCKER_CONTENT_TRUST (cli/command/cli_options.go).
    const pullPolicy = opts['--pull'] || 'missing'
    let found = pullPolicy === 'always' ? null : lookup(image)
    if (!found) {
      if (pullPolicy === 'never') fail(new Error(`Unable to find image '${image}' locally`))
      try {
        const pulled = pull(image)
        process.stderr.write(digestLine(pulled.digest, `${pulled.ref.name}@${pulled.digest}`))
        found = lookup(image)
      } catch (error) {
        fail(error)
      }
    }
    if (!found || !found.payload) fail(new Error(`Unable to find image '${image}' locally`))
    const name = opts['--name'] || ''
    if (name && state.containers.some((container) => container.name === name)) {
      fail(new Error(`Conflict. The container name "${name}" is already in use`))
    }
    const container = {
      id: randomBytes(32).toString('hex'),
      name,
      imageArg: image,
      imageDigest: found.digest,
      content: found.payload,
      restart: opts['--restart'] || '',
      port: opts['-p'] || opts['--publish'] || ''
    }
    // createContainer only stores the container after the image resolves.
    state.containers.push(container)
    remember({ argv: process.argv.slice(2), image, digest: found.digest, containerId: container.id })
    if (opts['-d'] || opts['--detach']) process.stdout.write(container.id + '\n')
    process.exit(0)
  }

  fail(new Error(`unsupported docker command: ${command}`))
} catch (error) {
  fail(error)
}
