/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const bootstrap = path.join(repoRoot, 'vagrant/bootstrap.sh')
const defaultConf = path.join(repoRoot, 'vagrant/default.conf')
const stub = path.join(repoRoot, 'test/server/helpers/docker201017Stub.mjs')
const manifestFixture = path.join(repoRoot, 'test/server/helpers/legitimate-juice-shop-manifest.json')

// The legitimate manifest is the published image index saved in the fixture.
// `latest` can later point at the replaced bytes. A fixed provision pins the
// fixture digest, which is the hash of those saved bytes.
const LEGITIMATE_IMAGE_BYTES = readFileSync(manifestFixture, 'utf8')
const REPLACED_IMAGE_BYTES = 'replaced-juice-shop-image'

function digestOf (bytes: string) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

const legitimateDigest = digestOf(LEGITIMATE_IMAGE_BYTES)
const replacedDigest = digestOf(REPLACED_IMAGE_BYTES)

function writeExecutable (file: string, body: string) {
  writeFileSync(file, body)
  chmodSync(file, 0o755)
}

function stubBin () {
  const dir = path.join(tmpdir(), `juice-vagrant-stub-${process.pid}-${Math.random().toString(16).slice(2)}`)
  mkdirSync(dir)
  writeExecutable(path.join(dir, 'sudo'), '#!/bin/sh\nexec "$@"\n')
  writeExecutable(path.join(dir, 'apt-key'), '#!/bin/sh\nexit 0\n')
  writeExecutable(path.join(dir, 'apt-get'), '#!/bin/sh\nexit 0\n')
  writeExecutable(path.join(dir, 'curl'), '#!/bin/sh\nexit 0\n')
  writeExecutable(path.join(dir, 'a2enmod'), '#!/bin/sh\nexit 0\n')
  writeExecutable(path.join(dir, 'systemctl'), '#!/bin/sh\nexit 0\n')
  writeExecutable(path.join(dir, 'docker'), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(stub)} "$@"\n`)
  return dir
}

interface RunOptions {
  latestDigest: string
  retargetTo?: string
  corruptDigest?: string
}

interface DockerState {
  commandCount: number
  blobs: Record<string, string>
  remoteTags: Record<string, string>
  local: Record<string, string>
  containers: Array<{
    id: string
    name: string
    imageArg: string
    imageDigest: string
    content: string
    restart: string
    port: string
  }>
  commands: Array<{ argv: string[], image?: string, digest?: string, error?: string }>
}

function runBootstrap (options: RunOptions) {
  const bin = stubBin()
  const statePath = path.join(tmpdir(), `juice-vagrant-docker-${process.pid}-${Math.random().toString(16).slice(2)}.json`)
  const confOut = path.join(tmpdir(), `juice-vagrant-apache-${process.pid}-${Math.random().toString(16).slice(2)}.conf`)
  const state: DockerState = {
    commandCount: 0,
    blobs: {
      [legitimateDigest]: LEGITIMATE_IMAGE_BYTES,
      [replacedDigest]: REPLACED_IMAGE_BYTES
    },
    remoteTags: {
      'bkimminich/juice-shop:latest': options.latestDigest
    },
    local: {},
    containers: [],
    commands: []
  }
  writeFileSync(statePath, JSON.stringify(state))
  const runner = path.join(bin, 'runner.sh')
  writeExecutable(runner, `#!/bin/sh
set -eu
mount -t tmpfs tmpfs /etc/apache2
mount -t tmpfs tmpfs /etc/apt/sources.list.d
mkdir -p /etc/apache2/sites-available /tmp/juice-shop
cp "$DEFAULT_CONF" /tmp/juice-shop/default.conf
export PATH="$STUB_BIN:$PATH"
set +e
sh "$BOOTSTRAP"
status=$?
set -e
if [ -f /etc/apache2/sites-available/000-default.conf ]; then
  cp /etc/apache2/sites-available/000-default.conf "$CONF_OUT"
fi
exit $status
`)
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    DEFAULT_CONF: defaultConf,
    STUB_BIN: bin,
    BOOTSTRAP: bootstrap,
    CONF_OUT: confOut,
    DOCKER_STUB_STATE: statePath
  }
  if (options.retargetTo) env.DOCKER_STUB_RETARGET_TO = options.retargetTo
  if (options.corruptDigest) env.DOCKER_STUB_CORRUPT_DIGEST = options.corruptDigest
  const result = spawnSync('unshare', ['--user', '--map-root-user', '--mount', runner], {
    env,
    encoding: 'utf8'
  })
  const after = JSON.parse(readFileSync(statePath, 'utf8')) as DockerState
  let installedConf = ''
  try {
    installedConf = readFileSync(confOut, 'utf8')
  } catch {
    installedConf = ''
  }
  return { result, after, installedConf }
}

void describe('vagrant bootstrap image pin', { concurrency: false }, () => {
  void it('starts the pinned shop image when latest has moved', () => {
    const { result, after, installedConf } = runBootstrap({ latestDigest: replacedDigest })
    const output = `${result.stdout}\n${result.stderr}`
    const pinned = 'bkimminich/juice-shop@' + legitimateDigest
    assert.equal(result.status, 0, output)
    assert.equal(after.containers.length, 1, output)
    const container = after.containers[0]
    assert.equal(digestOf(container.content), legitimateDigest, `ran ${JSON.stringify(container.content.slice(0, 60))} from ${container.imageArg}; docker run must use ${pinned}`)
    assert.equal(container.imageDigest, legitimateDigest)
    assert.equal(container.imageArg.includes(pinned), true, `docker run image was ${container.imageArg}; expected ${pinned}`)
    assert.equal(container.port, '3000:3000')
    assert.equal(container.restart, 'always')
    assert.equal(after.remoteTags['bkimminich/juice-shop:latest'], replacedDigest)
    assert.equal(installedConf, readFileSync(defaultConf, 'utf8'))
  })

  void it('starts the digest passed to docker run after an earlier tag lookup', () => {
    const { result, after } = runBootstrap({
      latestDigest: legitimateDigest,
      retargetTo: replacedDigest
    })
    const output = `${result.stdout}\n${result.stderr}`
    assert.equal(result.status, 0, output)
    const runs = after.commands.filter((command) => command.argv[0] === 'run')
    const pinned = 'bkimminich/juice-shop@' + legitimateDigest
    assert.equal(runs.length, 1, output)
    assert.equal(runs[0].image?.includes(pinned), true, `docker run image was ${String(runs[0].image)}; expected ${pinned}`)
    assert.equal(after.containers.length, 1)
    assert.equal(after.containers[0].imageDigest, legitimateDigest)
    assert.equal(digestOf(after.containers[0].content), legitimateDigest)
    assert.equal(after.containers[0].imageArg.includes(pinned), true)
  })

  void it('does not start a container when the pinned digest does not match the manifest', () => {
    const { result, after } = runBootstrap({
      latestDigest: replacedDigest,
      corruptDigest: legitimateDigest
    })
    assert.notEqual(result.status, 0, `${result.stdout}\n${result.stderr}`)
    assert.equal(after.containers.length, 0)
  })
})
