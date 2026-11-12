/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

// Latest stable Vagrant release. The repository does not pin one; the
// Vagrant section of the README tells the operator to install Vagrant.
const VAGRANT_VERSION = '2.4.9'
const SOURCE_URL = `https://github.com/hashicorp/vagrant/archive/refs/tags/v${VAGRANT_VERSION}.tar.gz`
const RUNTIME_GEMS = [
  'base64:0.2.0',
  'bcrypt_pbkdf:1.1.1',
  'childprocess:5.1.0',
  'csv:3.3.0',
  'ed25519:1.3.0',
  'erubi:1.13.1',
  'hashicorp-checkpoint:0.1.5',
  'i18n:1.14.7',
  'listen:3.9.0',
  'log4r:1.1.10',
  'logger:1.6.4',
  'mime-types:3.6.0',
  'net-ftp:0.3.8',
  'net-ssh:7.3.0',
  'net-sftp:4.0.0',
  'net-scp:4.1.0',
  'ostruct:0.6.1',
  'rb-kqueue:0.2.8',
  'rexml:3.4.1',
  'rubyzip:2.3.2',
  'vagrant_cloud:3.1.2',
  'ipaddr:1.2.6',
  'webrick:1.8.2'
]

const repoRoot = path.resolve(__dirname, '../..')
const vagrantDir = path.join(repoRoot, 'vagrant')
const harness = path.join(__dirname, 'vagrantBoxPin.harness.rb')
const sourceRoot = path.join(os.tmpdir(), 'vagrant-src', `vagrant-${VAGRANT_VERSION}`)
const gemHome = path.join(os.tmpdir(), 'vagrant-gems')

interface InstalledBox {
  installed_version: string
  provider: string
  marker: string
}

interface HarnessResult {
  box: string
  box_version: string | null
  shell_path: string
  shell_privileged: boolean
  shell_script: string
  shell_installs_packages: boolean
  phase1: InstalledBox
  replacement_version: string
  phase2: InstalledBox
}

function run (command: string, args: string[], env: NodeJS.ProcessEnv, cwd?: string) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8'
  })
  if (result.error) {
    throw result.error
  }
  return result
}

function rubyEnv (extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GEM_HOME: gemHome,
    GEM_PATH: gemHome,
    VAGRANT_DISABLE_PLUGIN_INIT: '1',
    VAGRANT_DISABLE_CHECKPOINT: '1',
    VAGRANT_HOME: path.join(os.tmpdir(), 'vagrant-home-tests'),
    ...extra
  }
}

function ensureVagrantSource () {
  const versionFile = path.join(sourceRoot, 'version.txt')
  if (fs.existsSync(versionFile) && fs.readFileSync(versionFile, 'utf8').trim() === VAGRANT_VERSION) {
    return sourceRoot
  }
  fs.mkdirSync(path.dirname(sourceRoot), { recursive: true })
  const tarball = path.join(os.tmpdir(), `vagrant-${VAGRANT_VERSION}.tar.gz`)
  const download = run('curl', ['-fsSL', '-o', tarball, SOURCE_URL], process.env)
  assert.equal(download.status, 0, download.stderr)
  const extract = run('tar', ['-xzf', tarball, '-C', path.dirname(sourceRoot)], process.env)
  assert.equal(extract.status, 0, extract.stderr)
  assert.equal(fs.existsSync(versionFile), true)
  return sourceRoot
}

function ensureRuntime (source: string) {
  fs.mkdirSync(gemHome, { recursive: true })
  const loaded = run(
    'ruby',
    ['-I', path.join(source, 'lib'), '-e', 'require "vagrant"; abort("wrong vagrant") unless Vagrant::VERSION == "' + VAGRANT_VERSION + '"'],
    rubyEnv()
  )
  if (loaded.status === 0) {
    return
  }
  const install = run('gem', ['install', '--no-document', ...RUNTIME_GEMS], rubyEnv())
  assert.equal(install.status, 0, install.stdout + install.stderr)
  const retry = run(
    'ruby',
    ['-I', path.join(source, 'lib'), '-e', 'require "vagrant"; abort("wrong vagrant") unless Vagrant::VERSION == "' + VAGRANT_VERSION + '"'],
    rubyEnv()
  )
  assert.equal(retry.status, 0, retry.stderr)
}

function resolveBox (source: string): HarnessResult {
  const result = run(
    'ruby',
    ['-I', path.join(source, 'lib'), harness],
    rubyEnv({ VAGRANTFILE_CWD: vagrantDir }),
    source
  )
  assert.equal(
    result.status,
    0,
    `Vagrant box resolution failed\n${result.stdout}\n${result.stderr}`
  )
  return JSON.parse(result.stdout) as HarnessResult
}

void describe('vagrant box version pin', () => {
  void it('keeps a newly published box version from being the one vagrant up installs', { timeout: 300_000 }, () => {
    const source = ensureVagrantSource()
    ensureRuntime(source)
    const resolved = resolveBox(source)

    assert.equal(resolved.box, 'generic/ubuntu2110')
    assert.equal(resolved.shell_path, 'bootstrap.sh')
    assert.equal(resolved.shell_privileged, true)
    assert.equal(resolved.shell_script, path.join(vagrantDir, 'bootstrap.sh'))
    assert.equal(resolved.shell_installs_packages, true)
    assert.equal(resolved.phase1.provider, 'virtualbox')
    assert.equal(resolved.phase2.provider, 'virtualbox')
    assert.equal(resolved.phase2.installed_version, resolved.phase1.installed_version)
    assert.equal(resolved.phase2.marker, 'baseline')
    assert.notEqual(resolved.phase2.installed_version, resolved.replacement_version)
  })
})
