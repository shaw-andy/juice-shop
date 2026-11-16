/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, afterEach, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const containerEnvironmentVariables = ['ECS_CONTAINER_METADATA_URI_V4', 'ECS_CONTAINER_METADATA_URI', 'KUBERNETES_SERVICE_HOST', 'K_SERVICE', 'CONTAINER_APP_NAME', 'FLY_APP_NAME']
const environmentVariables = [...containerEnvironmentVariables, 'AWS_EXECUTION_ENV', 'container']

function mockFileSystem (t: TestContext, { existingFiles = [], cgroup, mountinfo }: { existingFiles?: string[], cgroup?: string, mountinfo?: string } = {}) {
  t.mock.method(fs, 'statSync', (path: string) => {
    if (existingFiles.includes(path)) return {} as fs.Stats
    throw new Error()
  })
  t.mock.method(fs, 'readFileSync', (path: string) => {
    if (path === '/proc/self/cgroup' && cgroup !== undefined) return cgroup
    if (path === '/proc/self/mountinfo' && mountinfo !== undefined) return mountinfo
    throw new Error()
  })
}

void describe('isContainer', () => {
  let isContainer: any
  let savedEnvironment: Record<string, string | undefined>

  beforeEach(() => {
    savedEnvironment = Object.fromEntries(environmentVariables.map(name => [name, process.env[name]]))
    for (const name of environmentVariables) delete process.env[name]
    try {
      const path = require.resolve('../../lib/is-container')
      delete require.cache[path]
    } catch (e) {}
    isContainer = require('../../lib/is-container').default
  })

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnvironment)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  })

  void it('should return false if no container markers are present', (t) => {
    mockFileSystem(t)
    assert.equal(isContainer(), false)
  })

  for (const name of containerEnvironmentVariables) {
    void it(`should return true if ${name} is set`, (t) => {
      mockFileSystem(t)
      process.env[name] = 'placeholder'
      assert.equal(isContainer(), true)
    })
  }

  void it('should return true if AWS_EXECUTION_ENV names an ECS launch type', (t) => {
    mockFileSystem(t)
    process.env.AWS_EXECUTION_ENV = 'AWS_ECS_FARGATE'
    assert.equal(isContainer(), true)
  })

  void it('should return true if the container variable is set', (t) => {
    mockFileSystem(t)
    process.env.container = 'podman'
    assert.equal(isContainer(), true)
  })

  for (const file of ['/run/.containerenv', '/var/run/secrets/kubernetes.io/serviceaccount']) {
    void it(`should return true if ${file} exists`, (t) => {
      mockFileSystem(t, { existingFiles: [file] })
      assert.equal(isContainer(), true)
    })
  }

  for (const cgroup of [
    '0::/ecs/03752a671e744971a862edcee6195646/03752a671e744971a862edcee6195646-4015103728',
    '0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-0123456789abcdef.scope',
    '0::/system.slice/crio-0123456789abcdef.scope',
    '0::/machine.slice/libpod-0123456789abcdef.scope'
  ]) {
    void it(`should return true if /proc/self/cgroup is ${cgroup}`, (t) => {
      mockFileSystem(t, { cgroup })
      assert.equal(isContainer(), true)
    })
  }

  void it('should return false for a regular host process', (t) => {
    mockFileSystem(t, {
      cgroup: '0::/user.slice/user-1000.slice/session-2.scope',
      mountinfo: '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw'
    })
    assert.equal(isContainer(), false)
  })

  void it('should return true if /proc/self/mountinfo references a containerd snapshot', (t) => {
    mockFileSystem(t, { mountinfo: '36 35 0:31 / / rw - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs' })
    assert.equal(isContainer(), true)
  })
})
