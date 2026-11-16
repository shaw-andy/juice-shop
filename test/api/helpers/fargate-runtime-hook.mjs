/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { mock } from 'node:test'

// Stand-in for the runtime signals a Fargate task presents to lib/is-docker.ts.
// Platform LATEST is 1.4.0 and that platform runs containerd, not Docker Engine,
// so the Docker init layer that creates /.dockerenv is not applied. The cgroup
// path uses the ECS "/ecs/<task>" prefix and does not contain "docker".
// mountinfo has no Docker graph-driver path.
const realStatSync = fs.statSync
const realReadFileSync = fs.readFileSync

const fargateCgroup = '0::/ecs/03752a671e744971a862edcee6195646/03752a671e744971a862edcee6195646-4015103728\n'
const fargateMountinfo = '36 35 0:31 / / rw,relatime - overlay overlay rw\n'

mock.method(fs, 'statSync', function (target, options) {
  if (target === '/.dockerenv') {
    const error = new Error('ENOENT: no such file or directory, stat \'/.dockerenv\'')
    error.code = 'ENOENT'
    throw error
  }
  return realStatSync.call(fs, target, options)
})

mock.method(fs, 'readFileSync', function (target, options) {
  if (target === '/proc/self/cgroup') return fargateCgroup
  if (target === '/proc/self/mountinfo') return fargateMountinfo
  return realReadFileSync.call(fs, target, options)
})

process.env.ECS_CONTAINER_METADATA_URI_V4 = 'http://ecs-metadata.invalid/v4'
delete process.env.HEROKU
delete process.env.DYNO
