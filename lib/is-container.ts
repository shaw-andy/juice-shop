/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Recognizes container runtimes other than Docker Engine (ECS/Fargate, Kubernetes, containerd, CRI-O, Podman, LXC,
// Cloud Run, Azure Container Apps, Fly.io), which do not leave the markers lib/is-docker.ts looks for.

import fs from 'node:fs'

let isContainerCached: boolean | undefined

const containerEnvironmentVariables = [
  'ECS_CONTAINER_METADATA_URI_V4',
  'ECS_CONTAINER_METADATA_URI',
  'KUBERNETES_SERVICE_HOST',
  'K_SERVICE',
  'CONTAINER_APP_NAME',
  'FLY_APP_NAME'
]

const containerMarkerFiles = [
  '/run/.containerenv',
  '/var/run/secrets/kubernetes.io/serviceaccount'
]

const containerCGroupPattern = /\/ecs\/|kubepods|containerd|crio-|libpod|\/lxc[/.]/
const containerMountInfoPattern = /\/containerd\/|io\.containerd\.|\/var\/lib\/containers\/storage\/|\/var\/lib\/kubelet\//

function hasContainerEnvironment () {
  if (containerEnvironmentVariables.some(name => (process.env[name] ?? '') !== '')) {
    return true
  }
  if ((process.env.AWS_EXECUTION_ENV ?? '').startsWith('AWS_ECS')) {
    return true
  }
  return (process.env.container ?? '') !== ''
}

function hasContainerMarkerFile () {
  return containerMarkerFiles.some(file => {
    try {
      fs.statSync(file)
      return true
    } catch {
      return false
    }
  })
}

function hasContainerCGroup () {
  try {
    return containerCGroupPattern.test(fs.readFileSync('/proc/self/cgroup', 'utf8'))
  } catch {
    return false
  }
}

function hasContainerMountInfo () {
  try {
    return containerMountInfoPattern.test(fs.readFileSync('/proc/self/mountinfo', 'utf8'))
  } catch {
    return false
  }
}

export default function isContainer () {
  isContainerCached ??= hasContainerEnvironment() || hasContainerMarkerFile() || hasContainerCGroup() || hasContainerMountInfo()
  return isContainerCached
}
