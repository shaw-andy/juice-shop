/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'

export const easterEggPath = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'

const demoAssets = new Set([
  'three.js',
  'OrbitControls.js',
  'dat.gui.min.js',
  'stats.min.js',
  'EffectComposer.js',
  'RenderPass.js',
  'CopyShader.js',
  'ShaderPass.js',
  'MaskPass.js',
  'starry_background.avif',
  'orangemap2k.avif',
  'earthspec4k.avif',
  'earth_normalmap_flat4k.avif',
  'fair_clouds_4k.avif'
])

function overlayMapFilename () {
  if (!config.has('application.easterEggPlanet.overlayMap')) {
    return undefined
  }
  const overlay: string = config.get('application.easterEggPlanet.overlayMap')
  const filename = utils.isUrl(overlay) ? utils.extractFilename(overlay) : overlay
  return path.basename(filename) === filename ? filename : undefined
}

export function serveEasterEgg () {
  return (req: Request, res: Response) => {
    challengeUtils.solveIf(challenges.easterEggLevelTwoChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/private/threejs-demo.html'))
  }
}

export function serveEasterEggAsset () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file
    if (!demoAssets.has(file) && file !== overlayMapFilename()) {
      next()
      return
    }
    res.sendFile(path.resolve('frontend/dist/private', file))
  }
}
