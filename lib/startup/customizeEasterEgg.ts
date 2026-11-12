/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import * as utils from '../utils'
import { easterEggPath } from '../../routes/easterEgg'
// @ts-expect-error FIXME due to non-existing type definitions for replace
import replace from 'replace'

const customizeEasterEgg = async () => {
  if (config.has('application.easterEggPlanet.overlayMap')) {
    let overlay: string = config.get('application.easterEggPlanet.overlayMap')
    if (utils.isUrl(overlay)) {
      const overlayPath = overlay
      overlay = utils.extractFilename(overlay)
      await utils.downloadToFile(overlayPath, 'frontend/dist/private/' + overlay)
    }
    replaceImagePath(overlay)
  }
  if (config.has('application.easterEggPlanet.name')) {
    replaceThreeJsTitleTag()
  }
}

const replaceImagePath = (overlay: string) => {
  const textureDeclaration = 'orangeTexture = THREE.ImageUtils.loadTexture("' + easterEggPath + '/' + overlay + '");'
  replace({
    regex: /orangeTexture = .*;/,
    replacement: textureDeclaration,
    paths: ['frontend/dist/private/threejs-demo.html'],
    recursive: false,
    silent: true
  })
}

const replaceThreeJsTitleTag = () => {
  const threeJsTitleTag = '<title>Welcome to Planet ' + config.get<string>('application.easterEggPlanet.name') + '</title>'
  replace({
    regex: /<title>.*<\/title>/,
    replacement: threeJsTitleTag,
    paths: ['frontend/dist/private/threejs-demo.html'],
    recursive: false,
    silent: true
  })
}

export default customizeEasterEgg
