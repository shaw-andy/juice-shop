/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import type i18n from 'i18n'
import logger from './logger'
import * as utils from './utils'

// i18n looks up locale names and phrases with plain property access and writes missing
// phrases back into the catalog, so neither level may inherit from Object.prototype.
function readLocaleCatalog (directory: string, locale: string): i18n.LocaleCatalog | null {
  try {
    const phrases = JSON.parse(fs.readFileSync(path.join(directory, locale + '.json'), 'utf8'))
    return Object.assign(Object.create(null), phrases)
  } catch (err) {
    logger.warn(`Unable to read backend translations for locale ${locale}: ${utils.getErrorMessage(err)}`)
    return null
  }
}

export function loadGlobalCatalog (directory: string, locales: string[], watch: boolean): i18n.GlobalCatalog {
  const catalog: i18n.GlobalCatalog = Object.create(null)
  for (const locale of locales) {
    catalog[locale] = readLocaleCatalog(directory, locale) ?? Object.create(null)
  }
  if (watch) {
    fs.watch(directory, (event, filename) => {
      const locale = path.basename(filename ?? '', '.json')
      if (!Object.prototype.hasOwnProperty.call(catalog, locale)) return
      const reloaded = readLocaleCatalog(directory, locale)
      if (reloaded !== null) catalog[locale] = reloaded
    })
  }
  return catalog
}
