/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import i18n from 'i18n'

type Translate = (phraseOrOptions: string | i18n.TranslateOptions, ...replace: any[]) => string

const tagPattern = /<[^<>]*>/g
const wellFormedTag = /^(?:<!--[^<>]*-->|<\/?[a-zA-Z][\w-]*(?:\s+[^\s"'<>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*\s*\/?>)$/

// Translated phrases are rendered as trusted HTML (e.g. challenge descriptions on the Score Board),
// so a locale catalog may only reuse markup that appears verbatim and well-formed in the source phrase.
export function introducesMarkup (source: string, translated: string): boolean {
  if (translated === source) return false
  const sourceTags = new Set((source.match(tagPattern) ?? []).filter(tag => wellFormedTag.test(tag)))
  return translated.replace(tagPattern, tag => sourceTags.has(tag) ? '' : tag).includes('<')
}

function guard (translate: Translate): Translate {
  return (phraseOrOptions, ...replace) => {
    const translated = translate(phraseOrOptions, ...replace)
    const source = typeof phraseOrOptions === 'string' ? phraseOrOptions : phraseOrOptions?.phrase
    if (typeof source !== 'string' || typeof translated !== 'string' || !introducesMarkup(source, translated)) {
      return translated
    }
    return i18n.__({ phrase: source, locale: 'en' }, ...replace)
  }
}

export function guardTranslatedMarkup () {
  return (req: Request, res: Response, next: NextFunction) => {
    for (const target of [req, res, res.locals]) {
      if (typeof target.__ === 'function') {
        target.__ = guard(target.__)
      }
    }
    next()
  }
}
