import fs from 'node:fs'
import yaml from 'js-yaml'
import { type NextFunction, type Request, type Response } from 'express'

import * as accuracy from '../lib/accuracy'
import * as challengeUtils from '../lib/challengeUtils'
import { type ChallengeKey } from '@juice-shop/models/challenge'

const FixesDir = 'data/static/codefixes'

interface codeFix {
  fixes: string[]
  correct: number
}

let CodeFixes: Map<string, codeFix> | null = null

const loadFixes = () => {
  const fixesByKey = new Map<string, codeFix>()
  for (const file of fs.readdirSync(FixesDir)) {
    const metadata = file.split('_')
    if (metadata.length < 2) continue
    const key = metadata[0]
    let entry = fixesByKey.get(key)
    if (entry === undefined) {
      entry = { fixes: [], correct: -1 }
      fixesByKey.set(key, entry)
    }
    entry.fixes.push(fs.readFileSync(`${FixesDir}/${file}`).toString())
    if (metadata.length === 3) {
      entry.correct = parseInt(metadata[1], 10) - 1
    }
  }
  return fixesByKey
}

export const readFixes = (key: string): codeFix => {
  CodeFixes ??= loadFixes()
  return CodeFixes.get(key) ?? { fixes: [], correct: -1 }
}

interface FixesRequestParams {
  key: string
}

interface VerdictRequestBody {
  key: ChallengeKey
  selectedFix: number
}

export const serveCodeFixes = () => (req: Request<FixesRequestParams, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  const key = req.params.key
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
    return
  }
  res.status(200).json({
    fixes: fixData.fixes
  })
}

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  const selectedFix = req.body.selectedFix
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
  } else {
    let explanation
    if (fs.existsSync('./data/static/codefixes/' + key + '.info.yml')) {
      const codingChallengeInfos = yaml.load(fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'))
      const selectedFixInfo = codingChallengeInfos?.fixes.find(({ id }: { id: number }) => id === selectedFix + 1)
      if (selectedFixInfo?.explanation) explanation = res.__(selectedFixInfo.explanation)
    }
    if (selectedFix === fixData.correct) {
      await challengeUtils.solveFixIt(key)
      res.status(200).json({
        verdict: true,
        explanation
      })
    } else {
      accuracy.storeFixItVerdict(key, false)
      res.status(200).json({
        verdict: false,
        explanation
      })
    }
  }
}
