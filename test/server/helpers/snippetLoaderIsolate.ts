/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import * as codingChallenges from '../../../lib/codingChallenges'

interface ParseInput {
  op: 'parse'
  source: string
  key: string
  resultPath: string
}

function writeResult (resultPath: string, value: unknown) {
  fs.writeFileSync(resultPath, JSON.stringify(value))
}

async function main () {
  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')) as ParseInput
  if (input.op !== 'parse') {
    writeResult(input.resultPath, { ok: false, name: 'Error', message: 'unknown op' })
    return
  }
  try {
    const parsed = codingChallenges.getCodingChallengeFromFileContent(input.source, input.key)
    writeResult(input.resultPath, {
      ok: true,
      vulnLines: parsed.vulnLines,
      neutralLines: parsed.neutralLines,
      snippet: parsed.snippet
    })
  } catch (error) {
    const err = error as Error
    writeResult(input.resultPath, { ok: false, name: err.name, message: err.message })
  }
}

void main()
