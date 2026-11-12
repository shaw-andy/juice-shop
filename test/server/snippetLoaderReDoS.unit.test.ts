/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import * as codingChallenges from '../../lib/codingChallenges'

const isolateScript = path.resolve(__dirname, 'helpers/snippetLoaderIsolate.ts')
const repoRoot = path.resolve(__dirname, '../..')

// Long enough that a nested quantifier on one line does not return, short of the upload limit.
const filler = 'a'.repeat(32)

interface ParseResult {
  ok: boolean
  name?: string
  message?: string
  vulnLines?: number[]
  neutralLines?: number[]
  snippet?: string
}

function runParse (source: string, key: string, timeoutMs: number): Promise<{ timedOut: boolean, result: ParseResult | null }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'snippet-loader-'))
  const inputPath = path.join(dir, 'input.json')
  const resultPath = path.join(dir, 'result.json')
  fs.writeFileSync(inputPath, JSON.stringify({ op: 'parse', source, key, resultPath }))
  const child = spawn(process.execPath, ['--import', 'tsx', isolateScript, inputPath], {
    cwd: repoRoot,
    env: { ...process.env, NODE_ENV: 'test' },
    stdio: ['ignore', 'ignore', 'pipe']
  })
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
    }, timeoutMs)
    child.on('exit', (_code, signal) => {
      clearTimeout(timer)
      let result: ParseResult | null = null
      if (fs.existsSync(resultPath)) {
        result = JSON.parse(fs.readFileSync(resultPath, 'utf8')) as ParseResult
      }
      fs.rmSync(dir, { recursive: true, force: true })
      resolve({ timedOut: signal === 'SIGKILL', result })
    })
  })
}

async function assertLiteralBoundaryMiss (source: string, key: string) {
  const outcome = await runParse(source, key, 1000)
  assert.equal(outcome.timedOut, false)
  assert.ok(outcome.result)
  assert.equal(outcome.result.ok, false)
  assert.equal(outcome.result.name, 'BrokenBoundary')
}

void describe('coding challenge snippet markers', () => {
  void it('treats a nested quantifier in a // marker as a literal and returns', async () => {
    const source = `// vuln-code-snippet start (.+)+ ${filler}\n`
    await assertLiteralBoundaryMiss(source, '(.+)+')
  })

  void it('treats a nested quantifier in a # marker as a literal and returns', async () => {
    const source = `# vuln-code-snippet start (.+)+ ${filler}\n`
    await assertLiteralBoundaryMiss(source, '(.+)+')
  })

  void it('does not hang while classifying a vuln-line whose marker text is a nested quantifier', async () => {
    const source = [
      '// vuln-code-snippet start aaab',
      '// vuln-code-snippet vuln-line ' + filler,
      '// vuln-code-snippet end aaab'
    ].join('\n')
    await assertLiteralBoundaryMiss(source, '(a+)+b')
  })

  void it('does not hang while classifying a neutral-line whose marker text is a nested quantifier', async () => {
    const source = [
      '// vuln-code-snippet start aaab',
      '// vuln-code-snippet neutral-line ' + filler,
      '// vuln-code-snippet end aaab'
    ].join('\n')
    await assertLiteralBoundaryMiss(source, '(a+)+b')
  })

  void it('classifies vuln and neutral lines only when the marker name matches literally', () => {
    const source = [
      '// vuln-code-snippet start a.b',
      'lineA',
      '// vuln-code-snippet vuln-line a.b',
      '// vuln-code-snippet vuln-line aXb',
      '// vuln-code-snippet neutral-line a.b',
      '// vuln-code-snippet neutral-line aYb',
      '// vuln-code-snippet end a.b'
    ].join('\n')
    const parsed = codingChallenges.getCodingChallengeFromFileContent(source, 'a.b')
    assert.equal(parsed.snippet, 'lineA')
    assert.deepEqual(parsed.vulnLines, [2])
    assert.deepEqual(parsed.neutralLines, [4])
  })

  void it('still extracts a snippet whose marker name is a nested quantifier when the end marker is present', () => {
    const source = [
      '// vuln-code-snippet start (.+)+',
      'BODY',
      '// vuln-code-snippet end (.+)+'
    ].join('\n')
    const parsed = codingChallenges.getCodingChallengeFromFileContent(source, '(.+)+')
    assert.equal(parsed.snippet, 'BODY')
    assert.deepEqual(parsed.vulnLines, [])
    assert.deepEqual(parsed.neutralLines, [])
  })
})
