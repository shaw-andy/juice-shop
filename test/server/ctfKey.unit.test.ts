/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkForIllogicalCombos } from '../../lib/startup/validateConfig'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

const ctfMode = {
  challenges: { restrictToTutorialsFirst: false, showSolvedNotifications: true },
  hackingInstructor: { isEnabled: true },
  ctf: { showFlagsInNotifications: true, showCountryDetailsInNotifications: 'none' as const }
}

function runScenario (name: string): { status: number | null, stdout: string, stderr: string } {
  const result = spawnSync(process.execPath, [
    '--import', './test/server/helpers/test-env.mjs',
    '--import', 'tsx',
    'test/server/helpers/ctf-key-isolated.ts',
    name
  ], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'test' }
  })
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? ''
  }
}

function expectRefused (name: string): void {
  const result = runScenario(name)
  assert.equal(result.status, 0, `stdout=${JSON.stringify(result.stdout)} stderr=${result.stderr}`)
  assert.equal(result.stdout, 'REFUSED\n')
}

void describe('ctf key', () => {
  void it('ctfFlag refuses to mint when CTF_KEY is unset and ctf.key is present', () => {
    expectRefused('flag-unset')
  })

  void it('ctfFlag refuses to mint when CTF_KEY is empty and ctf.key is present', () => {
    expectRefused('flag-empty')
  })

  void it('ctfFlag refuses again on a later call in the same process when CTF_KEY stays unset', () => {
    expectRefused('flag-twice')
  })

  void it('sendNotification does not publish a flag when CTF_KEY is unset', () => {
    expectRefused('notification-unset')
  })

  void it('solve does not publish a flag or webhook payload when CTF_KEY is unset', () => {
    expectRefused('solve-unset')
  })

  void it('webhook.notify does not POST a flag when CTF_KEY is unset', () => {
    expectRefused('webhook-unset')
  })

  void it('ctfFlag signs with CTF_KEY when that variable is set', () => {
    const result = runScenario('flag-env')
    assert.equal(result.status, 0, `stdout=${JSON.stringify(result.stdout)} stderr=${result.stderr}`)
    assert.equal(result.stdout, 'OK\n')
  })

  void it('checkForIllogicalCombos rejects CTF mode when CTF_KEY is unset', () => {
    const previous = process.env.CTF_KEY
    delete process.env.CTF_KEY
    try {
      assert.equal(checkForIllogicalCombos(ctfMode), false)
    } finally {
      if (previous === undefined) delete process.env.CTF_KEY
      else process.env.CTF_KEY = previous
    }
  })

  void it('checkForIllogicalCombos rejects CTF mode when CTF_KEY is empty', () => {
    const previous = process.env.CTF_KEY
    process.env.CTF_KEY = ''
    try {
      assert.equal(checkForIllogicalCombos(ctfMode), false)
    } finally {
      if (previous === undefined) delete process.env.CTF_KEY
      else process.env.CTF_KEY = previous
    }
  })

  void it('checkForIllogicalCombos accepts CTF mode when CTF_KEY is set', () => {
    const previous = process.env.CTF_KEY
    process.env.CTF_KEY = 'placeholder-ctf-key'
    try {
      assert.equal(checkForIllogicalCombos(ctfMode), true)
    } finally {
      if (previous === undefined) delete process.env.CTF_KEY
      else process.env.CTF_KEY = previous
    }
  })

  void it('checkForIllogicalCombos does not require CTF_KEY when flags are hidden', () => {
    const previous = process.env.CTF_KEY
    delete process.env.CTF_KEY
    try {
      assert.equal(checkForIllogicalCombos({
        ...ctfMode,
        ctf: { showFlagsInNotifications: false, showCountryDetailsInNotifications: 'none' }
      }), true)
    } finally {
      if (previous === undefined) delete process.env.CTF_KEY
      else process.env.CTF_KEY = previous
    }
  })

  void it('the repository does not contain a default ctf.key file', () => {
    assert.equal(fs.existsSync(path.join(repoRoot, 'ctf.key')), false)
  })

  void it('the release packager does not list a default ctf.key file', () => {
    const source = fs.readFileSync(path.join(repoRoot, 'scripts/package.mjs'), 'utf8')
    assert.equal(source.includes("'ctf.key'"), false)
  })
})
