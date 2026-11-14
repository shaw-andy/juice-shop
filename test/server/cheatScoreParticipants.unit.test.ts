/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as antiCheat from '../../lib/antiCheat'

const TEN_YEARS_MS = 10 * 365 * 24 * 60 * 60 * 1000

function installClock () {
  const RealDate = Date
  let current = RealDate.now()
  function FakeDate (this: unknown, ...args: unknown[]) {
    if (!new.target) {
      return RealDate()
    }
    if (args.length === 0) {
      return new RealDate(current)
    }
    return new RealDate(...args as [string])
  }
  FakeDate.now = () => current
  FakeDate.parse = RealDate.parse
  FakeDate.UTC = RealDate.UTC
  FakeDate.prototype = RealDate.prototype
  Object.setPrototypeOf(FakeDate, RealDate)
  global.Date = FakeDate as DateConstructor
  return {
    advance (ms: number) {
      current += ms
    },
    restore () {
      global.Date = RealDate
    }
  }
}

async function withBaselineGap (fn: () => Promise<void> | void) {
  const clock = installClock()
  try {
    antiCheat.reset()
    clock.advance(TEN_YEARS_MS)
    await fn()
  } finally {
    clock.restore()
    antiCheat.reset()
  }
}

void describe('cheat score participants', { concurrency: 1 }, () => {
  void it('still flags one participant who solves two unrelated challenges back to back', async () => {
    await withBaselineGap(() => {
      antiCheat.calculateCheatScore({ key: 'nftUnlockChallenge', difficulty: 2 } as any, false, 'same-participant')
      const score = antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2 } as any, false, 'same-participant')
      assert.ok(score > 0.66, `same-participant score was ${score}`)
    })
  })

  void it('does not let one participant make another participant\'s next solve look instant', async () => {
    await withBaselineGap(() => {
      antiCheat.calculateCheatScore({ key: 'nftUnlockChallenge', difficulty: 2 } as any, false, 'attacker')
      const score = antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2 } as any, false, 'victim')
      assert.ok(score < 0.33, `victim score was ${score}`)
    })
  })

  void it('does not let an isCheating solve move another participant\'s clock', async () => {
    await withBaselineGap(() => {
      antiCheat.calculateCheatScore({ key: 'nftUnlockChallenge', difficulty: 2 } as any, true, 'attacker')
      const score = antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2 } as any, false, 'victim')
      assert.ok(score < 0.33, `victim score was ${score}`)
    })
  })

  void it('still flags one participant whose find-it phases land back to back', async () => {
    await withBaselineGap(async () => {
      await antiCheat.calculateFindItCheatScore({ key: 'scoreBoardChallenge' } as any, 'same-participant')
      const score = await antiCheat.calculateFindItCheatScore({ key: 'scoreBoardChallenge' } as any, 'same-participant')
      assert.ok(score > 0.66, `same-participant find-it score was ${score}`)
    })
  })

  void it('does not let another participant\'s solve make a find-it phase look instant', async () => {
    await withBaselineGap(async () => {
      antiCheat.calculateCheatScore({ key: 'nftUnlockChallenge', difficulty: 2 } as any, false, 'attacker')
      const score = await antiCheat.calculateFindItCheatScore({ key: 'scoreBoardChallenge' } as any, 'victim')
      assert.ok(score < 0.33, `victim find-it score was ${score}`)
    })
  })

  void it('still flags one participant whose fix-it phases land back to back', async () => {
    await withBaselineGap(async () => {
      await antiCheat.calculateFixItCheatScore({ key: 'scoreBoardChallenge' } as any, 'same-participant')
      const score = await antiCheat.calculateFixItCheatScore({ key: 'scoreBoardChallenge' } as any, 'same-participant')
      assert.ok(score > 0.66, `same-participant fix-it score was ${score}`)
    })
  })

  void it('does not let another participant\'s solve make a fix-it phase look instant', async () => {
    await withBaselineGap(async () => {
      antiCheat.calculateCheatScore({ key: 'nftUnlockChallenge', difficulty: 2 } as any, false, 'attacker')
      const score = await antiCheat.calculateFixItCheatScore({ key: 'scoreBoardChallenge' } as any, 'victim')
      assert.ok(score < 0.33, `victim fix-it score was ${score}`)
    })
  })

  void it('does not let another participant\'s solve zero a loosely coupled challenge', async () => {
    await withBaselineGap(() => {
      antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2 } as any, false, 'victim')
      antiCheat.calculateCheatScore({ key: 'localXssChallenge', difficulty: 1 } as any, false, 'attacker')
      const score = antiCheat.calculateCheatScore({ key: 'xssBonusChallenge', difficulty: 1 } as any, false, 'victim')
      assert.ok(score > 0.66, `victim loosely coupled score was ${score}`)
    })
  })

  void it('does not let another participant\'s solve zero a tightly coupled challenge', async () => {
    await withBaselineGap(() => {
      antiCheat.calculateCheatScore({ key: 'securityPolicyChallenge', difficulty: 2 } as any, false, 'victim')
      antiCheat.calculateCheatScore({ key: 'weakPasswordChallenge', difficulty: 1 } as any, false, 'attacker')
      const score = antiCheat.calculateCheatScore({ key: 'loginAdminChallenge', difficulty: 1 } as any, false, 'victim')
      assert.ok(score > 0.66, `victim tightly coupled score was ${score}`)
    })
  })
})
