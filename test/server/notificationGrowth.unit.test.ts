/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { notifications, challenges } from '../../data/datacache'
import { sendNotification, solve } from '../../lib/challengeUtils'

const globalWithIo = global as typeof globalThis & {
  io: { emit: (...args: unknown[]) => void }
}

function noticesFor (key: string) {
  return notifications.filter(notification => notification.key === key)
}

function solvedChallenge () {
  return {
    solved: true,
    key: 'scoreBoardChallenge' as const,
    name: 'Score Board',
    description: 'Find the carefully hidden Score Board page.',
    difficulty: 1,
    save: mock.fn(async function (this: { solved: boolean }) { return this })
  }
}

void describe('solved-challenge notice retention', () => {
  beforeEach(() => {
    notifications.splice(0, notifications.length)
    globalWithIo.io = { emit: () => {} }
  })

  void it('retains at most one notice when the same solved challenge is broadcast again', () => {
    const challenge = solvedChallenge()
    challenges.scoreBoardChallenge = challenge as unknown as typeof challenges.scoreBoardChallenge

    sendNotification(challenge, false)
    assert.equal(noticesFor(challenge.key).length, 1)

    for (let i = 0; i < 25; i++) {
      sendNotification(challenge, true)
      sendNotification(challenge, false)
    }

    assert.equal(noticesFor(challenge.key).length, 1)
  })

  void it('retains at most one notice when restore marks the same challenge solved again', async () => {
    const challenge = solvedChallenge()
    challenges.scoreBoardChallenge = challenge as unknown as typeof challenges.scoreBoardChallenge

    await solve(challenge, true)
    assert.equal(noticesFor(challenge.key).length, 1)

    for (let i = 0; i < 15; i++) {
      await solve(challenge, true)
    }

    assert.equal(noticesFor(challenge.key).length, 1)
  })

  void it('stores one notice again after the previous notice is removed and still ignores further broadcasts', () => {
    const challenge = solvedChallenge()
    challenges.scoreBoardChallenge = challenge as unknown as typeof challenges.scoreBoardChallenge

    sendNotification(challenge, true)
    assert.equal(noticesFor(challenge.key).length, 1)

    const flag = noticesFor(challenge.key)[0].flag
    const index = notifications.findIndex(notification => notification.flag === flag)
    assert.ok(index > -1)
    notifications.splice(index, 1)
    assert.equal(noticesFor(challenge.key).length, 0)

    sendNotification(challenge, true)
    assert.equal(noticesFor(challenge.key).length, 1)
    sendNotification(challenge, true)
    assert.equal(noticesFor(challenge.key).length, 1)
  })
})
