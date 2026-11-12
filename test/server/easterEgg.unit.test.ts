/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { type Challenge } from '@juice-shop/data/types'
import { serveEasterEgg, serveEasterEggAsset } from '../../routes/easterEgg'

void describe('easterEgg', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { sendFile: mock.fn() }
    req = {}
    next = mock.fn()
    save = () => ({
      then () { }
    })
  })

  void it('should serve /frontend/dist/private/threejs-demo.html', () => {
    serveEasterEgg()(req, res)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /frontend[/\\]dist[/\\]private[/\\]threejs-demo\.html/)
  })

  void it('should solve "easterEggLevelTwoChallenge"', () => {
    challenges.easterEggLevelTwoChallenge = { solved: false, save } as unknown as Challenge

    serveEasterEgg()(req, res)

    assert.equal(challenges.easterEggLevelTwoChallenge.solved, true)
  })

  void it('should serve assets used by the planet demo', () => {
    req.params = { file: 'three.js' }

    serveEasterEggAsset()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /frontend[/\\]dist[/\\]private[/\\]three\.js$/)
  })

  for (const file of ['JuiceShop_Wallpaper_1920x1080_VR.jpg', 'threejs-demo.html', '../private/three.js', 'THREE.JS']) {
    void it(`should not serve "${file}" as a planet demo asset`, () => {
      req.params = { file }

      serveEasterEggAsset()(req, res, next)

      assert.equal(res.sendFile.mock.calls.length, 0)
      assert.equal(next.mock.calls.length, 1)
    })
  }
})
