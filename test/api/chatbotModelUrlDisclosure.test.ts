/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import config from 'config'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const chatbotChallengeKeys = [
  'chatbotPromptInjectionChallenge',
  'chatbotGreedyInjectionChallenge',
  'aiDebuggingChallenge',
  'systemPromptExtractionChallenge'
]

let app: Express
let modelUrl: string

before(async () => {
  modelUrl = config.get<string>('application.chatBot.llmApiUrl')
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function llmDependencies (body: { data?: Array<{ key?: string, ChallengeDependencies?: Array<{ name?: string, key?: string }> }> }) {
  const challenges = (body.data ?? []).filter(challenge => chatbotChallengeKeys.includes(challenge.key ?? ''))
  return { challenges, dependencies: challenges.flatMap(challenge => challenge.ChallengeDependencies ?? []) }
}

void describe('chatbot model URL is not disclosed by public challenge records', () => {
  void it('GET /api/Challenges omits the configured model URL without a session', async () => {
    const res = await request(app).get('/api/Challenges')

    assert.equal(res.status, 200)
    const { challenges, dependencies } = llmDependencies(res.body)
    assert.equal(challenges.length, chatbotChallengeKeys.length)
    const llmDeps = dependencies.filter(dependency => dependency.name === 'LLM API')
    assert.equal(llmDeps.length, chatbotChallengeKeys.length)
    for (const dependency of llmDeps) {
      assert.notEqual(dependency.key, modelUrl)
      assert.equal(JSON.stringify(dependency).includes(modelUrl), false)
    }
    assert.equal(JSON.stringify(res.body).includes(modelUrl), false)
  })

  void it('GET /api/Challenges/ with a trailing slash omits the configured model URL', async () => {
    const res = await request(app).get('/api/Challenges/')

    assert.equal(res.status, 200)
    assert.equal(JSON.stringify(res.body).includes(modelUrl), false)
    const { dependencies } = llmDependencies(res.body)
    assert.ok(dependencies.some(dependency => dependency.name === 'LLM API'))
  })

  void it('GET /api/Challenges filtered by challenge key omits the configured model URL', async () => {
    const res = await request(app).get('/api/Challenges').query({ key: 'chatbotPromptInjectionChallenge' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].key, 'chatbotPromptInjectionChallenge')
    const llmDep = (res.body.data[0].ChallengeDependencies ?? []).find((dependency: { name?: string }) => dependency.name === 'LLM API')
    assert.ok(llmDep)
    assert.notEqual(llmDep.key, modelUrl)
    assert.equal(JSON.stringify(res.body).includes(modelUrl), false)
  })

  void it('GET /api/Challenges filtered by challenge name omits the configured model URL', async () => {
    const res = await request(app).get('/api/Challenges').query({ name: 'System Prompt Extraction' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    const llmDep = (res.body.data[0].ChallengeDependencies ?? []).find((dependency: { name?: string }) => dependency.name === 'LLM API')
    assert.ok(llmDep)
    assert.notEqual(llmDep.key, modelUrl)
    assert.equal(JSON.stringify(res.body).includes(modelUrl), false)
  })

  void it('GET /rest/admin/application-configuration still omits chatBot.llmApiUrl', async () => {
    const res = await request(app).get('/rest/admin/application-configuration')

    assert.equal(res.status, 200)
    assert.equal(Object.hasOwn(res.body.config.application.chatBot, 'llmApiUrl'), false)
    assert.equal(JSON.stringify(res.body).includes(modelUrl), false)
  })
})
