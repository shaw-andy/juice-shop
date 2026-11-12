/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const MOCK_LLM_PORT = 43210

let app: Express
let mockServer: http.Server
let onLlmRequest: (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void = (_req, _body, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end('{}')
}

function sseData (obj: object): string {
  return `data: ${JSON.stringify(obj)}\n\n`
}

function contentChunk (content: string): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{ index: 0, delta: { content }, finish_reason: null }]
  }
}

function toolCallChunk (id: string, name: string, args: string): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{
      index: 0,
      delta: {
        tool_calls: [{ index: 0, id, type: 'function', function: { name, arguments: args } }]
      },
      finish_reason: null
    }]
  }
}

function finishChunk (reason: string = 'stop'): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{ index: 0, delta: {}, finish_reason: reason }]
  }
}

function sendSSE (res: http.ServerResponse, chunks: object[]): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'close'
  })
  for (const chunk of chunks) {
    res.write(sseData(chunk))
  }
  res.write('data: [DONE]\n\n')
  res.end()
}

before(async () => {
  await new Promise<void>((resolve) => {
    mockServer = http.createServer((req, res) => {
      // Prevent keep-alive: each response closes the connection so the AI SDK's
      // connection pool does not retain sockets that could outlive the test suite.
      res.setHeader('Connection', 'close')
      let body = ''
      req.on('data', (chunk: Buffer) => { body += chunk.toString() })
      req.on('end', () => {
        // Startup precondition checks (validatePreconditions) probe `/v1` and
        // `/v1/models` with GET requests. Don't route those through onLlmRequest,
        // which would call JSON.parse('') on the empty body and throw.
        if (req.method !== 'POST' || !(req.url?.includes('chat/completions') ?? false)) {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end('{"data":[]}')
          return
        }
        onLlmRequest(req, body, res)
      })
    })
    mockServer.keepAliveTimeout = 0
    mockServer.listen(MOCK_LLM_PORT, resolve)
  })
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(async () => {
  await new Promise<void>((resolve) => {
    if (!mockServer?.listening) {
      resolve()
      return
    }
    // Destroy all open sockets immediately so req.on('end') callbacks from
    // lingering keep-alive connections cannot fire after the suite ends and
    // produce uncaught SyntaxError exceptions from JSON.parse('').
    mockServer.closeAllConnections()
    mockServer.close(() => { resolve() })
  })
})

void describe('/rest/chat', { timeout: 120000 }, () => {
  void it('POST returns streamed text content as SSE events', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('Hello'),
        contentChunk(' there!'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hi' }] })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/event-stream'))
    assert.ok(res.text.includes('Hello'))
    assert.ok(res.text.includes(' there!'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST sets correct SSE response headers', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [contentChunk('Hi'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hello' }] })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/event-stream'))
    assert.ok(res.headers['cache-control']?.includes('no-cache'))
  })

  void it('POST includes system prompt and user messages in LLM request', { timeout: 15000 }, async () => {
    let parsedBody: any
    onLlmRequest = (_req, body, res) => {
      parsedBody = JSON.parse(body)
      sendSSE(res, [contentChunk('I am Juicy!'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'What is your name?' }] })

    assert.equal(res.status, 200)
    assert.equal(parsedBody.messages[0].role, 'system')
    assert.ok(parsedBody.messages[0].content.includes('Juicy'))
    assert.equal(parsedBody.messages[1].role, 'user')
    assert.equal(parsedBody.messages[1].content, 'What is your name?')
  })

  void it('POST sends searchProducts tool definition to LLM', { timeout: 15000 }, async () => {
    let parsedBody: any
    onLlmRequest = (_req, body, res) => {
      parsedBody = JSON.parse(body)
      sendSSE(res, [contentChunk('We have many products!'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'What products do you have?' }] })

    assert.equal(res.status, 200)
    assert.ok(parsedBody.tools)
    assert.equal(parsedBody.tools.length, 4)
    const toolNames = parsedBody.tools.map((t: { function: { name: string } }) => t.function.name)
    assert.ok(toolNames.includes('searchProducts'))
    assert.ok(toolNames.includes('generateCoupon'))
    assert.ok(toolNames.includes('getOrderById'))
  })

  void it('POST handles searchProducts tool call and returns follow-up response', { timeout: 15000 }, async () => {
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_abc', 'searchProducts', '{"query":"apple"}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        const toolMsg = parsed.messages.find((m: { role: string }) => m.role === 'tool')
        assert.ok(toolMsg)
        assert.equal(toolMsg.tool_call_id, 'call_abc')
        assert.ok(toolMsg.content.includes('Apple Juice'))
        sendSSE(res, [
          contentChunk('We have Apple Juice (1000ml) for $1.99!'),
          finishChunk()
        ])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Do you have apple juice?' }] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('Apple Juice'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST handles LLM API error gracefully', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: { message: 'Internal server error' } }))
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hi' }] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('error'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST with empty messages returns error SSE stream', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('How can I help you?'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('error'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST includes authenticated user name in system prompt', { timeout: 15000 }, async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    let parsedBody: any
    onLlmRequest = (_req, body, res) => {
      parsedBody = JSON.parse(body)
      sendSSE(res, [contentChunk('Hi!'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
      .send({ messages: [{ role: 'user', content: 'Hi' }] })

    assert.equal(res.status, 200)
    assert.ok(parsedBody.messages[0].content.includes('bkimminich'))
  })

  void it('POST handles getProductReviews tool call by returning matching reviews', { timeout: 15000 }, async () => {
    let toolResult: string | undefined
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_rev', 'getProductReviews', '{"id":"1"}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        toolResult = parsed.messages.find((m: { role: string }) => m.role === 'tool')?.content
        sendSSE(res, [contentChunk('Here are the reviews.'), finishChunk()])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Show me reviews for product 1' }] })

    assert.equal(res.status, 200)
    assert.ok(toolResult !== undefined)
  })

  void it('POST handles getOrderById tool call by reporting unauthenticated customer', { timeout: 15000 }, async () => {
    let toolResult: string | undefined
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_ord', 'getOrderById', '{"orderId":"abcd-0123456789abcdef"}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        toolResult = parsed.messages.find((m: { role: string }) => m.role === 'tool')?.content
        sendSSE(res, [contentChunk('Done.'), finishChunk()])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Look up my order' }] })

    assert.equal(res.status, 200)
    assert.ok(toolResult?.includes('Customer not authenticated'))
  })

  void it('POST handles getOrderById tool call by reporting order not found for authenticated customer', { timeout: 15000 }, async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    let toolResult: string | undefined
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_ord2', 'getOrderById', '{"orderId":"abcd-9999999999999999"}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        toolResult = parsed.messages.find((m: { role: string }) => m.role === 'tool')?.content
        sendSSE(res, [contentChunk('Done.'), finishChunk()])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
      .send({ messages: [{ role: 'user', content: 'Look up my order' }] })

    assert.equal(res.status, 200)
    assert.ok(toolResult?.includes('Order not found'))
  })

  void it('POST handles generateCoupon tool call and includes coupon code in tool response', { timeout: 15000 }, async () => {
    let toolResult: string | undefined
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_cpn', 'generateCoupon', '{"discount":5}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        toolResult = parsed.messages.find((m: { role: string }) => m.role === 'tool')?.content
        sendSSE(res, [contentChunk('Here is your coupon.'), finishChunk()])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Give me a coupon' }] })

    assert.equal(res.status, 200)
    assert.ok(toolResult)
    const parsed = JSON.parse(toolResult)
    assert.equal(parsed.discount, 5)
    assert.ok(parsed.couponCode !== undefined)
  })

  void it('POST response SSE data lines contain valid JSON', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('Test message'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Test' }] })

    assert.equal(res.status, 200)
    const dataLines = res.text.split('\n').filter((l: string) => l.startsWith('data: '))
    assert.ok(dataLines.length >= 2)
    for (const line of dataLines) {
      const data = line.slice(6)
      if (data === '[DONE]') continue
      const parsed = JSON.parse(data)
      assert.ok(parsed.choices)
      if (parsed.choices[0].finish_reason) continue
      assert.ok(parsed.choices[0].delta)
    }
  })
})

const MAX_CHAT_MESSAGES = 10
const MAX_CHAT_MESSAGE_CHARS = 2000
const MAX_CHAT_REQUESTS_PER_CALLER = 5

interface ObservedModelRequest {
  messages?: Array<{ role?: string, content?: unknown }>
  tools?: Array<{ function?: { name?: string } }>
}

function recordModelRequest (body: string, seen: ObservedModelRequest[]): void {
  try {
    seen.push(JSON.parse(body) as ObservedModelRequest)
  } catch {
    seen.push({ messages: [{ role: 'unparsed', content: body.slice(0, 200) }] })
  }
}

function toolResultSnippets (seen: ObservedModelRequest[]): string[] {
  const snippets: string[] = []
  for (const requestBody of seen) {
    for (const message of requestBody.messages ?? []) {
      if (message.role === 'tool' && typeof message.content === 'string') {
        snippets.push(message.content.slice(0, 160))
      }
    }
  }
  return snippets.slice(-4)
}

function userContents (seen: ObservedModelRequest[]): string[] {
  const contents: string[] = []
  for (const requestBody of seen) {
    for (const message of requestBody.messages ?? []) {
      if (message.role === 'user' && typeof message.content === 'string') {
        contents.push(message.content)
      }
    }
  }
  return contents
}

void describe('POST /rest/chat refuses before invoking the model', { timeout: 120000 }, () => {
  const password = 'placeholder'

  void it('does not wait on the model for a request with no session', { timeout: 15000 }, async () => {
    const seen: ObservedModelRequest[] = []
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      setTimeout(() => {
        sendSSE(res, [contentChunk('late'), finishChunk()])
      }, 1500)
    }

    const started = Date.now()
    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'anonymous-wait' }] })
    const elapsed = Date.now() - started

    assert.deepEqual(
      { status: res.status, modelCalls: seen.length, elapsedUnderOneSecond: elapsed < 1000 },
      { status: 401, modelCalls: 0, elapsedUnderOneSecond: true }
    )
  })

  void it('does not invoke the model for a bearer token that is not a session', { timeout: 15000 }, async () => {
    const seen: ObservedModelRequest[] = []
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      sendSSE(res, [contentChunk('nope'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json', Authorization: 'Bearer placeholder-token' })
      .send({ messages: [{ role: 'user', content: 'invalid-session' }] })

    assert.deepEqual(
      { status: res.status, modelCalls: seen.length },
      { status: 401, modelCalls: 0 }
    )
  })

  void it('does not run repeated catalog and order tool steps without a session', { timeout: 20000 }, async () => {
    const seen: ObservedModelRequest[] = []
    let step = 0
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      step++
      if (step > 12) {
        sendSSE(res, [contentChunk('stop'), finishChunk()])
        return
      }
      const toolName = ['searchProducts', 'getOrderById', 'getProductReviews', 'generateCoupon'][(step - 1) % 4]
      const args = toolName === 'searchProducts'
        ? '{"query":"juice"}'
        : toolName === 'getOrderById'
          ? '{"orderId":"abcd-0123456789abcdef"}'
          : toolName === 'getProductReviews'
            ? '{"id":"1"}'
            : '{"discount":5}'
      sendSSE(res, [
        toolCallChunk(`call_${step}`, toolName, args),
        finishChunk('tool_calls')
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Look up juice and my order' }] })

    assert.deepEqual(
      {
        status: res.status,
        modelCalls: seen.length,
        toolsOffered: (seen[0]?.tools ?? []).map(tool => tool.function?.name),
        toolResults: toolResultSnippets(seen)
      },
      { status: 401, modelCalls: 0, toolsOffered: [], toolResults: [] }
    )
  })

  void it('rejects more than 10 messages for a signed-in caller before the model', { timeout: 15000 }, async () => {
    const email = 'chat-too-many@juice-sh.op'
    await register(app, { email, password })
    const { token } = await login(app, { email, password })
    const seen: ObservedModelRequest[] = []
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      sendSSE(res, [contentChunk('ok'), finishChunk()])
    }
    const messages = Array.from({ length: MAX_CHAT_MESSAGES + 1 }, (_unused, index) => ({
      role: 'user',
      content: `message-${index}`
    }))

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
      .send({ messages })

    assert.deepEqual(
      { status: res.status, modelCalls: seen.length },
      { status: 400, modelCalls: 0 }
    )
  })

  void it('rejects a message longer than 2000 characters before the model', { timeout: 15000 }, async () => {
    const email = 'chat-too-long@juice-sh.op'
    await register(app, { email, password })
    const { token } = await login(app, { email, password })
    const seen: ObservedModelRequest[] = []
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      sendSSE(res, [contentChunk('ok'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
      .send({ messages: [{ role: 'user', content: 'x'.repeat(MAX_CHAT_MESSAGE_CHARS + 1) }] })

    assert.deepEqual(
      { status: res.status, modelCalls: seen.length },
      { status: 400, modelCalls: 0 }
    )
  })

  void it('caps model calls at 5 per signed-in caller and does not share or reset that cap', { timeout: 20000 }, async () => {
    const emailA = 'chat-limit-a@juice-sh.op'
    const emailB = 'chat-limit-b@juice-sh.op'
    await register(app, { email: emailA, password })
    await register(app, { email: emailB, password })
    const callerA = await login(app, { email: emailA, password })
    const callerB = await login(app, { email: emailB, password })
    const seen: ObservedModelRequest[] = []
    onLlmRequest = (_req, body, res) => {
      recordModelRequest(body, seen)
      sendSSE(res, [contentChunk('ok'), finishChunk()])
    }

    const burst = await Promise.all(Array.from({ length: MAX_CHAT_REQUESTS_PER_CALLER + 3 }, (_unused, index) => {
      return request(app)
        .post('/rest/chat')
        .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + callerA.token })
        .send({ messages: [{ role: 'user', content: `caller-a-${index}` }], userId: `rotated-${index}` })
    }))
    const statuses = burst.map(res => res.status).sort((left, right) => left - right)

    const bypass = await request(app)
      .post('/rest/chat')
      .set({
        'content-type': 'application/json',
        Authorization: 'Bearer ' + callerA.token,
        'X-Forwarded-For': '203.0.113.10'
      })
      .send({ messages: [{ role: 'user', content: 'caller-a-bypass' }], userId: 'someone-else' })

    const otherCaller = await request(app)
      .post('/rest/chat')
      .set({
        'content-type': 'application/json',
        Authorization: 'Bearer ' + callerB.token,
        'X-Forwarded-For': '203.0.113.10'
      })
      .send({ messages: [{ role: 'user', content: 'caller-b-allowed' }], userId: emailA })

    const contents = userContents(seen)
    const callerAReached = contents.filter(content => /^caller-a-\d+$/.test(content)).sort()
    assert.deepEqual(
      {
        statuses,
        bypassStatus: bypass.status,
        otherCallerStatus: otherCaller.status,
        modelCalls: seen.length,
        callerAReached: callerAReached.length,
        bypassReachedModel: contents.includes('caller-a-bypass'),
        callerBContents: contents.filter(content => content.startsWith('caller-b-')),
        callerAReachedAreUnique: new Set(callerAReached).size
      },
      {
        statuses: [200, 200, 200, 200, 200, 429, 429, 429],
        bypassStatus: 429,
        otherCallerStatus: 200,
        modelCalls: MAX_CHAT_REQUESTS_PER_CALLER + 1,
        callerAReached: MAX_CHAT_REQUESTS_PER_CALLER,
        bypassReachedModel: false,
        callerBContents: ['caller-b-allowed'],
        callerAReachedAreUnique: MAX_CHAT_REQUESTS_PER_CALLER
      }
    )
  })
})
