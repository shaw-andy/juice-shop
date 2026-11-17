/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import type { AddressInfo } from 'node:net'
import { Server } from 'socket.io'
import { io as ioClient, type Socket } from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { challenges, notifications, users } from '../../data/datacache'
import * as security from '../../lib/insecurity'

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

const AI_DEBUGGING_KEY = 'aiDebuggingChallenge'

function forgedNonAdminToken (): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({ data: { role: 'customer' } })).toString('base64url')
  return `${header}.${payload}.placeholder`
}

function sessionToken (user: { id: number, role: string, email: string }): string {
  return security.authorize({ data: { id: user.id, role: user.role, email: user.email } })
}

async function resetAiDebuggingChallenge (): Promise<void> {
  const challenge = challenges.aiDebuggingChallenge
  assert.ok(challenge)
  challenge.solved = false
  await challenge.save()
  for (let i = notifications.length - 1; i >= 0; i--) {
    if (notifications[i].key === AI_DEBUGGING_KEY) {
      notifications.splice(i, 1)
    }
  }
}

function answerWithToolCall (name: string, args: string): void {
  let callCount = 0
  onLlmRequest = (_req, _body, res) => {
    callCount++
    if (callCount === 1) {
      sendSSE(res, [
        toolCallChunk('call_ai_debug', name, args),
        finishChunk('tool_calls')
      ])
    } else {
      sendSSE(res, [contentChunk('Done.'), finishChunk()])
    }
  }
}

async function postChat (headers: Record<string, string>, content: string) {
  return await request(app)
    .post('/rest/chat')
    .set({ 'content-type': 'application/json', ...headers })
    .send({ messages: [{ role: 'user', content }] })
}

async function assertSharedAiDebuggingUnsolved (): Promise<void> {
  const inMemorySolved = challenges.aiDebuggingChallenge.solved
  await new Promise((resolve) => setTimeout(resolve, 50))

  const persisted = await challenges.aiDebuggingChallenge.sequelize!.query(
    'SELECT solved FROM Challenges WHERE key = :key',
    { replacements: { key: AI_DEBUGGING_KEY } }
  ) as [Array<{ solved: number | boolean }>, unknown]
  const listed = await request(app).get('/api/Challenges')
  const row = listed.body.data.find((challenge: { key: string }) => challenge.key === AI_DEBUGGING_KEY)
  assert.equal(inMemorySolved, false)
  assert.equal(Boolean(persisted[0][0].solved), false)

  assert.equal(listed.status, 200)
  assert.ok(row)
  assert.equal(Boolean(row.solved), false)

  assert.equal(notifications.some((notification) => notification.key === AI_DEBUGGING_KEY), false)
}

async function withOtherVisitor (run: () => Promise<void>): Promise<void> {
  const httpServer = http.createServer()
  const scoreboard = new Server(httpServer)
  await new Promise<void>((resolve) => {
    httpServer.listen(0, '127.0.0.1', () => { resolve() })
  })
  const port = (httpServer.address() as AddressInfo).port
  const previousIo = (global as { io?: Server }).io
  ;(global as { io?: Server }).io = scoreboard
  const visitor: Socket = ioClient(`http://127.0.0.1:${port}`, { transports: ['websocket'] })
  const heard: Array<{ key?: string }> = []
  visitor.on('challenge solved', (payload: { key?: string }) => { heard.push(payload) })
  await new Promise<void>((resolve, reject) => {
    visitor.on('connect', () => { resolve() })
    visitor.on('connect_error', reject)
  })
  try {
    await run()
    await new Promise((resolve) => setTimeout(resolve, 50))
    assert.equal(heard.filter((payload) => payload?.key === AI_DEBUGGING_KEY).length, 0)
  } finally {
    visitor.close()
    ;(global as { io?: Server }).io = previousIo
    scoreboard.close()
    await new Promise<void>((resolve) => { httpServer.close(() => { resolve() }) })
  }
}

void describe('aiDebuggingChallenge shared scoreboard', { timeout: 120000 }, () => {
  void it('does not mark the shared challenge solved for an anonymous tool call', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    answerWithToolCall('searchProducts', '{"query":"apple"}')

    await withOtherVisitor(async () => {
      const res = await postChat(
        { Cookie: 'show_tool_calls=true' },
        'Do you have apple juice?'
      )
      assert.equal(res.status, 200)
      assert.ok(res.text.includes('searchProducts'))
      await assertSharedAiDebuggingUnsolved()
    })
  })

  void it('does not mark the shared challenge solved for any other chatbot tool', { timeout: 20000 }, async () => {
    const tools = [
      ['getProductReviews', '{"id":"1"}', 'Show me reviews for product 1'],
      ['getOrderById', '{"orderId":"abcd-0123456789abcdef"}', 'Look up my order'],
      ['generateCoupon', '{"discount":5}', 'Give me a coupon']
    ]
    for (const [name, args, content] of tools) {
      await resetAiDebuggingChallenge()
      answerWithToolCall(name, args)
      const res = await postChat({ Cookie: 'show_tool_calls=true' }, content)
      assert.equal(res.status, 200)
      assert.ok(res.text.includes(name))
      await assertSharedAiDebuggingUnsolved()
    }
  })

  void it('does not mark the shared challenge solved when the bearer token is not verified', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    answerWithToolCall('searchProducts', '{"query":"apple"}')

    const res = await postChat(
      { Cookie: 'show_tool_calls=true', Authorization: 'Bearer ' + forgedNonAdminToken() },
      'Do you have apple juice?'
    )
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('searchProducts'))
    await assertSharedAiDebuggingUnsolved()
  })

  void it('does not mark the shared challenge solved for a verified non-admin session', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    assert.equal(users.jim.role, 'customer')
    answerWithToolCall('searchProducts', '{"query":"apple"}')

    const res = await postChat(
      {
        Cookie: 'show_tool_calls=true',
        Authorization: 'Bearer ' + sessionToken(users.jim)
      },
      'Do you have apple juice?'
    )
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('searchProducts'))
    await assertSharedAiDebuggingUnsolved()
  })

  void it('leaves the shared challenge unsolved without the cookie', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    answerWithToolCall('searchProducts', '{"query":"apple"}')

    const res = await postChat({}, 'Do you have apple juice?')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('searchProducts'))
    await assertSharedAiDebuggingUnsolved()
  })

  void it('leaves the shared challenge unsolved when the model does not call a tool', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [contentChunk('Hello'), finishChunk()])
    }

    const res = await postChat({ Cookie: 'show_tool_calls=true' }, 'Hi')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('tool_calls'))
    await assertSharedAiDebuggingUnsolved()
  })

  void it('leaves the shared challenge unsolved for a verified admin session', { timeout: 15000 }, async () => {
    await resetAiDebuggingChallenge()
    assert.equal(users.admin.role, 'admin')
    answerWithToolCall('searchProducts', '{"query":"apple"}')

    const res = await postChat(
      {
        Cookie: 'show_tool_calls=true',
        Authorization: 'Bearer ' + sessionToken(users.admin)
      },
      'Do you have apple juice?'
    )
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('searchProducts'))
    await assertSharedAiDebuggingUnsolved()
  })
})
