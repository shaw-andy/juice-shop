/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import jws from 'jws'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { UserModel } from '../../models/user'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'
import * as chat from '../../routes/chat'

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

const ORDER_PRODUCT = 'OrderLookupMarkerProduct'
const ORDER_ADDRESS_ID = 4815162342
const ORDER_TOTAL = 64.25
const ORDER_DELIVERY_PRICE = 2.75
const ORDER_ETA = 'eta-order-lookup'

function maskedCustomerEmail (email: string): string {
  return email.replace(/[aeiou]/gi, '*')
}

function bearerToken (payload: { data: { id: number } }, algorithm: 'HS256' | 'none'): string {
  return jws.sign({
    header: { alg: algorithm, typ: 'JWT' },
    payload,
    secret: crypto.randomBytes(32)
  })
}

interface OrderLookupProbe {
  status: number
  body: string
  systemPrompt?: string
  toolResults: string[]
}

function orderMarkers (): string[] {
  return [ORDER_PRODUCT, String(ORDER_ADDRESS_ID), String(ORDER_TOTAL), String(ORDER_DELIVERY_PRICE), ORDER_ETA]
}

function assertOrderHidden (probe: OrderLookupProbe, username: string): void {
  const disclosed = [probe.body, probe.systemPrompt ?? '', ...probe.toolResults].join('\n')
  for (const marker of orderMarkers()) {
    assert.equal(disclosed.includes(marker), false, `order detail ${marker} was disclosed`)
  }
  assert.equal(disclosed.includes(username), false, 'unverified token was treated as the customer')
}

function assertOrderVisible (probe: OrderLookupProbe): void {
  const disclosed = probe.toolResults.join('\n')
  for (const marker of orderMarkers()) {
    assert.equal(disclosed.includes(marker), true, `order detail ${marker} was not returned to the owner`)
  }
}

function armOrderLookup (orderId: string, beforeToolCall?: () => void): { probe: () => { systemPrompt?: string, toolResults: string[] } } {
  const toolResults: string[] = []
  let systemPrompt: string | undefined
  let callCount = 0
  onLlmRequest = (_req, body, res) => {
    callCount++
    const parsed = JSON.parse(body)
    if (callCount === 1) {
      systemPrompt = parsed.messages?.[0]?.content
      beforeToolCall?.()
      sendSSE(res, [
        toolCallChunk('call_order_lookup', 'getOrderById', JSON.stringify({ orderId })),
        finishChunk('tool_calls')
      ])
      return
    }
    const toolMsg = parsed.messages.find((message: { role: string }) => message.role === 'tool')
    const content = typeof toolMsg?.content === 'string' ? toolMsg.content : JSON.stringify(toolMsg?.content ?? '')
    toolResults.push(content)
    sendSSE(res, [contentChunk(content), finishChunk()])
  }
  return { probe: () => ({ systemPrompt, toolResults }) }
}

async function insertCustomerOrder (email: string, orderId: string): Promise<void> {
  await ordersCollection.insert({
    orderId,
    email: maskedCustomerEmail(email),
    addressId: ORDER_ADDRESS_ID,
    totalPrice: ORDER_TOTAL,
    deliveryPrice: ORDER_DELIVERY_PRICE,
    eta: ORDER_ETA,
    delivered: false,
    products: [{ name: ORDER_PRODUCT, price: ORDER_TOTAL, total: ORDER_TOTAL, quantity: 1 }]
  })
}

async function createCustomer (email: string, username: string): Promise<{ id: number, email: string, username: string }> {
  const user = await UserModel.create({ email, username, role: 'customer' })
  return { id: user.id, email: user.email, username: user.username ?? username }
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

  void describe('getOrderById customer identity', { concurrency: false }, () => {
    const victimEmail = 'victim.order.lookup@example.test'
    const victimUsername = 'victim-order-lookup'
    const otherEmail = 'other.customer.lookup@example.test'
    const otherUsername = 'other-customer-lookup'
    const victimOrderId = 'c0de-orderlookupvictim1'
    let victimId = 0
    let otherId = 0

    before(async () => {
      const victim = await createCustomer(victimEmail, victimUsername)
      const other = await createCustomer(otherEmail, otherUsername)
      victimId = victim.id
      otherId = other.id
      await insertCustomerOrder(victimEmail, victimOrderId)
    })

    void it('POST does not disclose an order when the bearer token signature is not the server signature', { timeout: 15000 }, async () => {
      const token = bearerToken({ data: { id: victimId } }, 'HS256')
      assert.equal(security.verify(token), false)
      const captured = armOrderLookup(victimOrderId)
      const res = await request(app)
        .post('/rest/chat')
        .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
        .send({ messages: [{ role: 'user', content: 'Look up order ' + victimOrderId }] })
      const capturedProbe = captured.probe()
      assertOrderHidden({
        status: res.status,
        body: res.text,
        systemPrompt: capturedProbe.systemPrompt,
        toolResults: capturedProbe.toolResults
      }, victimUsername)
    })

    void it('POST does not disclose an order when the bearer token is unsigned', { timeout: 15000 }, async () => {
      const token = bearerToken({ data: { id: victimId } }, 'none')
      const captured = armOrderLookup(victimOrderId)
      const res = await request(app)
        .post('/rest/chat')
        .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
        .send({ messages: [{ role: 'user', content: 'Look up order ' + victimOrderId }] })
      const capturedProbe = captured.probe()
      assertOrderHidden({
        status: res.status,
        body: res.text,
        systemPrompt: capturedProbe.systemPrompt,
        toolResults: capturedProbe.toolResults
      }, victimUsername)
    })

    void it('POST does not disclose an order when a later read of the same header is an unverified user id', { timeout: 15000 }, async () => {
      const authorized = security.authorize({ data: { id: otherId } })
      const unverified = bearerToken({ data: { id: victimId } }, 'HS256')
      assert.equal(security.verify(unverified), false)
      let useUnverified = false
      const captured = armOrderLookup(victimOrderId, () => { useUnverified = true })
      const response = await invokeChat(() => useUnverified ? unverified : authorized)
      const capturedProbe = captured.probe()
      assertOrderHidden({
        status: response.status,
        body: response.body,
        systemPrompt: capturedProbe.systemPrompt,
        toolResults: capturedProbe.toolResults
      }, victimUsername)
    })

    void it('POST returns the order when the bearer token is signed for that customer', { timeout: 15000 }, async () => {
      const token = security.authorize({ data: { id: victimId } })
      const captured = armOrderLookup(victimOrderId)
      const res = await request(app)
        .post('/rest/chat')
        .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
        .send({ messages: [{ role: 'user', content: 'Look up order ' + victimOrderId }] })
      assertOrderVisible({
        status: res.status,
        body: res.text,
        systemPrompt: captured.probe().systemPrompt,
        toolResults: captured.probe().toolResults
      })
    })

    void it('POST does not return an order signed in as a different customer', { timeout: 15000 }, async () => {
      const token = security.authorize({ data: { id: otherId } })
      const captured = armOrderLookup(victimOrderId)
      const res = await request(app)
        .post('/rest/chat')
        .set({ 'content-type': 'application/json', Authorization: 'Bearer ' + token })
        .send({ messages: [{ role: 'user', content: 'Look up order ' + victimOrderId }] })
      const disclosed = captured.probe().toolResults.join('\n') + res.text
      for (const marker of orderMarkers()) {
        assert.equal(disclosed.includes(marker), false, `order detail ${marker} was disclosed to another customer`)
      }
      assert.equal(captured.probe().toolResults.some(result => result.includes('Order does not belong')), true)
    })
  })
})

async function invokeChat (token: () => string): Promise<{ status: number, body: string }> {
  let status = 200
  let body = ''
  const res = {
    setHeader () { return undefined },
    flushHeaders () { return undefined },
    write (chunk: string) { body += chunk; return true },
    end (chunk?: string) { if (chunk != null) body += chunk },
    status (code: number) { status = code; return this },
    json (payload: unknown) { body = JSON.stringify(payload); return this },
    send (payload?: unknown) {
      if (payload != null) body = typeof payload === 'string' ? payload : JSON.stringify(payload)
      return this
    },
    cookie () { return this }
  }
  const req = {
    headers: {
      get authorization () { return 'Bearer ' + token() }
    },
    body: { messages: [{ role: 'user', content: 'Look up my order' }] },
    cookies: {}
  }
  await chat.chat()(req as any, res as any)
  return { status, body }
}
