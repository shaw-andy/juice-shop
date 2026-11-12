/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { safeLoad } from 'js-yaml'

const repoRoot = path.resolve(__dirname, '../..')
const nodeBin = process.execPath
const replacementPassword = 'replacement-password'
const placeholderPassword = 'placeholder-password'
const placeholderAnswer = 'placeholder-answer'
const placeholderReset = 'placeholder-reset'
const reviewCreated = 'replica-review-created'
const reviewUpdated = 'replica-review-updated'
const newUserEmail = 'replica-writer@example.test'

void describe('production tasks share shop data', () => {
  void it('keeps accounts, wallets, baskets, orders, and reviews together when more than one task is running', async (t) => {
    const desiredCount = readDesiredCount()
    if (desiredCount <= 1) {
      assert.equal(desiredCount, 1)
      return
    }

    const layout = readContainerLayout()
    const shared = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-shared-'))
    const taskA = materializeTask(layout)
    const taskB = materializeTask(layout)
    const children: ChildProcess[] = []
    t.after(() => {
      for (const child of children) stop(child)
      fs.rmSync(shared, { recursive: true, force: true })
      fs.rmSync(taskA.root, { recursive: true, force: true })
      fs.rmSync(taskB.root, { recursive: true, force: true })
    })

    const portA = await freePort()
    const portB = await freePort()
    const serverA = startTask(taskA, shared, layout.mountRelative, portA)
    const serverB = startTask(taskB, shared, layout.mountRelative, portB)
    children.push(serverA.child, serverB.child)

    await waitReady(serverA)
    await waitReady(serverB)

    const failures: string[] = []
    const customer = seededCustomer()
    const loginA = await login(serverA.base, customer.email, customer.password)
    const loginB = await login(serverB.base, customer.email, customer.password)
    if (loginA.token == null || loginB.token == null) {
      failures.push('seeded customer could not log in on both tasks before any write')
      assert.deepEqual(failures, [])
      return
    }

    const changed = await http(serverA.base, 'GET', '/rest/user/change-password?current=' + encodeURIComponent(customer.password) + '&new=' + encodeURIComponent(replacementPassword) + '&repeat=' + encodeURIComponent(replacementPassword), undefined, loginA.token)
    if (changed.status !== 200) failures.push('password change on the first task returned ' + changed.status)

    const oldOnB = await login(serverB.base, customer.email, customer.password)
    if (oldOnB.status !== 401) failures.push('password from before the change is still accepted by the other task')
    const newOnB = await login(serverB.base, customer.email, replacementPassword)
    if (newOnB.status !== 200) failures.push('password written on the first task is rejected by the other task')

    const beforeA = await walletBalance(serverA.base, loginA.token)
    const beforeB = await walletBalance(serverB.base, loginB.token)
    const added = await http(serverA.base, 'POST', '/api/BasketItems', {
      BasketId: loginA.bid,
      ProductId: 1,
      quantity: 4
    }, loginA.token)
    if (added.status !== 200) failures.push('adding a basket item on the first task returned ' + added.status)
    const userId = idFromToken(loginA.token)
    const checkout = await http(serverA.base, 'POST', '/rest/basket/' + loginA.bid + '/checkout', {
      UserId: userId,
      orderDetails: { paymentId: 'wallet' }
    }, loginA.token)
    const orderId = checkout.json?.orderConfirmation
    if (checkout.status !== 200 || typeof orderId !== 'string') failures.push('wallet checkout on the first task returned ' + checkout.status)

    const afterA = await walletBalance(serverA.base, loginA.token)
    const afterB = await walletBalance(serverB.base, loginB.token)
    if (afterA == null || afterA === beforeA) failures.push('wallet checkout did not debit the first task')
    if (afterB !== afterA) failures.push('wallet balance on the other task stayed at ' + String(beforeB) + ' after the debit')

    const basketB = await http(serverB.base, 'GET', '/rest/basket/' + loginA.bid, undefined, loginB.token)
    const quantities = basketQuantities(basketB.json)
    if (!quantities.includes(4)) failures.push('basket item written on the first task is missing on the other task')

    const tracked = await http(serverB.base, 'GET', '/rest/track-order/' + encodeURIComponent(String(orderId ?? '')))
    if (typeof tracked.json?.data?.[0]?.totalPrice !== 'number') failures.push('order inserted on the first task is missing on the other task')
    const history = await http(serverB.base, 'GET', '/rest/order-history', undefined, loginB.token)
    if (!JSON.stringify(history.json ?? {}).includes(String(orderId ?? 'missing-order'))) failures.push('order history on the other task does not list the order')

    const deluxe = await http(serverA.base, 'POST', '/rest/deluxe-membership', { paymentMode: 'wallet' }, loginA.token)
    if (deluxe.status !== 200) failures.push('wallet deluxe upgrade on the first task returned ' + deluxe.status)
    const afterDeluxeA = await walletBalance(serverA.base, loginA.token)
    const afterDeluxeB = await walletBalance(serverB.base, loginB.token)
    if (afterDeluxeB !== afterDeluxeA) failures.push('deluxe wallet debit is missing on the other task')
    const deluxeLogin = await login(serverB.base, customer.email, replacementPassword)
    const deluxeStatus = deluxeLogin.token == null
      ? { status: 0 }
      : await http(serverB.base, 'GET', '/rest/deluxe-membership', undefined, deluxeLogin.token)
    if (deluxeStatus.status !== 400) failures.push('deluxe role written on the first task is missing on the other task')

    const registered = await http(serverA.base, 'POST', '/api/Users', {
      email: newUserEmail,
      password: placeholderPassword,
      passwordRepeat: placeholderPassword
    })
    const newUserId = registered.json?.data?.id
    if (registered.status !== 201 || typeof newUserId !== 'number') failures.push('registration on the first task returned ' + registered.status)
    const answer = await http(serverA.base, 'POST', '/api/SecurityAnswers/', {
      UserId: newUserId,
      SecurityQuestionId: 1,
      answer: placeholderAnswer
    })
    if (answer.status !== 201) failures.push('security answer create on the first task returned ' + answer.status)
    const reset = await http(serverB.base, 'POST', '/rest/user/reset-password', {
      email: newUserEmail,
      answer: placeholderAnswer,
      new: placeholderReset,
      repeat: placeholderReset
    })
    if (reset.status !== 200) failures.push('security answer stored on the first task is not accepted by the other task')
    const newUserOnB = await login(serverB.base, newUserEmail, placeholderReset)
    if (newUserOnB.status !== 200) failures.push('account created on the first task cannot log in on the other task')

    const createdReview = await http(serverA.base, 'PUT', '/rest/products/1/reviews', {
      message: reviewCreated,
      author: newUserEmail
    })
    if (createdReview.status !== 201) failures.push('review create on the first task returned ' + createdReview.status)
    const reviewsOnA = await http(serverA.base, 'GET', '/rest/products/1/reviews')
    const reviewId = findReviewId(reviewsOnA.json, reviewCreated)
    if (reviewId == null) failures.push('review create did not store a review on the first task')
    const updatedReview = await http(serverA.base, 'PATCH', '/rest/products/reviews', {
      id: reviewId,
      message: reviewUpdated
    }, loginA.token)
    if (updatedReview.status !== 200) failures.push('review update on the first task returned ' + updatedReview.status)
    const liked = await http(serverA.base, 'POST', '/rest/products/reviews', { id: reviewId }, loginA.token)
    if (liked.status !== 200) failures.push('review like on the first task returned ' + liked.status)
    const reviewsOnB = await http(serverB.base, 'GET', '/rest/products/1/reviews')
    const sharedReview = findReview(reviewsOnB.json, reviewUpdated)
    if (sharedReview == null) failures.push('review written on the first task is missing on the other task')
    if (sharedReview != null && !(Number(sharedReview.likesCount) >= 1)) failures.push('review like written on the first task is missing on the other task')

    assert.deepEqual(failures, [])
  }, { timeout: 180000 })
})

function readDesiredCount () {
  const source = fs.readFileSync(path.join(repoRoot, 'terraform/variables.tf'), 'utf8')
  const block = source.split(/variable\s+"desired_count"/)[1]
  if (block == null) throw new Error('terraform/variables.tf has no desired_count variable')
  const ownBlock = block.split(/\nvariable\s+"/)[0]
  const match = ownBlock.match(/default\s*=\s*(-?\d+)/)
  if (match == null) throw new Error('desired_count default is not a literal number')
  return Number(match[1])
}

function readContainerLayout () {
  const terraform = fs.readFileSync(path.join(repoRoot, 'terraform/main.tf'), 'utf8')
  const mount = terraform.match(/sourceVolume\s*=\s*"sqlite-data"[\s\S]*?containerPath\s*=\s*"([^"]+)"/)
  if (mount == null) throw new Error('terraform/main.tf has no sqlite-data containerPath')
  const dockerfile = fs.readFileSync(path.join(repoRoot, 'infrastructure/Dockerfile'), 'utf8')
  const workdirs = [...dockerfile.matchAll(/^WORKDIR\s+(\S+)/gm)]
  if (workdirs.length === 0) throw new Error('infrastructure/Dockerfile has no WORKDIR')
  const workdir = workdirs[workdirs.length - 1][1]
  const mountRelative = path.relative(workdir, mount[1])
  if (mountRelative.startsWith('..') || path.isAbsolute(mountRelative)) {
    throw new Error('sqlite volume containerPath is outside the image WORKDIR')
  }
  return { workdir, mountRelative }
}

function seededCustomer () {
  const users = safeLoad(fs.readFileSync(path.join(repoRoot, 'data/static/users.yml'), 'utf8')) as Array<{
    key: string
    email: string
    password: string
    customDomain?: boolean
  }>
  const user = users.find((entry) => entry.key === 'test')
  if (user == null) throw new Error('static users file has no customer with key test')
  return { email: user.email, password: user.password }
}

function materializeTask (layout: { workdir: string }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-task-'))
  const appDir = path.join(root, layout.workdir.replace(/^\/+/, ''))
  fs.mkdirSync(appDir, { recursive: true })
  for (const name of fs.readdirSync(repoRoot)) {
    if (name === 'data' || name === '.git' || name === 'build' || name === 'frontend' || name === 'ftp' || name === 'logs' || name === 'node_modules') continue
    fs.symlinkSync(path.join(repoRoot, name), path.join(appDir, name))
  }
  fs.mkdirSync(path.join(appDir, 'data'), { recursive: true })
  for (const name of fs.readdirSync(path.join(repoRoot, 'data'))) {
    fs.symlinkSync(path.join(repoRoot, 'data', name), path.join(appDir, 'data', name))
  }
  fs.mkdirSync(path.join(appDir, 'ftp'), { recursive: true })
  fs.mkdirSync(path.join(appDir, 'logs'), { recursive: true })
  fs.mkdirSync(path.join(appDir, 'build'), { recursive: true })
  fs.writeFileSync(path.join(appDir, 'build/server.js'), '')
  const dist = path.join(appDir, 'frontend/dist/frontend')
  fs.mkdirSync(dist, { recursive: true })
  fs.writeFileSync(path.join(dist, 'index.html'), '<title>placeholder</title>\n<body class="placeholder-theme">\n"content": { "message": "m", "dismiss": "d", "link": "l", "href": "h" }\n')
  fs.writeFileSync(path.join(dist, 'styles.css'), '')
  fs.writeFileSync(path.join(dist, 'main.js'), '')
  fs.writeFileSync(path.join(dist, 'polyfills.js'), '')
  fs.writeFileSync(path.join(dist, 'hacking-instructor-stub.js'), '')
  fs.cpSync(path.join(repoRoot, 'frontend/src/assets'), path.join(dist, 'assets'), { recursive: true })
  return { root, appDir }
}

function startTask (task: { root: string, appDir: string }, sharedDir: string, mountRelative: string, port: number) {
  const mountPoint = path.join(task.appDir, mountRelative)
  fs.mkdirSync(mountPoint, { recursive: true })
  const scriptPath = path.join(task.appDir, 'start-task.sh')
  fs.writeFileSync(scriptPath, '#!/bin/sh\ncd /juice-shop\nexport PORT=' + String(port) + '\nexport NODE_ENV=production\nexec ' + shellQuote(nodeBin) + ' --import tsx /juice-shop/app.ts\n', { mode: 0o755 })
  const namespace = path.join(task.root, 'namespace')
  fs.mkdirSync(namespace, { recursive: true })
  const command = [
    'set -e',
    'ln -s usr/bin ' + shellQuote(path.join(namespace, 'bin')),
    'for d in /usr /lib /lib64 /etc /exec-daemon /agent; do',
    '  [ -e "$d" ] || continue',
    '  mkdir -p ' + shellQuote(namespace) + '"$d"',
    '  mount --bind "$d" ' + shellQuote(namespace) + '"$d"',
    'done',
    'mkdir -p ' + shellQuote(path.join(namespace, 'juice-shop')),
    'mount --bind ' + shellQuote(task.appDir) + ' ' + shellQuote(path.join(namespace, 'juice-shop')),
    'mkdir -p ' + shellQuote(path.join(namespace, 'juice-shop/node_modules')) + ' ' + shellQuote(path.join(namespace, 'juice-shop', mountRelative)),
    'mount --bind ' + shellQuote(path.join(repoRoot, 'node_modules')) + ' ' + shellQuote(path.join(namespace, 'juice-shop/node_modules')),
    'mount --bind ' + shellQuote(sharedDir) + ' ' + shellQuote(path.join(namespace, 'juice-shop', mountRelative)),
    'chroot ' + shellQuote(namespace) + ' /juice-shop/start-task.sh'
  ].join('\n')
  const log = { text: '' }
  const child = spawn('unshare', ['--user', '--map-root-user', '--mount', 'bash', '-c', command], {
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const append = (chunk: Buffer) => {
    log.text = (log.text + chunk.toString('utf8')).slice(-12000)
  }
  child.stdout?.on('data', append)
  child.stderr?.on('data', append)
  return { child, base: 'http://127.0.0.1:' + String(port), log }
}

async function waitReady (server: { child: ChildProcess, base: string, log: { text: string } }) {
  const deadline = Date.now() + 60000
  while (Date.now() < deadline) {
    if (server.child.exitCode != null) {
      throw new Error('task exited before it was ready\n' + server.log.text)
    }
    try {
      const res = await fetch(server.base + '/rest/admin/application-version')
      if (res.ok) return
    } catch {
      // the listener is not open yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error('task did not become ready\n' + server.log.text)
}

function stop (child: ChildProcess) {
  if (child.pid == null) return
  try {
    process.kill(-child.pid, 'SIGTERM')
  } catch {
    try {
      child.kill('SIGTERM')
    } catch {
      // the task has already exited
    }
  }
}

async function freePort () {
  const server = net.createServer()
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const address = server.address()
  if (address == null || typeof address === 'string') throw new Error('could not allocate a port')
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  return address.port
}

async function http (base: string, method: string, pathname: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['content-type'] = 'application/json'
  if (token != null) headers.authorization = 'Bearer ' + token
  const res = await fetch(base + pathname, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  })
  const text = await res.text()
  let json: any
  try {
    json = JSON.parse(text)
  } catch {
    json = undefined
  }
  return { status: res.status, json }
}

async function login (base: string, email: string, password: string) {
  const res = await http(base, 'POST', '/rest/user/login', { email, password })
  return {
    status: res.status,
    token: res.json?.authentication?.token as string | undefined,
    bid: res.json?.authentication?.bid as number | undefined
  }
}

async function walletBalance (base: string, token: string) {
  const res = await http(base, 'GET', '/rest/wallet/balance', undefined, token)
  return res.json?.data as number | undefined
}

function idFromToken (token: string) {
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
  return payload.data.id as number
}

function basketQuantities (json: any) {
  const products = json?.data?.Products
  if (!Array.isArray(products)) return []
  return products.map((product) => product?.BasketItem?.quantity).filter((quantity) => typeof quantity === 'number')
}

function findReview (json: any, message: string) {
  const reviews = json?.data
  if (!Array.isArray(reviews)) return undefined
  return reviews.find((review) => review?.message === message)
}

function findReviewId (json: any, message: string) {
  const review = findReview(json, message)
  return review?._id as string | undefined
}

function shellQuote (value: string) {
  return "'" + value.replace(/'/g, "'\\''") + "'"
}
