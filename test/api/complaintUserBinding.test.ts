/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { ComplaintModel } from '../../models/complaint'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

let app: Express

const placeholderPassword = 'placeholder-password'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

interface Session {
  id: number
  token: string
  email: string
}

function bearer (token: string) {
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

async function openSession (email: string): Promise<Session> {
  const registered = await register(app, { email, password: placeholderPassword })
  assert.equal(registered.status, 201)
  assert.equal(typeof registered.body.data.id, 'number')
  const authentication = await login(app, { email, password: placeholderPassword })
  return { id: registered.body.data.id, token: authentication.token, email }
}

async function openAdminSession (email: string): Promise<Session> {
  const session = await openSession(email)
  await UserModel.update({ role: security.roles.admin }, { where: { id: session.id } })
  const authentication = await login(app, { email, password: placeholderPassword })
  const payload = security.decode(authentication.token)
  assert.equal(payload?.data?.role, security.roles.admin)
  return { id: session.id, token: authentication.token, email }
}

async function storedUserId (message: string) {
  const stored = await ComplaintModel.findOne({ where: { message } })
  assert.ok(stored)
  return Number(stored.UserId)
}

void describe('complaint user binding', () => {
  void it('stores a complaint under the authenticated caller when the body names another user', async () => {
    const actor = await openSession('complaint-actor@example.test')
    const victim = await openSession('complaint-victim@example.test')
    const message = 'complaint-binding-body-user-id'

    const res = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: victim.id })

    assert.equal(res.status, 201)
    assert.equal(Number(res.body.data.UserId), actor.id)
    assert.equal(res.body.data.message, message)
    assert.equal(await storedUserId(message), actor.id)
  })

  void it('stores a complaint under the authenticated caller when the body user id is a string', async () => {
    const actor = await openSession('complaint-actor-string@example.test')
    const victim = await openSession('complaint-victim-string@example.test')
    const message = 'complaint-binding-string-user-id'

    const res = await request(app)
      .post('/api/Complaints/')
      .set(bearer(actor.token))
      .send({ message, UserId: String(victim.id) })

    assert.equal(res.status, 201)
    assert.equal(Number(res.body.data.UserId), actor.id)
    assert.equal(await storedUserId(message), actor.id)
  })

  void it('stores a complaint under the authenticated caller when the body omits or nulls the user id', async () => {
    const actor = await openSession('complaint-actor-omitted@example.test')
    const omitted = 'complaint-binding-omitted-user-id'
    const nulled = 'complaint-binding-null-user-id'

    const omittedRes = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message: omitted })
    const nulledRes = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message: nulled, UserId: null })

    assert.equal(omittedRes.status, 201)
    assert.equal(nulledRes.status, 201)
    assert.equal(Number(omittedRes.body.data.UserId), actor.id)
    assert.equal(Number(nulledRes.body.data.UserId), actor.id)
    assert.equal(await storedUserId(omitted), actor.id)
    assert.equal(await storedUserId(nulled), actor.id)
  })

  void it('stores an administrator complaint under that administrator when the body names another user', async () => {
    const admin = await openAdminSession('complaint-admin@example.test')
    const victim = await openSession('complaint-admin-victim@example.test')
    const message = 'complaint-binding-admin-body-user-id'

    const res = await request(app)
      .post('/api/Complaints')
      .set(bearer(admin.token))
      .send({ message, UserId: victim.id })

    assert.equal(res.status, 201)
    assert.equal(Number(res.body.data.UserId), admin.id)
    assert.equal(await storedUserId(message), admin.id)
  })

  void it('does not return another user complaint to the named user', async () => {
    const actor = await openSession('complaint-reader-actor@example.test')
    const victim = await openSession('complaint-reader-victim@example.test')
    const message = 'complaint-binding-victim-query'

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: victim.id })
    assert.equal(created.status, 201)

    const victimList = await request(app)
      .get('/api/Complaints')
      .query({ UserId: victim.id })
      .set(bearer(victim.token))
    assert.equal(victimList.status, 200)
    const visible = victimList.body.data.find((complaint: { message: string }) => complaint.message === message)
    assert.equal(visible, undefined)
    for (const complaint of victimList.body.data) {
      assert.equal(Number(complaint.UserId), victim.id)
    }
  })

  void it('does not return another user complaint to a second logged-in customer', async () => {
    const actor = await openSession('complaint-bystander-actor@example.test')
    const victim = await openSession('complaint-bystander-victim@example.test')
    const bystander = await openSession('complaint-bystander@example.test')
    const message = 'complaint-binding-bystander-list'

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: victim.id })
    assert.equal(created.status, 201)

    const bystanderList = await request(app)
      .get('/api/Complaints')
      .set(bearer(bystander.token))
    assert.equal(bystanderList.status, 200)
    const visible = bystanderList.body.data.find((complaint: { message: string }) => complaint.message === message)
    assert.equal(visible, undefined)
    for (const complaint of bystanderList.body.data) {
      assert.equal(Number(complaint.UserId), bystander.id)
    }
  })

  void it('does not return another user complaint when a customer queries that user id', async () => {
    const actor = await openSession('complaint-query-actor@example.test')
    const victim = await openSession('complaint-query-victim@example.test')
    const bystander = await openSession('complaint-query-bystander@example.test')
    const message = 'complaint-binding-bystander-query'

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: victim.id })
    assert.equal(created.status, 201)

    const bystanderQuery = await request(app)
      .get('/api/Complaints/')
      .query({ UserId: String(victim.id) })
      .set(bearer(bystander.token))
    assert.equal(bystanderQuery.status, 200)
    const queried = bystanderQuery.body.data.find((complaint: { message: string }) => complaint.message === message)
    assert.equal(queried, undefined)
    for (const complaint of bystanderQuery.body.data) {
      assert.equal(Number(complaint.UserId), bystander.id)
    }
  })

  void it('shows an administrator complaints filed by other users under those users', async () => {
    const actor = await openSession('complaint-admin-reader-actor@example.test')
    const victim = await openSession('complaint-admin-reader-victim@example.test')
    const admin = await openAdminSession('complaint-admin-reader@example.test')
    const message = 'complaint-binding-admin-can-read'

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: victim.id })
    assert.equal(created.status, 201)

    const adminList = await request(app)
      .get('/api/Complaints')
      .set(bearer(admin.token))
    assert.equal(adminList.status, 200)
    const found = adminList.body.data.find((complaint: { message: string, UserId: number }) => complaint.message === message)
    assert.ok(found)
    assert.equal(Number(found.UserId), actor.id)
    assert.equal(await storedUserId(message), actor.id)
  })

  void it('does not change the stored user id when a complaint id route is updated or deleted', async () => {
    const actor = await openSession('complaint-mutation-actor@example.test')
    const victim = await openSession('complaint-mutation-victim@example.test')
    const message = 'complaint-binding-mutation-unchanged'

    const created = await request(app)
      .post('/api/Complaints')
      .set(bearer(actor.token))
      .send({ message, UserId: actor.id })
    assert.equal(created.status, 201)
    const complaintId = created.body.data.id
    const before = await ComplaintModel.findByPk(complaintId)
    assert.ok(before)

    const put = await request(app)
      .put(`/api/Complaints/${complaintId}`)
      .set(bearer(actor.token))
      .send({ message: 'complaint-binding-mutated', UserId: victim.id })
    const patch = await request(app)
      .patch(`/api/Complaints/${complaintId}`)
      .set(bearer(victim.token))
      .send({ message: 'complaint-binding-mutated', UserId: victim.id })
    const removed = await request(app)
      .delete(`/api/Complaints/${complaintId}`)
      .set(bearer(victim.token))
    const read = await request(app)
      .get(`/api/Complaints/${complaintId}`)
      .set(bearer(victim.token))

    assert.equal(put.status, 401)
    assert.equal(patch.status, 401)
    assert.equal(removed.status, 401)
    assert.equal(read.status, 401)

    const after = await ComplaintModel.findByPk(complaintId)
    assert.ok(after)
    assert.equal(after.message, before.message)
    assert.equal(Number(after.UserId), Number(before.UserId))
  })
})
