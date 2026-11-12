/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const registrationPassword = 'placeholder-registration-password'
const customerProfileImage = '/assets/public/images/uploads/default.svg'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function bearer (token: string) {
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

async function postUser (path: string, body: Record<string, unknown>, authorization?: string) {
  const req = request(app).post(path).set(jsonHeader)
  if (authorization !== undefined) {
    req.set('Authorization', authorization)
  }
  return await req.send(body)
}

void describe('public registration role', () => {
  for (const role of [security.roles.admin, security.roles.accounting, security.roles.deluxe]) {
    void it(`POST /api/Users keeps a customer when the body role is ${role}`, async () => {
      const email = `public-${role}@example.test`
      const created = await postUser('/api/Users', {
        email,
        password: registrationPassword,
        role
      })
      const { token } = await login(app, { email, password: registrationPassword })
      const payload = security.decode(token) as { data?: { role?: string, profileImage?: string } }
      const stored = await request(app)
        .get(`/api/Users/${created.body.data.id as number}`)
        .set(bearer(token))
      const whoami = await request(app)
        .get('/rest/user/whoami')
        .query({ fields: 'role,profileImage' })
        .set('Cookie', [`token=${token}`])

      assert.deepEqual({
        status: created.status,
        responseRole: created.body.data.role,
        responseProfileImage: created.body.data.profileImage,
        tokenRole: payload?.data?.role,
        storedRole: stored.body.data?.role,
        storedProfileImage: stored.body.data?.profileImage,
        whoamiRole: whoami.body.user?.role,
        whoamiProfileImage: whoami.body.user?.profileImage
      }, {
        status: 201,
        responseRole: security.roles.customer,
        responseProfileImage: customerProfileImage,
        tokenRole: security.roles.customer,
        storedRole: security.roles.customer,
        storedProfileImage: customerProfileImage,
        whoamiRole: security.roles.customer,
        whoamiProfileImage: customerProfileImage
      })
    })

    void it(`POST /api/Users keeps a customer when passwordRepeat is sent with role ${role}`, async () => {
      const email = `public-${role}-repeat@example.test`
      const created = await postUser('/api/Users', {
        email,
        password: registrationPassword,
        passwordRepeat: registrationPassword,
        role
      })
      const { token } = await login(app, { email, password: registrationPassword })
      const payload = security.decode(token) as { data?: { role?: string } }
      const stored = await request(app)
        .get(`/api/Users/${created.body.data.id as number}`)
        .set(bearer(token))

      assert.deepEqual({
        status: created.status,
        responseRole: created.body.data.role,
        tokenRole: payload?.data?.role,
        storedRole: stored.body.data?.role
      }, {
        status: 201,
        responseRole: security.roles.customer,
        tokenRole: security.roles.customer,
        storedRole: security.roles.customer
      })
    })
  }

  void it('POST /api/Users/ keeps a customer when a signed-in customer supplies role admin', async () => {
    const customer = await postUser('/api/Users', {
      email: 'public-customer@example.test',
      password: registrationPassword
    })
    const customerLogin = await login(app, {
      email: 'public-customer@example.test',
      password: registrationPassword
    })
    const created = await postUser('/api/Users/', {
      email: 'public-customer-admin@example.test',
      password: registrationPassword,
      passwordRepeat: registrationPassword,
      role: security.roles.admin
    }, `Bearer ${customerLogin.token}`)
    const adminLogin = await login(app, {
      email: 'public-customer-admin@example.test',
      password: registrationPassword
    })
    const payload = security.decode(adminLogin.token) as { data?: { role?: string } }

    assert.deepEqual({
      customerStatus: customer.status,
      status: created.status,
      responseRole: created.body.data.role,
      responseProfileImage: created.body.data.profileImage,
      tokenRole: payload?.data?.role
    }, {
      customerStatus: 201,
      status: 201,
      responseRole: security.roles.customer,
      responseProfileImage: customerProfileImage,
      tokenRole: security.roles.customer
    })
  })

  void it('a self-registered accounting user cannot list or update orders', async () => {
    const email = 'public-accounting-orders@example.test'
    const created = await postUser('/api/Users', {
      email,
      password: registrationPassword,
      passwordRepeat: registrationPassword,
      role: security.roles.accounting
    })
    const { token } = await login(app, { email, password: registrationPassword })
    const payload = security.decode(token) as { data?: { role?: string } }
    const orders = await request(app)
      .get('/rest/order-history/orders')
      .set(bearer(token))
    const delivery = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set(bearer(token))
      .send({ deliveryStatus: false })
    const quantity = await request(app)
      .get('/api/Quantitys/1')
      .set(bearer(token))

    assert.deepEqual({
      status: created.status,
      tokenRole: payload?.data?.role,
      ordersStatus: orders.status,
      ordersError: orders.body.error,
      deliveryStatus: delivery.status,
      deliveryError: delivery.body.error,
      quantityStatus: quantity.status,
      quantityError: quantity.body.error
    }, {
      status: 201,
      tokenRole: security.roles.customer,
      ordersStatus: 403,
      ordersError: 'Malicious activity detected',
      deliveryStatus: 403,
      deliveryError: 'Malicious activity detected',
      quantityStatus: 403,
      quantityError: 'Malicious activity detected'
    })
  })

  void it('a self-registered deluxe user with a client deluxe token is not deluxe', async () => {
    const email = 'public-deluxe-token@example.test'
    const created = await postUser('/api/Users', {
      email,
      password: registrationPassword,
      role: security.roles.deluxe,
      deluxeToken: security.deluxeToken(email)
    })
    const { token } = await login(app, { email, password: registrationPassword })
    const payload = security.decode(token) as { data?: { role?: string } }
    const membership = await request(app)
      .get('/rest/deluxe-membership')
      .set(bearer(token))
    const methods = await request(app)
      .get('/api/Deliverys')
      .set(bearer(token))
    const oneDay = await request(app)
      .get('/api/Deliverys/1')
      .set(bearer(token))

    assert.deepEqual({
      status: created.status,
      tokenRole: payload?.data?.role,
      membershipStatus: membership.status,
      membership: membership.body,
      methodPrices: (methods.body.data ?? []).map((method: { name: string, price: number }) => ({
        name: method.name,
        price: method.price
      })),
      oneDayStatus: oneDay.status,
      oneDayPrice: oneDay.body.data?.price
    }, {
      status: 201,
      tokenRole: security.roles.customer,
      membershipStatus: 200,
      membership: { status: 'success', data: { membershipCost: 49 } },
      methodPrices: [
        { name: 'One Day Delivery', price: 0.99 },
        { name: 'Fast Delivery', price: 0.5 },
        { name: 'Standard Delivery', price: 0 }
      ],
      oneDayStatus: 200,
      oneDayPrice: 0.99
    })
  })
})
