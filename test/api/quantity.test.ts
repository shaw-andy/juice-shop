/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { Op } from 'sequelize'
import { createTestApp } from './helpers/setup'
import { QuantityModel } from '../../models/quantity'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Quantitys', () => {
  void it('GET quantity of all items is forbidden for anonymous users', async () => {
    const res = await request(app)
      .get('/api/Quantitys')

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('GET quantity of all items is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .get('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('GET quantity of all items is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: `admin@${config.get<string>('application.domain')}`,
      password: 'admin123'
    })
    const res = await request(app)
      .get('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('GET quantity of all items for accounting users', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .get('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
  })

  void it('POST quantity is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .post('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ ProductId: 1, quantity: 100 })

    assert.equal(res.status, 401)
  })

  void it('POST quantity forbidden for admin', async () => {
    const { token } = await login(app, {
      email: `admin@${config.get<string>('application.domain')}`,
      password: 'admin123'
    })
    const res = await request(app)
      .post('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ ProductId: 1, quantity: 100 })

    assert.equal(res.status, 401)
  })

  void it('POST quantity is forbidden for accounting users', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .post('/api/Quantitys')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ ProductId: 1, quantity: 100 })

    assert.equal(res.status, 401)
  })
})

void describe('/api/Quantitys/:ids', () => {
  void it('GET quantity of all items is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .get('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('GET quantity of all items is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: `admin@${config.get<string>('application.domain')}`,
      password: 'admin123'
    })
    const res = await request(app)
      .get('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('GET quantity of all items for accounting users blocked by IP filter', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .get('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
  })

  void it.skip('GET quantity of all items for accounting users from IP 123.456.789', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .get('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
  })

  void it('PUT quantity is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .put('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ quantity: 100 })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('PUT quantity is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .put('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ quantity: 100 })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('PUT quantity as accounting user blocked by IP filter', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .put('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ quantity: 100 })

    assert.equal(res.status, 403)
  })

  void it.skip('PUT quantity as accounting user from IP 123.456.789', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .put('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({ quantity: 100 })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.quantity, 100)
  })

  void it('DELETE quantity is forbidden for accountant', async () => {
    const { token } = await login(app, {
      email: `accountant@${config.get<string>('application.domain')}`,
      password: 'i am an awesome accountant'
    })
    const res = await request(app)
      .delete('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 401)
  })

  void it('DELETE quantity is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: `admin@${config.get<string>('application.domain')}`,
      password: 'admin123'
    })
    const res = await request(app)
      .delete('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 401)
  })

  void it('DELETE quantity is forbidden for users', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .delete('/api/Quantitys/1')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/products/availability', () => {
  void it('GET only low-stock quantities for anonymous users without purchase limits', async () => {
    const res = await request(app)
      .get('/rest/products/availability')

    assert.equal(res.status, 200)
    const lowStock = await QuantityModel.findAll({ where: { quantity: { [Op.lte]: 5 } } })
    const byProduct = (a: { ProductId: number }, b: { ProductId: number }) => a.ProductId - b.ProductId
    assert.deepEqual(
      [...res.body.data].sort(byProduct),
      lowStock.map(({ ProductId, quantity }) => ({ ProductId, quantity })).sort(byProduct)
    )
  })
})
