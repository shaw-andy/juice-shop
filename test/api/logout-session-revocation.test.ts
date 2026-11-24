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
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import { CardModel } from '../../models/card'
import { AddressModel } from '../../models/address'
import { PrivacyRequestModel } from '../../models/privacyRequests'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { ComplaintModel } from '../../models/complaint'
import { SecurityQuestionModel } from '../../models/securityQuestion'
import { SecurityAnswerModel } from '../../models/securityAnswer'

const placeholderPassword = 'placeholder-password'
const renamedUsername = 'chosen-name'
const attackerUsername = 'replaced-name'
const keptImageUrl = 'http://127.0.0.1:1/kept.png'
const replacedImageUrl = 'http://127.0.0.1:1/replaced.png'

let app: Express
let sequence = 0

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('session revocation on sign-out', { concurrency: 1 }, () => {
  void it('rejects a stolen token after sign-out on signature checks and does not put it back', async () => {
    const session = await openSession('signature')
    const usersBefore = await request(app).get('/api/Users').set(session.headers)
    assert.equal(usersBefore.status, 200)
    const deluxeBefore = await request(app).get('/rest/deluxe-membership').set(session.headers)
    assert.equal(deluxeBefore.status, 200)
    const walletBefore = await request(app).get('/rest/wallet/balance').set(session.headers)
    assert.equal(walletBefore.status, 200)
    const profileBefore = await request(app).get('/profile').set(session.headers)
    assert.equal(profileBefore.status, 200)
    assert.equal(profileBefore.text.includes(session.email), true)

    await customerSignsOut(session.token)

    await assertSignatureRejected(session)
    await assertWalletRejected(session)
    await settleRevocationRace()
    await assertSignatureRejected(session)
    await assertWalletRejected(session)
    await assertProfileRejected(session)
    await assertWhoamiRejected(session)

    const logout = await request(app)
      .post('/rest/user/logout')
      .set(session.headers)
      .send({})
    assert.ok(logout.status === 200 || logout.status === 204)
  })

  void it('does not change the profile, password, or last login ip after sign-out', async () => {
    const session = await openSession('profile')
    const renamed = await request(app)
      .post('/profile')
      .set(session.headers)
      .send({ username: renamedUsername })
    assert.equal(renamed.status, 302)
    const stamped = await request(app)
      .get('/rest/saveLoginIp')
      .set(session.headers)
      .set('True-Client-IP', '203.0.113.10')
    assert.equal(stamped.status, 200)

    await customerSignsOut(session.token)
    await settleRevocationRace()

    const userBefore = await UserModel.findByPk(session.userId)
    const passwordBefore = userBefore?.password
    const ipBefore = userBefore?.lastLoginIp
    for (let attempt = 0; attempt < 2; attempt++) {
      await request(app)
        .post('/profile')
        .set(session.headers)
        .send({ username: attackerUsername, UserId: session.otherUserId })
      await request(app)
        .get('/rest/user/change-password')
        .set(session.headers)
        .query({
          current: placeholderPassword,
          new: 'placeholder-password-2',
          repeat: 'placeholder-password-2'
        })
      await request(app)
        .get('/rest/saveLoginIp')
        .set(session.headers)
        .set('True-Client-IP', '203.0.113.99')
      await settleRevocationRace()
    }

    const userAfter = await UserModel.findByPk(session.userId)
    const otherAfter = await UserModel.findByPk(session.otherUserId)
    assert.equal(userAfter?.username, renamedUsername)
    assert.equal(otherAfter?.username == null || otherAfter?.username === '', true)
    assert.equal(userAfter?.password, passwordBefore)
    assert.equal(userAfter?.lastLoginIp, ipBefore)
    await assertProfileRejected(session)
  })

  void it('does not replace the profile image after sign-out', async () => {
    const session = await openSession('image')
    const uploaded = await request(app)
      .post('/profile/image/url')
      .set('Cookie', 'token=' + session.token)
      .type('form')
      .send({ imageUrl: keptImageUrl })
    assert.notEqual(uploaded.status, 401)
    const kept = await UserModel.findByPk(session.userId)
    assert.equal(kept?.profileImage, keptImageUrl)

    await customerSignsOut(session.token)
    await request(app).get('/rest/wallet/balance').set(session.headers)
    await settleRevocationRace()

    await request(app)
      .post('/profile/image/url')
      .set('Cookie', 'token=' + session.token)
      .set('Authorization', 'Bearer ' + session.token)
      .type('form')
      .send({ imageUrl: replacedImageUrl, UserId: session.otherUserId })
    await settleRevocationRace()
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', 'token=' + session.token)
      .type('form')
      .send({ imageUrl: replacedImageUrl })

    const after = await UserModel.findByPk(session.userId)
    const other = await UserModel.findByPk(session.otherUserId)
    assert.equal(after?.profileImage, keptImageUrl)
    assert.notEqual(other?.profileImage, replacedImageUrl)
  })

  void it('stops accepting the token after a data-erasure request is filed', async () => {
    const session = await openSession('erasure')
    await SecurityAnswerModel.create({
      UserId: session.userId,
      SecurityQuestionId: (await SecurityQuestionModel.findOne())?.id ?? (await SecurityQuestionModel.create({ question: 'Placeholder question' })).id,
      answer: 'placeholder-answer'
    })
    const opened = await request(app).get('/dataerasure/').set(session.headers)
    assert.equal(opened.status, 200)
    assert.equal(opened.text.includes(session.email), true)

    const filed = await request(app)
      .post('/dataerasure/')
      .set(session.headers)
      .type('form')
      .send({ email: session.email, securityAnswer: 'placeholder-answer' })
    assert.equal(filed.status, 200)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: session.userId } }), 1)

    await request(app).get('/api/Users').set(session.headers)
    await settleRevocationRace()

    const again = await request(app)
      .post('/dataerasure/')
      .set(session.headers)
      .type('form')
      .send({ email: session.email, securityAnswer: 'placeholder-answer', UserId: session.otherUserId })
    assert.notEqual(again.status, 200)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: session.userId } }), 1)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: session.otherUserId } }), 0)
    await assertProfileRejected(session)
    await assertSignatureRejected(session)
    await assertWhoamiRejected(session)
  })

  void it('does not read or change wallet, card, address, or deluxe data after sign-out', async () => {
    const session = await openSession('wallet')
    const card = await request(app).post('/api/Cards').set(session.headers).send({
      fullName: 'Customer',
      cardNum: 1000000000000000,
      expMonth: 1,
      expYear: 2085,
      UserId: session.otherUserId
    })
    assert.equal(card.status, 201)
    const cardId = card.body.data.id
    const topped = await request(app)
      .put('/rest/wallet/balance')
      .set(session.headers)
      .send({ balance: 10, paymentId: cardId, UserId: session.otherUserId })
    assert.equal(topped.status, 200)
    const address = await request(app).post('/api/Addresss').set(session.headers).send(addressBody(session.otherUserId))
    assert.equal(address.status, 201)
    const addressId = address.body.data.id
    const deluxeBefore = await request(app).get('/rest/deluxe-membership').set(session.headers)
    assert.equal(deluxeBefore.status, 200)

    await customerSignsOut(session.token)
    await settleRevocationRace()

    for (let attempt = 0; attempt < 2; attempt++) {
      const balance = await request(app).get('/rest/wallet/balance').set(session.headers)
      assert.equal(balance.status, 401)
      const topUp = await request(app)
        .put('/rest/wallet/balance')
        .set(session.headers)
        .send({ balance: 25, paymentId: cardId, UserId: session.otherUserId })
      assert.equal(topUp.status, 401)
      const cards = await request(app).get('/api/Cards').set(session.headers)
      assert.equal(cards.status, 401)
      const extraCard = await request(app).post('/api/Cards').set(session.headers).send({
        fullName: 'Attacker',
        cardNum: 1000000000000001,
        expMonth: 2,
        expYear: 2086,
        UserId: session.otherUserId
      })
      assert.equal(extraCard.status, 401)
      const removedCard = await request(app).delete('/api/Cards/' + cardId).set(session.headers).send({ UserId: session.otherUserId })
      assert.equal(removedCard.status, 401)
      const addresses = await request(app).get('/api/Addresss').set(session.headers)
      assert.equal(addresses.status, 401)
      const oneAddress = await request(app).get('/api/Addresss/' + addressId).set(session.headers)
      assert.equal(oneAddress.status, 401)
      const extraAddress = await request(app).post('/api/Addresss').set(session.headers).send({
        ...addressBody(session.otherUserId),
        streetAddress: 'Other Street'
      })
      assert.equal(extraAddress.status, 401)
      const edited = await request(app).put('/api/Addresss/' + addressId).set(session.headers).send({
        ...addressBody(session.otherUserId),
        city: 'Attacker City'
      })
      assert.equal(edited.status, 401)
      const removedAddress = await request(app).delete('/api/Addresss/' + addressId).set(session.headers).send({ UserId: session.otherUserId })
      assert.equal(removedAddress.status, 401)
      const upgrade = await request(app)
        .post('/rest/deluxe-membership')
        .set(session.headers)
        .send({ paymentMode: 'wallet', paymentId: cardId, UserId: session.otherUserId })
      assert.equal(upgrade.status, 401)
      const deluxe = await request(app).get('/rest/deluxe-membership').set(session.headers)
      assert.equal(deluxe.status, 401)
      await settleRevocationRace()
    }

    const wallet = await WalletModel.findOne({ where: { UserId: session.userId } })
    const otherWallet = await WalletModel.findOne({ where: { UserId: session.otherUserId } })
    assert.equal(wallet?.balance, 10)
    assert.equal(otherWallet?.balance ?? 0, 0)
    assert.equal(await CardModel.count({ where: { UserId: session.userId } }), 1)
    assert.equal(await CardModel.count({ where: { UserId: session.otherUserId } }), 0)
    assert.equal(await CardModel.count({ where: { id: cardId } }), 1)
    const storedAddress = await AddressModel.findByPk(addressId)
    assert.equal(storedAddress?.city, 'NYC')
    assert.equal(storedAddress?.UserId, session.userId)
    assert.equal(await AddressModel.count({ where: { UserId: session.otherUserId } }), 0)
    const customer = await UserModel.findByPk(session.userId)
    const other = await UserModel.findByPk(session.otherUserId)
    assert.equal(customer?.role, 'customer')
    assert.equal(other?.role, 'customer')
  })

  void it('does not export data, list orders, or issue a captcha after sign-out', async () => {
    const session = await openSession('export')
    const exported = await request(app).post('/rest/user/data-export').set(session.headers).send({ UserId: session.otherUserId })
    assert.equal(exported.status, 200)
    assert.equal(JSON.stringify(exported.body).includes(session.email), true)
    const orders = await request(app).get('/rest/order-history').set(session.headers)
    assert.equal(orders.status, 200)
    const captcha = await request(app).get('/rest/image-captcha').set(session.headers)
    assert.equal(captcha.status, 200)

    await customerSignsOut(session.token)

    for (let attempt = 0; attempt < 2; attempt++) {
      const replayExport = await request(app).post('/rest/user/data-export').set(session.headers).send({ UserId: session.otherUserId })
      assert.equal(replayExport.status, 401)
      assert.equal(JSON.stringify(replayExport.body ?? '').includes(session.email), false)
      const replayOrders = await request(app).get('/rest/order-history').set(session.headers)
      assert.notEqual(replayOrders.status, 200)
      assert.equal(JSON.stringify(replayOrders.body ?? '').includes(session.email), false)
      const replayCaptcha = await request(app).get('/rest/image-captcha').set(session.headers)
      assert.equal(replayCaptcha.status, 401)
      await settleRevocationRace()
    }
  })

  void it('does not add a basket item for this basket or another basket after sign-out', async () => {
    const session = await openSession('basket')
    const basket = await request(app).get('/rest/basket/' + session.bid).set(session.headers)
    assert.equal(basket.status, 200)
    const added = await request(app).post('/api/BasketItems').set(session.headers).send({
      ProductId: 1,
      BasketId: session.bid,
      quantity: 1
    })
    assert.equal(added.status, 200)
    const before = await BasketItemModel.count({ where: { BasketId: session.bid } })
    const otherBefore = await BasketItemModel.count({ where: { BasketId: session.otherBid } })

    await customerSignsOut(session.token)
    await settleRevocationRace()

    for (let attempt = 0; attempt < 2; attempt++) {
      const replayBasket = await request(app).get('/rest/basket/' + session.bid).set(session.headers)
      assert.equal(replayBasket.status, 401)
      const ownItem = await request(app).post('/api/BasketItems').set(session.headers).send({
        ProductId: 1,
        BasketId: session.bid,
        quantity: 1,
        UserId: session.otherUserId
      })
      assert.equal(ownItem.status, 401)
      const foreignItem = await request(app).post('/api/BasketItems').set(session.headers).send({
        ProductId: 1,
        BasketId: session.otherBid,
        quantity: 1,
        UserId: session.otherUserId
      })
      assert.equal(foreignItem.status, 401)
      await settleRevocationRace()
    }

    assert.equal(await BasketItemModel.count({ where: { BasketId: session.bid } }), before)
    assert.equal(await BasketItemModel.count({ where: { BasketId: session.otherBid } }), otherBefore)
  })

  void it('does not create products, complaints, privacy requests, reviews, or b2b orders after sign-out', async () => {
    const session = await openSession('writes')
    const productBefore = await ProductModel.count()
    const complaintBefore = await ComplaintModel.count()
    const privacyBefore = await PrivacyRequestModel.count({ where: { UserId: session.userId } })
    const created = await request(app).post('/api/Products').set(session.headers).send({
      name: 'Session probe',
      description: 'Ordinary description',
      price: 1,
      deluxePrice: 1,
      image: 'apple_juice.jpg'
    })
    assert.equal(created.status, 201)
    const complaint = await request(app).post('/api/Complaints').set(session.headers).send({
      message: 'Ordinary complaint',
      UserId: session.userId
    })
    assert.equal(complaint.status, 201)
    const likedBefore = await request(app).post('/rest/products/reviews').set(session.headers).send({ id: 'missing-review' })
    assert.equal(likedBefore.status, 404)
    const patchedBefore = await request(app).patch('/rest/products/reviews').set(session.headers).send({
      id: 'missing-review',
      message: 'rewritten'
    })
    assert.notEqual(patchedBefore.status, 401)
    const b2bBefore = await request(app).post('/b2b/v2/orders').set(session.headers).send({})
    assert.notEqual(b2bBefore.status, 401)
    const detailsBefore = await request(app).get('/rest/user/authentication-details').set(session.headers)
    assert.equal(detailsBefore.status, 200)
    const twoFactorBefore = await request(app).get('/rest/2fa/status').set(session.headers)
    assert.equal(twoFactorBefore.status, 200)
    const userBefore = await request(app).get('/api/Users/' + session.userId).set(session.headers)
    assert.equal(userBefore.status, 200)

    await customerSignsOut(session.token)
    await settleRevocationRace()

    for (let attempt = 0; attempt < 2; attempt++) {
      const product = await request(app).post('/api/Products').set(session.headers).send({
        name: 'Stolen session product',
        description: 'Ordinary description',
        price: 2,
        deluxePrice: 2,
        image: 'apple_juice.jpg',
        UserId: session.otherUserId
      })
      assert.equal(product.status, 401)
      const anotherComplaint = await request(app).post('/api/Complaints').set(session.headers).send({
        message: 'Stolen session complaint',
        UserId: session.otherUserId
      })
      assert.equal(anotherComplaint.status, 401)
      const privacy = await request(app).post('/api/PrivacyRequests').set(session.headers).send({
        UserId: session.otherUserId,
        deletionRequested: true
      })
      assert.equal(privacy.status, 401)
      const liked = await request(app).post('/rest/products/reviews').set(session.headers).send({ id: 'missing-review' })
      assert.equal(liked.status, 401)
      const patched = await request(app).patch('/rest/products/reviews').set(session.headers).send({
        id: 'missing-review',
        message: 'rewritten'
      })
      assert.equal(patched.status, 401)
      const b2b = await request(app).post('/b2b/v2/orders').set(session.headers).send({})
      assert.equal(b2b.status, 401)
      const details = await request(app).get('/rest/user/authentication-details').set(session.headers)
      assert.equal(details.status, 401)
      const twoFactor = await request(app).get('/rest/2fa/status').set(session.headers)
      assert.equal(twoFactor.status, 401)
      const user = await request(app).get('/api/Users/' + session.userId).set(session.headers)
      assert.equal(user.status, 401)
      await settleRevocationRace()
    }

    assert.equal(await ProductModel.count(), productBefore + 1)
    assert.equal(await ComplaintModel.count(), complaintBefore + 1)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: session.userId } }), privacyBefore)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: session.otherUserId } }), 0)
  })

  void it('lets a fresh sign-in work and keeps rejecting the token from the signed-out session', async () => {
    const session = await openSession('fresh')
    await customerSignsOut(session.token)
    await settleRevocationRace()
    await assertProfileRejected(session)
    await assertSignatureRejected(session)

    const fresh = await login(app, { email: session.email, password: placeholderPassword })
    const freshHeaders = {
      Authorization: 'Bearer ' + fresh.token,
      Cookie: 'token=' + fresh.token,
      'content-type': 'application/json'
    }
    const profile = await request(app).get('/profile').set(freshHeaders)
    assert.equal(profile.status, 200)
    assert.equal(profile.text.includes(session.email), true)
    const users = await request(app).get('/api/Users').set(freshHeaders)
    assert.equal(users.status, 200)

    await assertProfileRejected(session)
    await assertSignatureRejected(session)
    await settleRevocationRace()
    await assertProfileRejected(session)
    await assertWalletRejected(session)
  })
})

async function openSession (label: string) {
  sequence += 1
  const email = `logout-${label}-${sequence}@juice-sh.op`
  const otherEmail = `logout-${label}-other-${sequence}@juice-sh.op`
  const registered = await request(app)
    .post('/api/Users')
    .set('content-type', 'application/json')
    .send({ email, password: placeholderPassword, passwordRepeat: placeholderPassword })
  assert.equal(registered.status, 201)
  await replaceWallet(registered.body.data.id)
  const other = await request(app)
    .post('/api/Users')
    .set('content-type', 'application/json')
    .send({ email: otherEmail, password: placeholderPassword, passwordRepeat: placeholderPassword })
  assert.equal(other.status, 201)
  await replaceWallet(other.body.data.id)
  const authentication = await login(app, { email, password: placeholderPassword })
  const otherAuthentication = await login(app, { email: otherEmail, password: placeholderPassword })
  return {
    email,
    userId: registered.body.data.id as number,
    otherUserId: other.body.data.id as number,
    token: authentication.token as string,
    bid: authentication.bid as number,
    otherBid: otherAuthentication.bid as number,
    headers: {
      Authorization: 'Bearer ' + authentication.token,
      Cookie: 'token=' + authentication.token,
      'content-type': 'application/json'
    }
  }
}

async function replaceWallet (userId: number) {
  await new Promise((resolve) => setTimeout(resolve, 50))
  await WalletModel.destroy({ where: { UserId: userId } })
  await WalletModel.create({ UserId: userId, balance: 0 })
}

async function customerSignsOut (token: string) {
  await request(app)
    .get('/rest/saveLoginIp')
    .set('Authorization', 'Bearer ' + token)
    .set('Cookie', 'token=' + token)
  await request(app)
    .post('/rest/user/logout')
    .set('Authorization', 'Bearer ' + token)
    .set('Cookie', 'token=' + token)
    .set('content-type', 'application/json')
    .send({})
}

async function settleRevocationRace () {
  await new Promise((resolve) => setTimeout(resolve, 100))
}

async function assertSignatureRejected (session: { headers: Record<string, string>, email: string }) {
  const users = await request(app).get('/api/Users').set(session.headers)
  assert.equal(users.status, 401)
  assert.equal(JSON.stringify(users.body ?? '').includes(session.email), false)
  const deluxe = await request(app).get('/rest/deluxe-membership').set(session.headers)
  assert.equal(deluxe.status, 401)
  assert.equal(JSON.stringify(deluxe.body ?? '').includes('membershipCost'), false)
}

async function assertWalletRejected (session: { headers: Record<string, string> }) {
  const balance = await request(app).get('/rest/wallet/balance').set(session.headers)
  assert.equal(balance.status, 401)
}

async function assertProfileRejected (session: { headers: Record<string, string>, email: string }) {
  const profile = await request(app).get('/profile').set(session.headers)
  assert.notEqual(profile.status, 200)
  assert.equal(profile.text.includes(session.email), false)
  const form = await request(app).get('/dataerasure/').set(session.headers)
  assert.notEqual(form.status, 200)
  assert.equal(form.text.includes(session.email), false)
}

async function assertWhoamiRejected (session: { headers: Record<string, string>, email: string, userId: number }) {
  const whoami = await request(app).get('/rest/user/whoami').set(session.headers)
  if (whoami.status === 200) {
    assert.notEqual(whoami.body?.user?.email, session.email)
    assert.notEqual(whoami.body?.user?.id, session.userId)
  } else {
    assert.equal(whoami.status, 401)
  }
}

function addressBody (userId: number) {
  return {
    fullName: 'Customer',
    mobileNum: 9800000000,
    zipCode: 'NX 101',
    streetAddress: 'Bakers Street',
    city: 'NYC',
    state: 'NY',
    country: 'USA',
    UserId: userId
  }
}
