/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import { challenges, products } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { BasketItemModel } from '../models/basketitem'
import { DeliveryModel } from '../models/delivery'
import { QuantityModel } from '../models/quantity'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import * as db from '../data/mongodb'
import { orderConfirmationFile, prepareOrderConfirmationsDir, retainOrderConfirmation } from '../lib/orderConfirmations'

interface Product {
  quantity: number
  id?: number
  name: string
  price: number
  total: number
  bonus: number
}

const maxOrdersPerWindow = 5
const orderWindowMs = 15 * 60 * 1000

function createCheckoutAllowance () {
  const windows = new Map<string, { orders: number, resetAt: number }>()
  setInterval(() => {
    const now = Date.now()
    for (const [key, window] of windows) {
      if (window.resetAt <= now) windows.delete(key)
    }
  }, orderWindowMs).unref()

  return (keys: string[]) => {
    const now = Date.now()
    const keyWindows = keys.map((key) => {
      let window = windows.get(key)
      if (window === undefined || window.resetAt <= now) {
        window = { orders: 0, resetAt: now + orderWindowMs }
        windows.set(key, window)
      }
      return window
    })
    if (keyWindows.some(({ orders }) => orders >= maxOrdersPerWindow)) {
      return undefined
    }
    keyWindows.forEach((window) => { window.orders++ })
    let released = false
    return () => {
      if (!released) {
        released = true
        keyWindows.forEach((window) => { window.orders-- })
      }
    }
  }
}

function clientAddressKey (address = '') {
  const ipv4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address)
  if (ipv4 !== null) return ipv4[1]
  if (!net.isIPv6(address) || address.includes('.')) return address
  const [head, tail] = address.toLowerCase().split('::')
  const headGroups = head === '' ? [] : head.split(':')
  const tailGroups = tail === undefined || tail === '' ? [] : tail.split(':')
  const groups = [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill('0'), ...tailGroups].map((group) => group.padStart(4, '0'))
  // Group IPv6 clients by /56 prefix, as a single subscriber usually controls at least that much address space
  return `${groups.slice(0, 3).join(':')}:${groups[3].slice(0, 2)}00::/56`
}

export function placeOrder () {
  const reserveCheckout = createCheckoutAllowance()
  const basketsInCheckout = new Set<number>()

  return (req: Request, res: Response, next: NextFunction) => {
    const customer = security.authenticatedUsers.from(req)
    const releaseCheckout = reserveCheckout([`user:${customer?.data?.id}`, `address:${clientAddressKey(req.socket?.remoteAddress)}`])
    if (releaseCheckout === undefined) {
      res.status(429).json({ status: 'error', message: 'Too many orders, please try again later.' })
      return
    }
    let lockedBasketId: number | undefined
    const unlockBasket = () => {
      if (lockedBasketId !== undefined) basketsInCheckout.delete(lockedBasketId)
    }
    const fail = (error: unknown) => {
      unlockBasket()
      releaseCheckout()
      next(error)
    }
    const failAfterOrderStored = (error: unknown) => {
      unlockBasket()
      next(error)
    }

    const id = req.params.id
    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      .then(async (basket: BasketModel | null) => {
        if (basket != null) {
          if (customer?.data?.id === undefined || basket.UserId !== customer.data.id) {
            releaseCheckout()
            res.status(403).json({ status: 'error', message: 'You are not allowed to check out this basket.' })
            return
          }
          if (!(basket.Products ?? []).some(({ BasketItem }) => BasketItem != null && BasketItem.quantity > 0)) {
            releaseCheckout()
            res.status(400).json({ status: 'error', message: 'Your basket does not contain any products.' })
            return
          }
          if (basketsInCheckout.has(basket.id)) {
            releaseCheckout()
            res.status(409).json({ status: 'error', message: 'This basket is already being checked out.' })
            return
          }
          lockedBasketId = basket.id
          basketsInCheckout.add(basket.id)
          const email = customer.data.email ?? ''
          const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)
          const { default: PDFDocument } = await import('pdfkit')
          const doc = new PDFDocument()
          const date = new Date().toJSON().slice(0, 10)

          doc.font('Times-Roman').fontSize(40).text(config.get<string>('application.name'), { align: 'center' })
          doc.moveTo(70, 115).lineTo(540, 115).stroke()
          doc.moveTo(70, 120).lineTo(540, 120).stroke()
          doc.fontSize(20).moveDown()
          doc.font('Times-Roman').fontSize(20).text(req.__('Order Confirmation'), { align: 'center' })
          doc.fontSize(20).moveDown()
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Customer')}: ${email}`, { align: 'left' })
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Order')} #: ${orderId}`, { align: 'left' })
          doc.moveDown()
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Date')}: ${date}`, { align: 'left' })
          doc.moveDown()
          doc.moveDown()
          let totalPrice = 0
          const basketProducts: Product[] = []
          let totalPoints = 0
          for (const { BasketItem, price, deluxePrice, name, id } of basket.Products ?? []) {
            if (BasketItem != null) {
              challengeUtils.solveIf(challenges.christmasSpecialChallenge, () => { return BasketItem.ProductId === products.christmasSpecial.id })
              try {
                const quantityRow = await QuantityModel.findOne({ where: { ProductId: BasketItem.ProductId } })
                if (quantityRow) {
                  const newQuantity = quantityRow.quantity - BasketItem.quantity
                  await QuantityModel.update({ quantity: newQuantity }, { where: { ProductId: BasketItem.ProductId } })
                }
              } catch (error: unknown) {
                fail(error)
                return
              }
              let itemPrice: number
              if (security.isDeluxe(req)) {
                itemPrice = deluxePrice
              } else {
                itemPrice = price
              }
              const itemTotal = itemPrice * BasketItem.quantity
              const itemBonus = Math.round(itemPrice / 10) * BasketItem.quantity
              const product = {
                quantity: BasketItem.quantity,
                id,
                name: req.__(name),
                price: itemPrice,
                total: itemTotal,
                bonus: itemBonus
              }
              basketProducts.push(product)
              doc.text(`${BasketItem.quantity}x ${req.__(name)} ${req.__('ea.')} ${itemPrice} = ${itemTotal}¤`)
              doc.moveDown()
              totalPrice += itemTotal
              totalPoints += itemBonus
            }
          }
          doc.moveDown()
          const discount = calculateApplicableDiscount(basket, req) ?? 0
          let discountAmount = '0'
          if (discount > 0) {
            discountAmount = (totalPrice * (discount / 100)).toFixed(2)
            doc.text(discount + '% discount from coupon: -' + discountAmount + '¤')
            doc.moveDown()
            totalPrice -= parseFloat(discountAmount)
          }
          const deliveryMethod = {
            deluxePrice: 0,
            price: 0,
            eta: 5
          }
          if (req.body.orderDetails?.deliveryMethodId) {
            const deliveryMethodFromModel = await DeliveryModel.findOne({ where: { id: req.body.orderDetails.deliveryMethodId } })
            if (deliveryMethodFromModel != null) {
              deliveryMethod.deluxePrice = deliveryMethodFromModel.deluxePrice
              deliveryMethod.price = deliveryMethodFromModel.price
              deliveryMethod.eta = deliveryMethodFromModel.eta
            }
          }
          const deliveryAmount = security.isDeluxe(req) ? deliveryMethod.deluxePrice : deliveryMethod.price
          totalPrice += deliveryAmount
          doc.text(`${req.__('Delivery Price')}: ${deliveryAmount.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(20).text(`${req.__('Total Price')}: ${totalPrice.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(15).text(`${req.__('Bonus Points Earned')}: ${totalPoints}`)
          doc.font('Times-Roman').fontSize(15).text(`(${req.__('The bonus points from this order will be added 1:1 to your wallet ¤-fund for future purchases!')}`)
          doc.moveDown()
          doc.moveDown()
          doc.font('Times-Roman').fontSize(15).text(req.__('Thank you for your order!'))

          challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

          if (req.body.UserId) {
            if (req.body.orderDetails && req.body.orderDetails.paymentId === 'wallet') {
              const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
              if ((wallet != null) && wallet.balance >= totalPrice) {
                await WalletModel.decrement({ balance: totalPrice }, { where: { UserId: req.body.UserId } })
              } else {
                fail(new Error('Insufficient wallet balance.'))
                return
              }
            }
            try {
              await WalletModel.increment({ balance: totalPoints }, { where: { UserId: req.body.UserId } })
            } catch (error: unknown) {
              fail(error)
              return
            }
          }

          await prepareOrderConfirmationsDir()
          db.ordersCollection.insert({
            promotionalAmount: discountAmount,
            paymentId: req.body.orderDetails ? req.body.orderDetails.paymentId : null,
            addressId: req.body.orderDetails ? req.body.orderDetails.addressId : null,
            orderId,
            delivered: false,
            email: (email ? email.replace(/[aeiou]/gi, '*') : undefined),
            totalPrice,
            products: basketProducts,
            bonus: totalPoints,
            deliveryPrice: deliveryAmount,
            eta: deliveryMethod.eta.toString()
          }).then(() => {
            const pdfFile = orderConfirmationFile(orderId)
            const fileWriter = doc.pipe(fs.createWriteStream(pdfFile))
            fileWriter.on('error', failAfterOrderStored)
            fileWriter.on('finish', () => {
              retainOrderConfirmation(pdfFile)
              void (async () => {
                try {
                  void basket.update({ coupon: null })
                  await BasketItemModel.destroy({ where: { BasketId: basket.id } })
                  unlockBasket()
                  res.json({ orderConfirmation: orderId })
                } catch (error: unknown) {
                  failAfterOrderStored(error)
                }
              })()
            })
            doc.end()
          }, fail).catch(failAfterOrderStored)
        } else {
          fail(new Error(`Basket with id=${id} does not exist.`))
        }
      }).catch(fail)
  }
}

export function serveOrderConfirmation () {
  return (req: Request, res: Response, next: NextFunction) => {
    const orderId = req.params.id
    if (!/^[\w-]+$/.test(orderId)) {
      res.status(400).json({ status: 'error', message: 'Invalid order id.' })
      return
    }
    res.sendFile(orderConfirmationFile(orderId), (error) => {
      if (error != null) next(error)
    })
  }
}

function calculateApplicableDiscount (basket: BasketModel, req: Request) {
  const discount = security.discountFromCoupon(basket.coupon ?? undefined)
  if (discount) {
    challengeUtils.solveIf(challenges.forgedCouponChallenge, () => { return (discount ?? 0) >= 80 })
    return discount
  } else if (req.body.couponData) {
    const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')
    const couponCode = couponData[0]
    const couponDate = Number(couponData[1])
    const campaign = campaigns[couponCode as keyof typeof campaigns]

    if (campaign && couponDate == campaign.validOn) { // eslint-disable-line eqeqeq
      challengeUtils.solveIf(challenges.manipulateClockChallenge, () => { return campaign.validOn < new Date().getTime() })
      return campaign.discount
    }
  }
  return 0
}

const campaigns = {
  WMNSDY2019: { validOn: new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime(), discount: 75 },
  WMNSDY2020: { validOn: new Date('Mar 08, 2020 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2021: { validOn: new Date('Mar 08, 2021 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2022: { validOn: new Date('Mar 08, 2022 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2023: { validOn: new Date('Mar 08, 2023 00:00:00 GMT+0100').getTime(), discount: 60 },
  ORANGE2020: { validOn: new Date('May 04, 2020 00:00:00 GMT+0100').getTime(), discount: 50 },
  ORANGE2021: { validOn: new Date('May 04, 2021 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2022: { validOn: new Date('May 04, 2022 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2023: { validOn: new Date('May 04, 2023 00:00:00 GMT+0100').getTime(), discount: 40 }
}
