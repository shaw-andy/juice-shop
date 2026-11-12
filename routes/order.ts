/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
import { Op, literal } from 'sequelize'

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
import logger from '../lib/logger'
import * as db from '../data/mongodb'

interface Product {
  quantity: number
  id?: number
  name: string
  price: number
  total: number
  bonus: number
}

interface StockChange {
  ProductId: number
  quantity: number
}

interface AppliedOrderChanges {
  walletCharge: number
  bonus: number
  stock: StockChange[]
}

async function revertOrderChanges (UserId: number | undefined, applied: AppliedOrderChanges) {
  try {
    for (const change of applied.stock) {
      await QuantityModel.increment({ quantity: change.quantity }, { where: { ProductId: change.ProductId } })
    }
    if (UserId && (applied.walletCharge !== 0 || applied.bonus !== 0)) {
      await WalletModel.increment({ balance: applied.walletCharge - applied.bonus }, { where: { UserId } })
    }
  } catch (error: unknown) {
    logger.error(`Could not revert changes of failed order: ${utils.getErrorMessage(error)}`)
  }
}

export function placeOrder () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      .then(async (basket: BasketModel | null) => {
        if (basket != null) {
          const customer = security.authenticatedUsers.from(req)
          const email = customer ? customer.data ? customer.data.email : '' : ''
          const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)
          const pdfFile = `order_${orderId}.pdf`
          const date = new Date().toJSON().slice(0, 10)
          let totalPrice = 0
          const basketProducts: Product[] = []
          const stockChanges: StockChange[] = []
          let totalPoints = 0
          for (const { BasketItem, price, deluxePrice, name, id } of basket.Products ?? []) {
            if (BasketItem != null) {
              challengeUtils.solveIf(challenges.christmasSpecialChallenge, () => { return BasketItem.ProductId === products.christmasSpecial.id })
              stockChanges.push({ ProductId: BasketItem.ProductId, quantity: BasketItem.quantity })
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
              totalPrice += itemTotal
              totalPoints += itemBonus
            }
          }
          const discount = calculateApplicableDiscount(basket, req) ?? 0
          let discountAmount = '0'
          if (discount > 0) {
            discountAmount = (totalPrice * (discount / 100)).toFixed(2)
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

          challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

          const UserId = req.body.UserId
          const applied: AppliedOrderChanges = { walletCharge: 0, bonus: 0, stock: [] }
          if (UserId && req.body.orderDetails?.paymentId === 'wallet') {
            if (!Number.isFinite(totalPrice)) {
              next(new Error('Insufficient wallet balance.'))
              return
            }
            const [charged] = await WalletModel.update(
              { balance: literal(`balance - ${totalPrice}`) },
              { where: { UserId, balance: { [Op.gte]: totalPrice } } }
            )
            if (charged === 0) {
              next(new Error('Insufficient wallet balance.'))
              return
            }
            applied.walletCharge = totalPrice
          }

          try {
            for (const change of stockChanges) {
              await QuantityModel.decrement({ quantity: change.quantity }, { where: { ProductId: change.ProductId } })
              applied.stock.push(change)
            }
            if (UserId) {
              await WalletModel.increment({ balance: totalPoints }, { where: { UserId } })
              applied.bonus = totalPoints
            }
            await db.ordersCollection.insert({
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
            })
          } catch (error: unknown) {
            await revertOrderChanges(UserId, applied)
            next(error)
            return
          }

          const { default: PDFDocument } = await import('pdfkit')
          const doc = new PDFDocument()
          const fileWriter = doc.pipe(fs.createWriteStream(path.join('ftp/', pdfFile)))

          fileWriter.on('finish', () => {
            void (async () => {
              try {
                void basket.update({ coupon: null })
                await BasketItemModel.destroy({ where: { BasketId: id } })
                res.json({ orderConfirmation: orderId })
              } catch (error: unknown) {
                next(error)
              }
            })()
          })

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
          for (const product of basketProducts) {
            doc.text(`${product.quantity}x ${product.name} ${req.__('ea.')} ${product.price} = ${product.total}¤`)
            doc.moveDown()
          }
          doc.moveDown()
          if (discount > 0) {
            doc.text(discount + '% discount from coupon: -' + discountAmount + '¤')
            doc.moveDown()
          }
          doc.text(`${req.__('Delivery Price')}: ${deliveryAmount.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(20).text(`${req.__('Total Price')}: ${totalPrice.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(15).text(`${req.__('Bonus Points Earned')}: ${totalPoints}`)
          doc.font('Times-Roman').fontSize(15).text(`(${req.__('The bonus points from this order will be added 1:1 to your wallet ¤-fund for future purchases!')}`)
          doc.moveDown()
          doc.moveDown()
          doc.font('Times-Roman').fontSize(15).text(req.__('Thank you for your order!'))
          doc.end()
        } else {
          next(new Error(`Basket with id=${id} does not exist.`))
        }
      }).catch((error: unknown) => {
        next(error)
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
