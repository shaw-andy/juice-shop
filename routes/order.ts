/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
import { Op, Sequelize } from 'sequelize'

import { challenges, products } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { BasketItemModel } from '../models/basketitem'
import { DeliveryModel } from '../models/delivery'
import { QuantityModel } from '../models/quantity'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import { WalletModel } from '../models/wallet'
import { exclusiveTransaction, sequelize } from '../models/index'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import * as db from '../data/mongodb'

interface Product {
  quantity: number
  id?: number
  name: string
  price: number
  total: number
  bonus: number
}

export function placeOrder () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (basket == null) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }
      const customer = security.authenticatedUsers.from(req)
      const email = customer ? customer.data ? customer.data.email : '' : ''
      const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)
      const isDeluxe = security.isDeluxe(req)

      let totalPrice = 0
      const basketItems: BasketItemModel[] = []
      const basketProducts: Product[] = []
      let totalPoints = 0
      for (const { BasketItem, price, deluxePrice, name, id } of basket.Products ?? []) {
        if (BasketItem != null) {
          challengeUtils.solveIf(challenges.christmasSpecialChallenge, () => { return BasketItem.ProductId === products.christmasSpecial.id })
          const itemPrice = isDeluxe ? deluxePrice : price
          const itemTotal = itemPrice * BasketItem.quantity
          const itemBonus = Math.round(itemPrice / 10) * BasketItem.quantity
          basketItems.push(BasketItem)
          basketProducts.push({
            quantity: BasketItem.quantity,
            id,
            name: req.__(name),
            price: itemPrice,
            total: itemTotal,
            bonus: itemBonus
          })
          totalPrice += itemTotal
          totalPoints += itemBonus
        }
      }
      if (basketItems.length === 0) {
        next(new Error(`Basket with id=${id} is empty.`))
        return
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
      const deliveryAmount = isDeluxe ? deliveryMethod.deluxePrice : deliveryMethod.price
      totalPrice += deliveryAmount

      challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

      await exclusiveTransaction(async (transaction) => {
        const claimedItems = await BasketItemModel.destroy({
          where: { BasketId: id, [Op.or]: basketItems.map(({ id, ProductId, quantity }) => ({ id, ProductId, quantity })) },
          transaction
        })
        if (claimedItems !== basketItems.length) {
          throw new Error(`Basket with id=${id} has already been checked out.`)
        }
        await basket.update({ coupon: null }, { transaction })
        for (const { ProductId, quantity } of basketItems) {
          const quantityRow = await QuantityModel.findOne({ where: { ProductId }, transaction })
          if (quantityRow) {
            await quantityRow.decrement('quantity', { by: quantity, transaction })
          }
        }
        if (req.body.UserId) {
          if (req.body.orderDetails && req.body.orderDetails.paymentId === 'wallet') {
            const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId }, transaction })
            const [debitedWallets] = wallet != null
              ? await WalletModel.update(
                { balance: Sequelize.literal(`balance - ${sequelize.escape(totalPrice)}`) },
                { where: { id: wallet.id, balance: { [Op.gte]: totalPrice } }, transaction }
              )
              : [0]
            if (debitedWallets !== 1) {
              throw new Error('Insufficient wallet balance.')
            }
          }
          await WalletModel.increment({ balance: totalPoints }, { where: { UserId: req.body.UserId }, transaction })
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
      })

      const { default: PDFDocument } = await import('pdfkit')
      const doc = new PDFDocument()
      const date = new Date().toJSON().slice(0, 10)
      const fileWriter = doc.pipe(fs.createWriteStream(path.join('ftp/', `order_${orderId}.pdf`)))
      fileWriter.on('finish', () => {
        res.json({ orderConfirmation: orderId })
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
      for (const { quantity, name, price, total } of basketProducts) {
        doc.text(`${quantity}x ${name} ${req.__('ea.')} ${price} = ${total}¤`)
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
    } catch (error: unknown) {
      next(error)
    }
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
