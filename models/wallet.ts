/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize,
  Op
} from 'sequelize'

class Wallet extends Model<
InferAttributes<Wallet>,
InferCreationAttributes<Wallet>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare balance: CreationOptional<number>
}

const WalletModelInit = (sequelize: Sequelize) => {
  Wallet.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      balance: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true
        },
        defaultValue: 0
      }
    },
    {
      tableName: 'Wallets',
      sequelize
    }
  )
}

// On SQLite, Model.decrement resolves to [[result, affectedCount]]
const debitWallet = async (wallet: Wallet, amount: number) => {
  const [result] = await Wallet.decrement({ balance: amount }, { where: { id: wallet.id, UserId: wallet.UserId, balance: { [Op.gte]: amount } } })
  const [, affectedCount] = result as unknown as [unknown, number]
  return affectedCount === 1
}

export { Wallet as WalletModel, WalletModelInit, debitWallet }
