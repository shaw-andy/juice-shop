/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

// The database is recreated on every startup, so a key that only ever lives in process memory suffices
// and keeps stored card rows unreadable for anything that can only read the database.
const encryptionKey = crypto.randomBytes(32)
const invalidValue = 'invalid'

type EncryptedField = 'fullName' | 'cardNum' | 'expMonth' | 'expYear'

function encrypt (plaintext: string, field: EncryptedField): string {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv).setAAD(Buffer.from(field))
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return [iv, cipher.getAuthTag(), ciphertext].map(part => part.toString('base64')).join('.')
}

function decrypt (stored: string, field: EncryptedField): string {
  const [iv, authTag, ciphertext] = stored.split('.').map(part => Buffer.from(part, 'base64'))
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv).setAAD(Buffer.from(field))
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}

// Only the last four digits are kept. Numbers beyond Number.MAX_SAFE_INTEGER were already altered by JSON parsing, so they are refused.
function lastFourDigits (value: unknown): string | null {
  const digits = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value
  return typeof digits === 'string' && /^[1-9]\d{15}$/.test(digits) ? digits.slice(-4) : null
}

function integerInRange (min: number, max: number) {
  return (value: unknown): string | null => {
    const number = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value
    return typeof number === 'number' && Number.isInteger(number) && number >= min && number <= max ? String(number).padStart(String(max).length, '0') : null
  }
}

function encryptedAttribute (field: EncryptedField, toPlaintext: (value: unknown) => string | null, fromPlaintext: (plaintext: string) => string | number) {
  return {
    type: DataTypes.STRING,
    get (this: Model) {
      const stored = this.getDataValue(field)
      return stored == null || stored === invalidValue ? null : fromPlaintext(decrypt(stored, field))
    },
    set (this: Model, value: unknown) {
      const plaintext = value == null ? null : toPlaintext(value)
      this.setDataValue(field, value == null ? null : plaintext === null ? invalidValue : encrypt(plaintext, field))
    },
    validate: {
      isValid (value: unknown) {
        if (value === invalidValue) {
          throw new Error(`Validation failed for ${field}`)
        }
      }
    }
  }
}

class Card extends Model<
InferAttributes<Card>,
InferCreationAttributes<Card>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare fullName: string
  declare cardNum: string
  declare expMonth: number
  declare expYear: number
}

const CardModelInit = (sequelize: Sequelize) => {
  Card.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      fullName: encryptedAttribute('fullName', String, plaintext => plaintext),
      cardNum: encryptedAttribute('cardNum', lastFourDigits, plaintext => plaintext),
      expMonth: encryptedAttribute('expMonth', integerInRange(1, 12), Number),
      expYear: encryptedAttribute('expYear', integerInRange(2080, 2099), Number)
    },
    {
      tableName: 'Cards',
      sequelize
    }
  )
}

export { Card as CardModel, CardModelInit }
