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
  type Sequelize
} from 'sequelize'

class Captcha extends Model<
InferAttributes<Captcha>,
InferCreationAttributes<Captcha>
> {
  declare id: CreationOptional<number>
  declare captchaId: number
  declare captcha: string
  declare answer: string
}

const CaptchaModelInit = (sequelize: Sequelize) => {
  Captcha.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      captchaId: {
        type: DataTypes.INTEGER
      },
      captcha: DataTypes.STRING,
      answer: DataTypes.STRING
    },
    {
      tableName: 'Captchas',
      sequelize
    }
  )
}

export { Captcha as CaptchaModel, CaptchaModelInit }
