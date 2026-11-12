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

class ImageCaptcha extends Model<
InferAttributes<ImageCaptcha>,
InferCreationAttributes<ImageCaptcha>
> {
  declare id: CreationOptional<number>
  declare image: CreationOptional<string>
  declare answer: string
  declare UserId: number
  declare createdAt: CreationOptional<Date>
}

const ImageCaptchaModelInit = (sequelize: Sequelize) => {
  ImageCaptcha.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      image: { type: DataTypes.STRING, defaultValue: '' }, // the SVG is only sent to the client, never persisted
      answer: DataTypes.STRING,
      UserId: { type: DataTypes.INTEGER, unique: true },
      createdAt: DataTypes.DATE
    },
    {
      tableName: 'ImageCaptchas',
      sequelize
    }
  )
}

export { ImageCaptcha as ImageCaptchaModel, ImageCaptchaModelInit }
