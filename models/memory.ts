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

export const MEMORY_CAPTION_MAX_LENGTH = 200

class Memory extends Model<
InferAttributes<Memory>,
InferCreationAttributes<Memory>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare caption: string
  declare imagePath: string
}

const MemoryModelInit = (sequelize: Sequelize) => {
  Memory.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      caption: {
        type: DataTypes.STRING(MEMORY_CAPTION_MAX_LENGTH),
        validate: { len: [0, MEMORY_CAPTION_MAX_LENGTH] }
      },
      imagePath: DataTypes.STRING
    },
    {
      tableName: 'Memories',
      sequelize
    }
  )
}

export { Memory as MemoryModel, MemoryModelInit }
