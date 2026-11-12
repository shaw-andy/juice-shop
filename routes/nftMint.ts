import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import { getAddress } from 'ethers/address'
import { verifyMessage } from 'ethers/hash'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set<string>()
let isEventListenerCreated = false

const claimNonceTtlMs = 5 * 60 * 1000
const pendingClaims = new Map<number, { nonce: string, walletAddress: string, expiresAt: number }>()

export function mintClaimMessage (userId: number, walletAddress: string, nonce: string) {
  return `juice-shop nft mint\nuserId:${userId}\nwallet:${walletAddress}\nnonce:${nonce}`
}

function toChecksumAddress (value: unknown) {
  if (typeof value !== 'string') return undefined
  try {
    return getAddress(value)
  } catch {
    return undefined
  }
}

function nonceMatches (submitted: unknown, issued: string) {
  if (typeof submitted !== 'string') return false
  const a = Buffer.from(submitted)
  const b = Buffer.from(issued)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

function isSignedBy (message: string, signature: unknown, walletAddress: string) {
  if (typeof signature !== 'string') return false
  try {
    return getAddress(verifyMessage(message, signature)) === walletAddress
  } catch {
    return false
  }
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    try {
      if (!isEventListenerCreated) {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.error(`WebSocket error (NFT Mint Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(nftAddress, nftABI, provider as any)
        void contract.on('NFTMinted', (minter: string) => {
          const minterAddress = toChecksumAddress(minter)
          if (minterAddress) {
            addressesMinted.add(minterAddress)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTNonce () {
  return (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      res.status(401).json({ success: false, message: 'Authentication required' })
      return
    }
    const walletAddress = toChecksumAddress(req.body.walletAddress)
    if (!walletAddress) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    const userId = user.data.id
    const nonce = crypto.randomBytes(32).toString('hex')
    pendingClaims.set(userId, { nonce, walletAddress, expiresAt: Date.now() + claimNonceTtlMs })
    res.status(200).json({ success: true, nonce, message: mintClaimMessage(userId, walletAddress, nonce) })
  }
}

export function walletNFTVerify () {
  return async (req: Request, res: Response) => {
    try {
      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).json({ success: false, message: 'Authentication required', status: challenges.nftMintChallenge })
        return
      }
      const userId = user.data.id
      const claim = pendingClaims.get(userId)
      pendingClaims.delete(userId)

      const walletAddress = toChecksumAddress(req.body.walletAddress)
      if (!claim || claim.expiresAt < Date.now() || walletAddress !== claim.walletAddress ||
        !nonceMatches(req.body.nonce, claim.nonce) ||
        !isSignedBy(mintClaimMessage(userId, claim.walletAddress, claim.nonce), req.body.signature, claim.walletAddress)) {
        res.status(200).json({ success: false, message: 'Wallet ownership could not be verified', status: challenges.nftMintChallenge })
        return
      }

      if (!addressesMinted.delete(claim.walletAddress)) {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
        return
      }

      const challenge = challenges.nftMintChallenge
      if (challengeUtils.notSolved(challenge)) {
        challenge.solvedByUserId = userId
        await challengeUtils.solve(challenge)
      }
      res.status(200).json({ success: true, message: 'Challenge successfully solved', solvedForUserId: challenge.solvedByUserId, status: challenge })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
