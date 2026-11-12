/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../..')
const bankPath = path.join(repoRoot, 'data/static/web3-snippets/ETHWalletBank.sol')
const testSourcePath = path.join(here, 'EthWalletBankReentrancy.sol')
const safeMathPath = path.join(here, 'fixtures/SafeMath.sol')
const safeMathUrl = 'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v3.3/contracts/math/SafeMath.sol'
const safeMathSha256 = '38e47d1b5299ce0d5e48db837ed9248449043c50d90ffa0ee2ceb58ffde942c2'
const modules = process.env.ETH_WALLET_EVM_MODULES || '/tmp/eth-wallet-bank-reentrancy/node_modules'

const ether = 10n ** 18n
const credit = ether / 10n
const funded = (16n * ether) / 10n
const otherDeposits = (15n * ether) / 10n

const cases = [
  {
    name: 'single reentry during withdraw cannot pay more than the credited 0.1 ether or wrap the ledger',
    signature: 'testSingleReentrantWithdrawCannotExceedCredit()',
    value: funded,
    security: true
  },
  {
    name: 'reentry through the early-return guard cannot drain a later 0.1 ether withdrawal',
    signature: 'testUnlimitedReentrantWithdrawThenDrainCannotTakeVictimEther()',
    value: funded,
    security: true
  },
  {
    name: 'honest withdraw pays the credited 0.1 ether once and debits that same account',
    signature: 'testHonestWithdrawPaysCreditOnce()',
    value: credit,
    security: false
  }
]

function loadToolchain () {
  const pkg = path.join(path.dirname(modules), 'package.json')
  assert.ok(fs.existsSync(pkg), `install solc@0.6.12 and @ethereumjs/vm@8.1.1 under ${path.dirname(modules)}`)
  const require = createRequire(pkg)
  return {
    solc: require('solc'),
    VM: require('@ethereumjs/vm').VM,
    Common: require('@ethereumjs/common').Common,
    Chain: require('@ethereumjs/common').Chain,
    Hardfork: require('@ethereumjs/common').Hardfork,
    Address: require('@ethereumjs/util').Address,
    Account: require('@ethereumjs/util').Account,
    bytesToHex: require('@ethereumjs/util').bytesToHex,
    keccak256: require('ethereum-cryptography/keccak').keccak256
  }
}

function compile (solc, bankSource) {
  const imported = bankSource.match(/import\s+'([^']+)'/)
  assert.ok(imported, 'ETHWalletBank.sol does not import SafeMath by URL')
  assert.equal(imported[1], safeMathUrl)
  const fixture = fs.readFileSync(safeMathPath)
  assert.equal(createHash('sha256').update(fixture).digest('hex'), safeMathSha256)
  const input = {
    language: 'Solidity',
    sources: {
      'ETHWalletBank.sol': { content: bankSource },
      'EthWalletBankReentrancy.sol': { content: fs.readFileSync(testSourcePath, 'utf8') }
    },
    settings: {
      outputSelection: {
        '*': {
          '*': ['evm.bytecode.object', 'metadata']
        }
      }
    }
  }
  const output = JSON.parse(solc.compile(JSON.stringify(input), {
    import: (importPath) => {
      if (importPath === safeMathUrl) return { contents: fixture.toString('utf8') }
      return { error: 'File not found: ' + importPath }
    }
  }))
  const errors = (output.errors || []).filter((entry) => entry.severity === 'error')
  assert.deepEqual(errors.map((entry) => entry.formattedMessage), [])
  const contract = output.contracts['EthWalletBankReentrancy.sol'].EthWalletBankReentrancyTest
  const metadata = JSON.parse(contract.metadata)
  return {
    bytecode: Buffer.from(contract.evm.bytecode.object, 'hex'),
    evmVersion: metadata.settings.evmVersion,
    compiler: metadata.compiler.version
  }
}

function selector (keccak256, signature) {
  return Buffer.from(keccak256(Buffer.from(signature))).subarray(0, 4)
}

function decodeUint (returnValue, index) {
  const start = index * 32
  return BigInt('0x' + Buffer.from(returnValue.subarray(start, start + 32)).toString('hex'))
}

function assertWithdrawalIsBounded (returnValue) {
  const attackerBal = decodeUint(returnValue, 0)
  const recorded = decodeUint(returnValue, 1)
  const bankBal = decodeUint(returnValue, 2)
  const victimRecorded = decodeUint(returnValue, 3)
  const problems = []
  if (attackerBal > credit) problems.push(`attacker received ${attackerBal} wei after being credited ${credit} wei`)
  if (recorded > credit) problems.push(`attacker ledger is ${recorded} wei`)
  if (victimRecorded !== ether) problems.push(`victim ledger is ${victimRecorded} wei`)
  if (bankBal < otherDeposits) problems.push(`bank holds ${bankBal} wei, below the other deposits of ${otherDeposits} wei`)
  if (bankBal + attackerBal !== funded) problems.push(`bank ${bankBal} plus attacker ${attackerBal} is not the funded ${funded} wei`)
  assert.deepEqual(problems, [])
}

function revertReason (returnValue, bytesToHex) {
  if (!returnValue || returnValue.length < 68) return bytesToHex(returnValue || new Uint8Array())
  const selectorHex = Buffer.from(returnValue.subarray(0, 4)).toString('hex')
  if (selectorHex !== '08c379a0') return bytesToHex(returnValue)
  const length = Number(BigInt('0x' + Buffer.from(returnValue.subarray(36, 68)).toString('hex')))
  return Buffer.from(returnValue.subarray(68, 68 + length)).toString('utf8')
}

async function runCase (tools, compiled, testCase) {
  const { VM, Common, Chain, Hardfork, Address, Account } = tools
  assert.equal(compiled.evmVersion, 'istanbul')
  const vm = await VM.create({
    common: new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Istanbul })
  })
  const caller = Address.fromString('0x1111111111111111111111111111111111111111')
  await vm.stateManager.putAccount(caller, new Account(0n, 10n * 10n ** 18n))
  const deployed = await vm.evm.runCall({
    caller,
    data: compiled.bytecode,
    gasLimit: 12_000_000n
  })
  assert.equal(deployed.execResult.exceptionError, undefined, revertReason(deployed.execResult.returnValue, tools.bytesToHex))
  const result = await vm.evm.runCall({
    caller,
    to: deployed.createdAddress,
    data: selector(tools.keccak256, testCase.signature),
    value: testCase.value,
    gasLimit: 12_000_000n
  })
  const error = result.execResult.exceptionError
  assert.equal(error, undefined, error ? `${error.error}: ${revertReason(result.execResult.returnValue, tools.bytesToHex)}` : '')
  if (testCase.security) assertWithdrawalIsBounded(result.execResult.returnValue)
}

const tools = loadToolchain()
const compiled = compile(tools.solc, fs.readFileSync(bankPath, 'utf8'))

describe('ETHWalletBank withdraw reentrancy', () => {
  for (const testCase of cases) {
    it(testCase.name, async () => {
      assert.match(tools.solc.version(), /^0\.6\.12\+commit\.27d51765/)
      assert.match(compiled.compiler, /^0\.6\.12\+commit\.27d51765/)
      await runCase(tools, compiled, testCase)
    })
  }
})
