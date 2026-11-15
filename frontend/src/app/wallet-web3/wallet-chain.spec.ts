/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { provideZoneChangeDetection } from '@angular/core'
import { of } from 'rxjs'
import { ethers } from 'ethers'

import { WalletWeb3Component } from './wallet-web3.component'
import { Web3SandboxComponent } from '../web3-sandbox/web3-sandbox.component'
import { FaucetComponent } from '../faucet/faucet.component'
import { KeysService } from '../Services/keys.service'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'

const SEPOLIA_CHAIN_ID = '0xaa36a7'
const MAINNET_CHAIN_ID = '0x1'
const ACCOUNT = '0x0000000000000000000000000000000000000001'
const BANK = '0x413744d59d31afdc2889aee602636177805bd7b0'

interface SubmittedTransaction {
  chainId: string
  tx: Record<string, string>
}

const wallet = vi.hoisted(() => {
  const sepolia = '0xaa36a7'
  const mainnet = '0x1'
  const account = '0x0000000000000000000000000000000000000001'
  const txHash = '0x' + 'ab'.repeat(32)
  const blockHash = '0x' + 'cd'.repeat(32)
  const state: {
    chainId: string
    mode: 'stable' | 'flip-after-sepolia'
    rejectAddChain: boolean
    sent: SubmittedTransaction[]
  } = {
    chainId: mainnet,
    mode: 'stable',
    rejectAddChain: false,
    sent: []
  }
  const listeners: Record<string, ((...args: unknown[]) => void)[]> = {}

  function word (byte: string): string {
    return '0x' + byte.repeat(32)
  }

  const ethereum = {
    isMetaMask: true,
    async request (args: { method: string, params?: unknown[] }) {
      const { method, params } = args
      if (method === 'eth_chainId') {
        const current = state.chainId
        if (state.mode === 'flip-after-sepolia' && current === sepolia) {
          state.chainId = mainnet
        }
        return current
      }
      if (method === 'eth_accounts' || method === 'eth_requestAccounts') {
        return [account]
      }
      if (method === 'eth_blockNumber') return '0x10'
      if (method === 'eth_estimateGas') return '0x5208'
      if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'
      if (method === 'eth_getBalance') return '0x8ac7230489e80000'
      if (method === 'eth_getTransactionCount') return '0x0'
      if (method === 'eth_call' || method === 'eth_getCode') return word('00')
      if (method === 'eth_getBlockByNumber') {
        return {
          number: '0x10',
          hash: blockHash,
          parentHash: word('11'),
          timestamp: '0x1',
          nonce: '0x0000000000000000',
          difficulty: '0x0',
          gasLimit: '0x1',
          gasUsed: '0x0',
          miner: '0x0000000000000000000000000000000000000000',
          extraData: '0x',
          transactions: [],
          baseFeePerGas: '0x1'
        }
      }
      if (method === 'wallet_addEthereumChain' || method === 'wallet_switchEthereumChain') {
        if (state.rejectAddChain) {
          const error = new Error('user rejected the request') as Error & { code: number }
          error.code = 4001
          throw error
        }
        return null
      }
      if (method === 'eth_sendTransaction') {
        const tx = (params?.[0] ?? {}) as Record<string, string>
        state.sent.push({ chainId: state.chainId, tx })
        return txHash
      }
      if (method === 'eth_getTransactionByHash') {
        const tx = state.sent[state.sent.length - 1]?.tx ?? {}
        return {
          hash: txHash,
          blockHash,
          blockNumber: '0x10',
          transactionIndex: '0x0',
          from: tx.from || account,
          gasPrice: '0x1',
          gas: tx.gas || '0x5208',
          to: tx.to || null,
          value: tx.value || '0x0',
          nonce: '0x0',
          input: tx.data || '0x',
          r: word('01'),
          s: word('02'),
          v: '0x1b'
        }
      }
      if (method === 'eth_getTransactionReceipt') {
        const tx = state.sent[state.sent.length - 1]?.tx ?? {}
        return {
          to: tx.to || null,
          from: tx.from || account,
          contractAddress: null,
          transactionIndex: '0x0',
          gasUsed: '0x5208',
          logsBloom: '0x' + '00'.repeat(256),
          blockHash,
          transactionHash: txHash,
          logs: [],
          blockNumber: '0x10',
          cumulativeGasUsed: '0x5208',
          status: '0x1',
          type: '0x0'
        }
      }
      throw new Error('unexpected wallet method ' + method)
    },
    on (event: string, cb: (...args: unknown[]) => void) {
      listeners[event] = listeners[event] || []
      listeners[event].push(cb)
    },
    removeListener (event: string, cb: (...args: unknown[]) => void) {
      listeners[event] = (listeners[event] || []).filter((listener) => listener !== cb)
    }
  }

  const browserWindow = (globalThis as { window?: { ethereum?: unknown } }).window ?? (globalThis as { ethereum?: unknown })
  browserWindow.ethereum = ethereum
  return { state, ethereum }
})

function useChain (chainId: string, mode: 'stable' | 'flip-after-sepolia' = 'stable'): void {
  wallet.state.chainId = chainId
  wallet.state.mode = mode
  wallet.state.rejectAddChain = false
  wallet.state.sent = []
}

function expectNoSubmission (): void {
  expect(wallet.state.sent).toEqual([])
}

describe('crypto wallet chain', () => {
  let fixture: ComponentFixture<WalletWeb3Component>
  let component: WalletWeb3Component

  beforeEach(async () => {
    useChain(MAINNET_CHAIN_ID)
    TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), WalletWeb3Component],
      providers: [
        {
          provide: KeysService,
          useValue: {
            walletAddressSend: vi.fn().mockReturnValue(of({ success: true, status: true }))
          }
        },
        { provide: SnackBarHelperService, useValue: { open: vi.fn() } },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        provideZoneChangeDetection()
      ]
    })
    fixture = TestBed.createComponent(WalletWeb3Component)
    component = fixture.componentInstance
    component.metamaskAddress = ACCOUNT
    component.inputAmount = 2
  })

  it('does not ask the wallet to deposit when the selected chain is mainnet', async () => {
    await component.handleAuth()
    expect(component.session).toBe(false)

    fixture.detectChanges()
    const button = fixture.nativeElement.querySelector('[aria-label="Button to deposit"]') as HTMLButtonElement
    const call = vi.spyOn(component, 'depositETH')
    button.click()
    expect(call).toHaveBeenCalled()
    await call.mock.results[0].value

    expectNoSubmission()
  })

  it('does not ask the wallet to deposit when adding Sepolia is rejected', async () => {
    wallet.state.rejectAddChain = true
    await component.handleAuth()
    expect(component.session).toBe(false)

    await component.depositETH()

    expectNoSubmission()
  })

  it('does not ask the wallet to withdraw when the selected chain is mainnet', async () => {
    await component.handleAuth()

    await component.withdrawETH()

    expectNoSubmission()
  })

  it('does not deposit after connect when the wallet has since left Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    await component.handleAuth()
    expect(component.session).toBe(true)

    useChain(MAINNET_CHAIN_ID)
    component.inputAmount = 2
    await component.depositETH()

    expectNoSubmission()
  })

  it('does not withdraw after connect when the wallet has since left Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    await component.handleAuth()
    expect(component.session).toBe(true)

    useChain(MAINNET_CHAIN_ID)
    component.inputAmount = 2
    await component.withdrawETH()

    expectNoSubmission()
  })

  it('does not deposit when the chain changes after it is read and before the wallet is asked to sign', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.inputAmount = 2
    wallet.state.mode = 'flip-after-sepolia'

    await component.depositETH()

    expectNoSubmission()
  })

  it('does not withdraw when the chain changes after it is read and before the wallet is asked to sign', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.inputAmount = 2
    wallet.state.mode = 'flip-after-sepolia'

    await component.withdrawETH()

    expectNoSubmission()
  })

  it('deposits the typed amount on Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.inputAmount = 2

    await component.depositETH()

    expect(wallet.state.sent).toHaveLength(1)
    expect(wallet.state.sent[0].chainId).toBe(SEPOLIA_CHAIN_ID)
    expect(wallet.state.sent[0].tx.to).toBe(BANK.toLowerCase())
    expect(wallet.state.sent[0].tx.value).toBe(ethers.utils.parseEther('2').toHexString())
  })

  it('withdraws on Sepolia without attaching a payment value', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.inputAmount = 2

    await component.withdrawETH()

    expect(wallet.state.sent).toHaveLength(1)
    expect(wallet.state.sent[0].chainId).toBe(SEPOLIA_CHAIN_ID)
    expect(wallet.state.sent[0].tx.to).toBe(BANK.toLowerCase())
    expect(wallet.state.sent[0].tx.value).toBeUndefined()
  })
})

describe('web3 sandbox chain', () => {
  let component: Web3SandboxComponent

  beforeEach(() => {
    useChain(MAINNET_CHAIN_ID)
    TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), Web3SandboxComponent],
      providers: [
        { provide: KeysService, useValue: {} },
        { provide: SnackBarHelperService, useValue: { open: vi.fn() } },
        provideZoneChangeDetection()
      ]
    })
    component = TestBed.createComponent(Web3SandboxComponent).componentInstance
    ;(component as unknown as { compiledContracts: unknown }).compiledContracts = {
      Test: {
        abi: [{
          type: 'constructor',
          stateMutability: 'payable',
          inputs: []
        }, {
          name: 'pay',
          type: 'function',
          stateMutability: 'payable',
          inputs: [],
          outputs: []
        }],
        evm: { bytecode: { object: '00' } }
      }
    }
    component.selectedContractName = 'Test'
    component.commonGweiValue = 5
    component.metamaskAddress = ACCOUNT
  })

  async function connectOnSepoliaThenLeave (): Promise<void> {
    useChain(SEPOLIA_CHAIN_ID)
    await component.handleAuth()
    expect(component.session).toBe(true)
    useChain(MAINNET_CHAIN_ID)
  }

  it('does not deploy with value when the wallet has left Sepolia since connect', async () => {
    await connectOnSepoliaThenLeave()

    await component.deploySelectedContract()

    expectNoSubmission()
  })

  it('does not invoke a payable function when the wallet has left Sepolia since connect', async () => {
    await connectOnSepoliaThenLeave()
    component.deployedContractAddress = '0x0000000000000000000000000000000000000002'
    const func = {
      name: 'pay',
      inputs: [],
      outputs: [],
      stateMutability: 'payable',
      inputValues: '',
      outputValue: ''
    }

    await component.invokeFunction(func)

    expectNoSubmission()
  })

  it('does not deploy when the chain changes after it is read and before the wallet is asked to sign', async () => {
    component.session = true
    useChain(SEPOLIA_CHAIN_ID, 'flip-after-sepolia')

    await component.deploySelectedContract()

    expectNoSubmission()
  })

  it('deploys with the typed value on Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.session = true

    await component.deploySelectedContract()

    expect(wallet.state.sent).toHaveLength(1)
    expect(wallet.state.sent[0].chainId).toBe(SEPOLIA_CHAIN_ID)
    expect(ethers.BigNumber.from(wallet.state.sent[0].tx.value).eq(ethers.utils.parseUnits('5', 'gwei'))).toBe(true)
    expect(wallet.state.sent[0].tx.to ?? null).toBeNull()
  })

  it('invokes a payable function on Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.session = true
    component.deployedContractAddress = '0x0000000000000000000000000000000000000002'
    const func = {
      name: 'pay',
      inputs: [],
      outputs: [],
      stateMutability: 'payable',
      inputValues: '',
      outputValue: ''
    }

    await component.invokeFunction(func)

    expect(wallet.state.sent).toHaveLength(1)
    expect(wallet.state.sent[0].chainId).toBe(SEPOLIA_CHAIN_ID)
    expect(wallet.state.sent[0].tx.to).toBe('0x0000000000000000000000000000000000000002')
    expect(ethers.BigNumber.from(wallet.state.sent[0].tx.value).eq(ethers.utils.parseUnits('5', 'gwei'))).toBe(true)
  })

  it('does not invoke when the chain changes after it is read and before the wallet is asked to sign', async () => {
    component.session = true
    component.deployedContractAddress = '0x0000000000000000000000000000000000000002'
    useChain(SEPOLIA_CHAIN_ID, 'flip-after-sepolia')
    const func = {
      name: 'pay',
      inputs: [],
      outputs: [],
      stateMutability: 'payable',
      inputValues: '',
      outputValue: ''
    }

    await component.invokeFunction(func)

    expectNoSubmission()
  })
})

describe('faucet chain', () => {
  let component: FaucetComponent

  beforeEach(() => {
    useChain(MAINNET_CHAIN_ID)
    TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot(), FaucetComponent],
      providers: [
        {
          provide: KeysService,
          useValue: {
            checkNftMinted: vi.fn().mockReturnValue(of({ data: [{ solved: false }] })),
            nftMintListen: vi.fn().mockReturnValue(of({})),
            verifyNFTWallet: vi.fn().mockReturnValue(of({ success: true }))
          }
        },
        { provide: SnackBarHelperService, useValue: { open: vi.fn() } },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        provideZoneChangeDetection()
      ]
    })
    component = TestBed.createComponent(FaucetComponent).componentInstance
    component.metamaskAddress = ACCOUNT
    component.withdrawAmount = 1
  })

  async function connectOnSepoliaThenLeave (): Promise<void> {
    useChain(SEPOLIA_CHAIN_ID)
    await component.handleAuth()
    expect(component.session).toBe(true)
    useChain(MAINNET_CHAIN_ID)
  }

  it('does not withdraw faucet tokens when the wallet has left Sepolia since connect', async () => {
    await connectOnSepoliaThenLeave()

    await component.extractBEETokens()

    expectNoSubmission()
  })

  it('does not approve or mint when the wallet has left Sepolia since connect', async () => {
    await connectOnSepoliaThenLeave()

    await component.mintNFT()

    expectNoSubmission()
  })

  it('does not withdraw faucet tokens when the chain changes after it is read and before the wallet is asked to sign', async () => {
    component.session = true
    useChain(SEPOLIA_CHAIN_ID, 'flip-after-sepolia')

    await component.extractBEETokens()

    expectNoSubmission()
  })

  it('withdraws faucet tokens on Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.session = true

    await component.extractBEETokens()

    expect(wallet.state.sent).toHaveLength(1)
    expect(wallet.state.sent[0].chainId).toBe(SEPOLIA_CHAIN_ID)
    expect(wallet.state.sent[0].tx.to).toBe('0x860e3616ad0e0dedc23352891f3e10c4131ea5bc')
  })

  it('approves and mints on Sepolia', async () => {
    useChain(SEPOLIA_CHAIN_ID)
    component.session = true

    await component.mintNFT()

    expect(wallet.state.sent).toHaveLength(2)
    expect(wallet.state.sent.every((submission) => submission.chainId === SEPOLIA_CHAIN_ID)).toBe(true)
  })

  it('does not approve or mint when the chain changes after it is read and before the wallet is asked to sign', async () => {
    component.session = true
    useChain(SEPOLIA_CHAIN_ID, 'flip-after-sepolia')

    await component.mintNFT()

    expectNoSubmission()
  })
})
