import { ethers } from 'ethers'

export const SEPOLIA_CHAIN_ID = 11155111

// A provider pinned to Sepolia throws on any call made while the wallet reports another chain.
export function sepoliaProvider (): ethers.providers.Web3Provider {
  return new ethers.providers.Web3Provider(window.ethereum, SEPOLIA_CHAIN_ID)
}

// The chainId travels with the request so the wallet refuses to sign it on any other chain.
// The wallet's chain is also read uncached right before handing the request over, because
// ethers caches its own network lookup and some wallets ignore the request's chainId.
export async function sendOnSepolia (signer: ethers.providers.JsonRpcSigner, transaction: ethers.providers.TransactionRequest): Promise<ethers.providers.TransactionResponse> {
  const request: ethers.providers.TransactionRequest = { ...transaction, chainId: SEPOLIA_CHAIN_ID }
  request.gasLimit ??= await signer.estimateGas(request)
  const walletChainId = await signer.provider.send('eth_chainId', [])
  if (ethers.BigNumber.from(walletChainId).toNumber() !== SEPOLIA_CHAIN_ID) {
    throw new Error('Switch your wallet to the Sepolia test network before sending a transaction.')
  }
  return await signer.sendTransaction(request)
}
