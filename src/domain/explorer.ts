import type { Network } from './keys/derivation';

export function mempoolTransactionUrl(network: Network, txid: string): string {
  return `https://mempool.space${network === 'signet' ? '/signet' : ''}/tx/${txid}`;
}
