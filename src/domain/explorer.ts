import type { Network } from './keys/derivation';

export function mempoolTransactionUrl(network: Network, txid: string): string {
  if (network === 'regtest') return `http://127.0.0.1:18481/tx/${txid}`;
  return `https://mempool.space${network === 'signet' ? '/signet' : ''}/tx/${txid}`;
}
