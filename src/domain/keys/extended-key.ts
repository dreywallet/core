import type { Network } from './derivation';

/** Mainnet uses xpub/xprv; signet and regtest use tpub/tprv. */
export function bip32Versions(network: Network): { private: number; public: number } {
  return network === 'mainnet'
    ? { private: 0x0488_ade4, public: 0x0488_b21e }
    : { private: 0x0435_8394, public: 0x0435_87cf };
}
