import { describe, expect, it } from 'vitest';
import { NETWORK, p2tr, p2tr_ns, SigHash, Transaction } from '@scure/btc-signer';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';
import {
  assertMarketplaceRegistryIntegrity,
  MARKETPLACE_TEMPLATES,
} from '../../src/domain/marketplaces/registry';
import { inspectMarketplacePsbt, resolveMarketplaceRequest } from '../../src/domain/marketplaces/resolver';
import { analyzeMarketplaceCommitment } from '../../src/domain/marketplaces/commitment';
import {
  ORDNET_SALE_PUBLIC_KEY,
  verifyOrdnetSaleScriptPath,
} from '../../src/domain/marketplaces/ordnet-script-path';
import type { MarketplaceContext } from '../../src/domain/marketplaces/types';
import { assertOrdnetSubmitBinding, assertSequentialMarketplaceStep } from '../../src/domain/marketplaces/contracts';
import { PROVIDER_MAX_PSBT_OUTPUTS } from '../../src/domain/transactions/provider-psbt-limits';

const context: MarketplaceContext = {
  version: 1,
  marketplaceId: 'satflow',
  templateVersion: 'drey-1',
  action: 'list',
  role: 'seller',
  assetKind: 'inscription',
  workflowId: 'listing-1',
  step: 1,
  stepCount: 2,
  identifiers: { inscriptionId: `${'11'.repeat(32)}i0` },
  economics: {
    sellerProceedsSats: '20000',
    payoutAddress: 'bc1qexamplemarketplacepayout',
  },
  broadcaster: 'site',
};

function flexiblePsbt(sighash = SigHash.SINGLE_ANYONECANPAY): string {
  const tx = new Transaction({ lowR: true });
  tx.addInput({
    txid: '11'.repeat(32), index: 0, sighashType: sighash,
    witnessUtxo: { script: hexToBytes(`0014${'22'.repeat(20)}`), amount: 10_000n },
  });
  tx.addOutput({ script: hexToBytes(`0014${'33'.repeat(20)}`), amount: 20_000n });
  return bytesToBase64(tx.toPSBT());
}

it('rejects a marketplace PSBT with too many outputs before marketplace analysis', () => {
  const tx = new Transaction({ lowR: true });
  tx.addInput({
    txid: '11'.repeat(32), index: 0, sighashType: SigHash.ALL,
    witnessUtxo: { script: hexToBytes(`0014${'22'.repeat(20)}`), amount: 10_000n },
  });
  const script = hexToBytes(`0014${'33'.repeat(20)}`);
  for (let index = 0; index <= PROVIDER_MAX_PSBT_OUTPUTS; index += 1) {
    tx.addOutput({ script, amount: 1n });
  }
  expect(() => inspectMarketplacePsbt(bytesToBase64(tx.toPSBT())))
    .toThrow(`PSBT output count exceeds ${PROVIDER_MAX_PSBT_OUTPUTS}`);
});

describe('compile-time marketplace registry', () => {
  it('has exact HTTPS origins, no collisions, and only reviewed sighashes', () => {
    expect(() => assertMarketplaceRegistryIntegrity()).not.toThrow();
    expect(MARKETPLACE_TEMPLATES.length).toBeGreaterThan(8);
    expect(MARKETPLACE_TEMPLATES.every((entry) =>
      entry.origins.every((origin) => origin.startsWith('https://') && !origin.includes('*')))).toBe(true);
  });

  it('matches the pinned Satflow contract but activates neither it nor a new origin/version', () => {
    const candidate = inspectMarketplacePsbt(flexiblePsbt());
    expect(resolveMarketplaceRequest({
      origin: 'https://satflow.com', network: 'mainnet', method: 'signPsbt', context, candidate,
    })).toMatchObject({
      status: 'known_template_mismatch', templateId: 'satflow-list-ordinal', flexible: true,
      reason: expect.stringContaining('fixture-backed'),
    });
    expect(resolveMarketplaceRequest({
      origin: 'https://new-market.example', network: 'mainnet', method: 'signPsbt', context, candidate,
    })).toMatchObject({ status: 'unknown_marketplace', templateId: null });
    expect(resolveMarketplaceRequest({
      origin: 'https://satflow.com', network: 'mainnet', method: 'signPsbt',
      context: { ...context, templateVersion: 'remote-v2' }, candidate,
    })).toMatchObject({ status: 'known_marketplace_unknown_version', templateId: null });
    expect(MARKETPLACE_TEMPLATES.filter((entry) => entry.marketplaceId === 'satflow' &&
      !entry.origins.includes('https://ordinalmaxibiz.wiki'))
      .every((entry) => entry.activation === 'fixture_only')).toBe(true);
    // Reviewed 2026-08-10: ord.net single-inscription trading is enabled from
    // the published Trading API 1.0.0 contract; the v2 collection/trait
    // funding-parent design stays fixture-backed.
    expect(MARKETPLACE_TEMPLATES.filter((entry) => entry.marketplaceId === 'ordnet')
      .every((entry) => entry.activation ===
        (entry.assetKind === 'inscription' ? 'enabled' : 'fixture_only'))).toBe(true);
    expect(resolveMarketplaceRequest({
      origin: 'https://satflow.com', network: 'mainnet', method: 'signMessage',
      context: {
        ...context, action: 'authenticate', role: 'buyer', step: 1, stepCount: 1,
        identifiers: undefined, economics: undefined,
      },
    })).toMatchObject({ status: 'known_template_mismatch', reason: expect.stringContaining('fixture-backed') });
    expect(resolveMarketplaceRequest({
      origin: 'https://satflow.com', network: 'mainnet', method: 'signMessage',
      context: {
        ...context, action: 'cancel', step: 1, stepCount: 1,
        identifiers: { orderId: 'listing-1', inscriptionId: `${'11'.repeat(32)}i0` },
        economics: undefined, revision: 'challenge-1', expiresAt: 1_900_000_000_000,
      },
    })).toMatchObject({
      status: 'known_template_mismatch', templateId: 'satflow-cancel-listing',
      reason: expect.stringContaining('fixture-backed'),
    });
  });

  it('resolves the exact OMB Wiki origin by marketplace ID and rejects altered contracts', () => {
    const candidate = inspectMarketplacePsbt(flexiblePsbt(SigHash.ALL));
    const common: MarketplaceContext = {
      version: 1,
      marketplaceId: 'ordnet',
      templateVersion: 'omb-wiki-ordnet-buy-v1',
      action: 'buy', role: 'buyer', assetKind: 'inscription', workflowId: 'omb-buy-1',
      step: 1, stepCount: 1,
      identifiers: {
        listingId: 'listing-1', inscriptionId: `${'11'.repeat(32)}i0`,
        purchaseAnchorUtxoId: `${'22'.repeat(32)}:0`,
      },
      economics: {
        priceSats: '20000', totalSats: '21000', buyerDebitSats: '21000',
        assetDestination: 'bc1qombdestination',
      },
      selectedInputIndexes: [0], expectedTxids: ['33'.repeat(32), '44'.repeat(32)],
      expiresAt: 1_900_000_000_000, broadcaster: 'site',
    };
    expect(resolveMarketplaceRequest({
      origin: 'https://ordinalmaxibiz.wiki', network: 'mainnet', method: 'signPsbt',
      context: common, candidate, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'recognized', templateId: 'omb-wiki-ordnet-buy' });

    const satflow: MarketplaceContext = {
      ...common, marketplaceId: 'satflow', templateVersion: 'omb-wiki-satflow-secure-buy-v1',
      action: 'secure_buy', step: 2, stepCount: 2, stage: 'purchase',
      revision: 'preflight-digest', expectedTxids: undefined,
      identifiers: { listingId: 'listing-1', inscriptionId: `${'11'.repeat(32)}i0` },
    };
    expect(resolveMarketplaceRequest({
      origin: 'https://ordinalmaxibiz.wiki', network: 'mainnet', method: 'signPsbt',
      context: satflow, candidate, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'recognized', templateId: 'omb-wiki-satflow-secure-buy' });
    expect(resolveMarketplaceRequest({
      origin: 'https://www.ordinalmaxibiz.wiki', network: 'mainnet', method: 'signPsbt',
      context: common, candidate, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'unknown_marketplace' });
    expect(resolveMarketplaceRequest({
      origin: 'https://ordinalmaxibiz.wiki', network: 'mainnet', method: 'signPsbt',
      context: { ...common, marketplaceId: 'satflow' }, candidate, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'known_marketplace_unknown_version' });
  });

  it('recognizes an enabled ord.net request only with its full preflight binding', () => {
    const ordnetContext: MarketplaceContext = {
      version: 1,
      marketplaceId: 'ordnet',
      templateVersion: 'drey-1',
      action: 'list',
      role: 'seller',
      assetKind: 'inscription',
      workflowId: 'ordnet-listing-1',
      step: 2,
      stepCount: 3,
      identifiers: {
        inscriptionId: `${'11'.repeat(32)}i0`,
        preflightHandle: '66666666-6666-6666-6666-666666666666',
      },
      economics: {
        sellerProceedsSats: '20000',
        payoutAddress: 'bc1qexamplemarketplacepayout',
      },
      broadcaster: 'site',
    };
    const candidate = inspectMarketplacePsbt(flexiblePsbt());
    expect(resolveMarketplaceRequest({
      origin: 'https://ord.net', network: 'mainnet', method: 'signPsbt',
      context: ordnetContext, candidate, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'recognized', templateId: 'ordnet-list', flexible: true });
    // Without the anchor handle the same request must not be recognized.
    expect(resolveMarketplaceRequest({
      origin: 'https://ord.net', network: 'mainnet', method: 'signPsbt',
      context: { ...ordnetContext, identifiers: { inscriptionId: `${'11'.repeat(32)}i0` } },
      candidate, selectedInputIndexes: [0],
    })).toMatchObject({
      status: 'known_template_mismatch',
      reason: expect.stringContaining('preflight handle'),
    });
    // A purchase must bind the expected settlement txids from preflight.
    const buyContext: MarketplaceContext = {
      ...ordnetContext,
      action: 'buy',
      role: 'buyer',
      step: 1,
      stepCount: 1,
      identifiers: { preflightHandle: '77777777-7777-7777-7777-777777777777' },
      economics: { totalSats: '30000', assetDestination: 'bc1pexampleownedordinalsdestination' },
    };
    const deterministic = inspectMarketplacePsbt(flexiblePsbt(SigHash.ALL));
    expect(resolveMarketplaceRequest({
      origin: 'https://ord.net', network: 'mainnet', method: 'signPsbt',
      context: { ...buyContext, expectedTxids: ['aa'.repeat(32), 'bb'.repeat(32)] },
      candidate: deterministic, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'recognized', templateId: 'ordnet-buy', flexible: false });
    expect(resolveMarketplaceRequest({
      origin: 'https://ord.net', network: 'mainnet', method: 'signPsbt',
      context: buyContext, candidate: deterministic, selectedInputIndexes: [0],
    })).toMatchObject({ status: 'known_template_mismatch' });
    // The v2 collection funding-parent design stays fixture-backed.
    expect(resolveMarketplaceRequest({
      origin: 'https://ord.net', network: 'mainnet', method: 'signPsbt',
      context: {
        ...buyContext, action: 'collection_offer', assetKind: 'collection',
        identifiers: { preflightHandle: 'token-1' }, expectedTxids: ['cc'.repeat(32)],
        economics: undefined, stepCount: 1,
      },
      candidate: deterministic, selectedInputIndexes: [0],
    })).toMatchObject({
      status: 'known_template_mismatch',
      templateId: 'ordnet-collection-offer-v2',
      reason: expect.stringContaining('fixture-backed'),
    });
  });

  it('pins Satflow purchase and cancellation broadcaster ownership to the site', () => {
    const satflow = MARKETPLACE_TEMPLATES.filter((entry) => entry.marketplaceId === 'satflow');
    expect(satflow.filter((entry) => ['buy', 'secure_buy', 'list', 'cancel'].includes(entry.action))
      .every((entry) => entry.broadcaster === 'site')).toBe(true);
  });

  it('rejects flexible substitution and accounts only for the committed seller output', () => {
    const psbtBase64 = flexiblePsbt();
    const commitmentContext = {
      ...context,
      economics: { sellerProceedsSats: context.economics!.sellerProceedsSats },
    };
    const analysis = analyzeMarketplaceCommitment({
      psbtBase64, network: 'mainnet', context: commitmentContext, selectedInputIndexes: [0],
    });
    expect(analysis).toEqual({
      mode: 'partial',
      selectedInputIndexes: [0],
      guaranteedOutputIndexes: 'all',
      guaranteedProceedsSats: 20_000n,
      walletFeeExposureSats: 0n,
      uncommittedDimensions: ['external_inputs', 'non_corresponding_outputs'],
    });
    expect(() => analyzeMarketplaceCommitment({
      psbtBase64: flexiblePsbt(SigHash.NONE_ANYONECANPAY),
      network: 'mainnet', context: commitmentContext, selectedInputIndexes: [0],
    })).toThrow(/unsupported marketplace sighash/u);
    expect(analyzeMarketplaceCommitment({
      psbtBase64: flexiblePsbt(SigHash.ALL_ANYONECANPAY),
      network: 'mainnet',
      context: { ...context, economics: undefined },
      selectedInputIndexes: [0],
    })).toMatchObject({
      mode: 'partial', guaranteedOutputIndexes: 'all',
      uncommittedDimensions: ['external_inputs'],
    });
  });

  it('verifies the exact ord.net control block, pinned key, output key, and multi_a leaf', () => {
    const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    const account = deriveAccountNode(seed, 'ordinals', 'mainnet', 0);
    const seller = deriveAddress(account, 'ordinals', 'mainnet', 0, 0).publicKeyHex.slice(2);
    account.wipePrivateData();
    const leaf = p2tr_ns(2, [hexToBytes(seller), hexToBytes(ORDNET_SALE_PUBLIC_KEY)])[0]!;
    const passthrough = p2tr(hexToBytes(seller), { script: leaf.script }, NETWORK, true);
    const tx = new Transaction({ lowR: true });
    tx.addInput({
      txid: '44'.repeat(32), index: 0, sighashType: SigHash.SINGLE_ANYONECANPAY,
      witnessUtxo: { script: passthrough.script, amount: 10_000n },
      tapInternalKey: passthrough.tapInternalKey,
      tapMerkleRoot: passthrough.tapMerkleRoot,
      tapLeafScript: passthrough.tapLeafScript!,
    });
    tx.addOutput({ script: hexToBytes(`0014${'55'.repeat(20)}`), amount: 20_000n });
    expect(verifyOrdnetSaleScriptPath(tx, 0, seller)).toMatchObject({
      sellerPublicKey: seller,
      ordnetPublicKey: ORDNET_SALE_PUBLIC_KEY,
      disableTweakSigner: true,
    });
    expect(() => verifyOrdnetSaleScriptPath(tx, 0, '66'.repeat(32))).toThrow(/control block/u);
  });

  it('invalidates ord.net 409s, changed handles, and out-of-order sequential state', () => {
    expect(() => assertOrdnetSubmitBinding({
      preflightHandle: 'p1', originalHandle: 'p1', originalFieldsHash: 'a', submittedFieldsHash: 'a', httpStatus: 409,
    })).toThrow('ERR_MARKETPLACE_STATE_CHANGED');
    expect(() => assertOrdnetSubmitBinding({
      preflightHandle: 'p2', originalHandle: 'p1', originalFieldsHash: 'a', submittedFieldsHash: 'a',
    })).toThrow('ERR_MARKETPLACE_STATE_CHANGED');
    expect(() => assertSequentialMarketplaceStep({
      previousStep: 1, nextStep: 3, previousSignedHash: 'aa', suppliedPriorSignedHash: 'aa',
    })).toThrow('ERR_MARKETPLACE_STATE_CHANGED');
  });
});
