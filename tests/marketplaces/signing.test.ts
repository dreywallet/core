import { beforeAll, describe, expect, it } from 'vitest';
import { NETWORK, p2tr, p2tr_ns, SigHash, Transaction } from '@scure/btc-signer';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { scriptPubKeyHex } from '../../src/domain/keys/script-hash';
import { bytesToBase64, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import {
  bindProviderPsbtPlanPreviews,
  createProviderPsbtPlan,
  signProviderPsbtPlan,
  type ProviderPsbtPlanV3,
} from '../../src/domain/transactions/provider-psbt';
import type { UtxoClassification } from '../../src/domain/gateway/contract';
import { ORDNET_SALE_PUBLIC_KEY } from '../../src/domain/marketplaces/ordnet-script-path';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';

beforeAll(() => installTestCryptoProvider());

const marketplaceSeed = mnemonicToSeed(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
);
const marketplaceAccountId = publicAccountFromSeed(marketplaceSeed, 'mainnet', 0).accountId;

function bindUnavailable(plan: ProviderPsbtPlanV3): ProviderPsbtPlanV3 {
  return bindProviderPsbtPlanPreviews(plan, {
    transactionCommitmentHash: plan.transactionCommitmentHash,
    analysisHash: plan.analysisHash,
    psbtHash: plan.psbtHash,
    effectSetHash: plan.analysis.assetEffects.effectSetHash,
    classificationRevision: plan.source.classificationRevision,
    verifiedAtMs: plan.createdAt,
    items: plan.analysis.assetEffects.inscriptions.map((effect) => ({
      metadata: {
        inscriptionId: effect.inscriptionId, satpoint: effect.satpoint, outpoint: effect.outpoint,
        classificationRevision: plan.source.classificationRevision, number: null, contentType: null,
        contentLength: null, confirmations: 1, parent: null, delegate: null,
        reinscription: false, cursed: false,
      },
      preview: {
        disposition: 'placeholder' as const, reason: 'unavailable' as const,
        requestedInscriptionId: effect.inscriptionId, sourceInscriptionId: effect.inscriptionId,
        resolvedInscriptionId: effect.inscriptionId, delegateInscriptionId: null,
        sourceContentSha256: null, declaredMime: null, declaredContentLength: null,
        detectedMime: null, detectedFormat: null, sourceContentLength: null,
        policyRevision: 'm9p-preview-v2' as const, rendererRevision: 'test-v1',
        pngSha256: null, pngWidth: null, pngHeight: null, pngByteLength: null,
        bytesBase64: null,
      },
    })),
  });
}

describe('recognized marketplace signing', () => {
  it('signs an exact Satflow SINGLE|ANYONECANPAY seller commitment without weakening generic policy', () => {
    const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    const account = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    const seller = deriveAddress(account, 'payment', 'mainnet', 0, 0);
    const payout = deriveAddress(account, 'payment', 'mainnet', 0, 1);
    account.wipePrivateData();
    const sellerScript = scriptPubKeyHex(seller.publicKeyHex, 'payment', 'mainnet');
    const payoutScript = scriptPubKeyHex(payout.publicKeyHex, 'payment', 'mainnet');
    const tx = new Transaction({ lowR: true });
    tx.addInput({
      txid: '11'.repeat(32), index: 0, sequence: 0xffffffff,
      sighashType: SigHash.SINGLE_ANYONECANPAY,
      witnessUtxo: { script: hexToBytes(sellerScript), amount: 10_000n },
    });
    tx.addOutput({ script: hexToBytes(payoutScript), amount: 20_000n });
    const source = {
      backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
      coreTip: { height: 100, hash: 'aa'.repeat(32) }, indexTip: { height: 100, hash: 'aa'.repeat(32) },
      feeQuoteTimestamp: null, mempoolState: null,
    };
    const classification: UtxoClassification = {
      txid: '11'.repeat(32), vout: 0, valueSats: '10000', scriptPubKey: sellerScript,
      confirmations: 10, primaryClass: 'inscribed',
      inscriptions: [{ inscriptionId: `${'11'.repeat(32)}i0`, satpoint: `${'11'.repeat(32)}:0:0` }],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
    };
    const plan = bindUnavailable(createProviderPsbtPlan({
      psbtBase64: bytesToBase64(tx.toPSBT()),
      binding: {
        origin: 'https://satflow.com', tabId: 1, frameId: 0,
        documentId: '123e4567-e89b-42d3-a456-426614174000',
        requestNonce: '123e4567-e89b-42d3-a456-426614174001', providerMethod: 'signPsbt',
      },
      network: 'mainnet', vaultId: 'vault-1', sessionId: 'session-1',
      accountId: marketplaceAccountId, account: 0,
      classifications: [classification],
      walletInputs: [{
        outpoint: `${'11'.repeat(32)}:0`,
        derivation: { accountId: marketplaceAccountId, account: 0, lane: 'payment', chain: 0, index: 0,
          path: seller.path, publicKeyHex: seller.publicKeyHex },
      }],
      source, broadcast: false, planId: 'market-plan-1', now: 1_800_000_000_000,
      marketplace: {
        context: {
          version: 1, marketplaceId: 'satflow', templateVersion: 'drey-1', action: 'list',
          role: 'seller', assetKind: 'inscription', workflowId: 'wf-1', step: 1, stepCount: 2,
          identifiers: { inscriptionId: `${'11'.repeat(32)}i0` },
          economics: { sellerProceedsSats: '20000', payoutAddress: payout.address }, broadcaster: 'site',
        },
        resolution: {
          status: 'recognized', marketplaceId: 'satflow', displayName: 'Satflow',
          templateId: 'satflow-list-ordinal', templateVersion: 'drey-1', flexible: true, reason: 'fixture',
        },
        selectedInputIndexes: [0],
      },
    }));
    expect(plan.kind).toBe('marketplace_psbt');
    expect(plan.requiresAdvanced).toBe(false);
    expect(plan.analysis.hardViolations).toEqual([]);
    expect(plan.analysis.marketplaceCommitment).toMatchObject({
      mode: 'partial', guaranteedProceedsSats: 20_000n, walletFeeExposureSats: 0n,
    });

    const signed = signProviderPsbtPlan({
      plan, seed, requestedInputIndexes: [0], random: (length) => new Uint8Array(length).fill(7),
    });
    const reparsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
    expect(reparsed.getInput(0).partialSig?.[0]?.[1].at(-1)).toBe(SigHash.SINGLE_ANYONECANPAY);
    expect(signed.transactionHex).toBeUndefined();
  });

  it('requires a positive fee from an exact marketplace commitment', () => {
    const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    const account = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    const buyer = deriveAddress(account, 'payment', 'mainnet', 0, 0);
    const destination = deriveAddress(account, 'payment', 'mainnet', 0, 1);
    account.wipePrivateData();
    const buyerScript = scriptPubKeyHex(buyer.publicKeyHex, 'payment', 'mainnet');
    const destinationScript = scriptPubKeyHex(destination.publicKeyHex, 'payment', 'mainnet');
    const source = {
      backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
      coreTip: { height: 100, hash: 'aa'.repeat(32) }, indexTip: { height: 100, hash: 'aa'.repeat(32) },
      feeQuoteTimestamp: null, mempoolState: null,
    };
    const classification: UtxoClassification = {
      txid: '77'.repeat(32), vout: 0, valueSats: '10000', scriptPubKey: buyerScript,
      confirmations: 10, primaryClass: 'cardinal_clean', inscriptions: [],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
    };
    // SigHash.ALL commits to every input and output, so the commitment is exact:
    // the PSBT is a whole transaction and its fee must be real. A partial
    // commitment is the only shape allowed to show outputs >= inputs.
    const plan = (outputSats: bigint) => {
      const tx = new Transaction({ lowR: true });
      tx.addInput({
        txid: '77'.repeat(32), index: 0, sequence: 0xffffffff, sighashType: SigHash.ALL,
        witnessUtxo: { script: hexToBytes(buyerScript), amount: 10_000n },
      });
      tx.addOutput({ script: hexToBytes(destinationScript), amount: outputSats });
      return createProviderPsbtPlan({
        psbtBase64: bytesToBase64(tx.toPSBT()),
        binding: {
          origin: 'https://satflow.com', tabId: 1, frameId: 0,
          documentId: '123e4567-e89b-42d3-a456-426614174000',
          requestNonce: '123e4567-e89b-42d3-a456-426614174001', providerMethod: 'signPsbt',
        },
        network: 'mainnet', vaultId: 'vault-1', sessionId: 'session-1',
        accountId: marketplaceAccountId, account: 0,
        classifications: [classification],
        walletInputs: [{
          outpoint: `${'77'.repeat(32)}:0`,
          derivation: { accountId: marketplaceAccountId, account: 0, lane: 'payment', chain: 0, index: 0,
            path: buyer.path, publicKeyHex: buyer.publicKeyHex },
        }],
        source, broadcast: false, planId: 'market-plan-2', now: 1_800_000_000_000,
        marketplace: {
          context: {
            version: 1, marketplaceId: 'satflow', templateVersion: 'drey-1', action: 'buy',
            role: 'buyer', assetKind: 'inscription', workflowId: 'wf-2', step: 1,
            stepCount: 1, broadcaster: 'site',
          },
          resolution: {
            status: 'recognized', marketplaceId: 'satflow', displayName: 'Satflow',
            templateId: 'satflow-buy-ordinal', templateVersion: 'drey-1',
            flexible: false, reason: 'fixture',
          },
          selectedInputIndexes: [0],
        },
      });
    };

    expect(() => plan(10_000n)).toThrow('PSBT fee is not positive');
    expect(() => plan(10_001n)).toThrow('PSBT fee is not positive');
    expect(plan(9_000n).feeSats).toBe(1_000n);
  });

  it('creates only the ord.net script-path partial signature with disable-tweak semantics', () => {
    const seed = mnemonicToSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    const ordinalAccount = deriveAccountNode(seed, 'ordinals', 'mainnet', 0);
    const paymentAccount = deriveAccountNode(seed, 'payment', 'mainnet', 0);
    const seller = deriveAddress(ordinalAccount, 'ordinals', 'mainnet', 0, 0);
    const payout = deriveAddress(paymentAccount, 'payment', 'mainnet', 0, 0);
    ordinalAccount.wipePrivateData();
    paymentAccount.wipePrivateData();
    const sellerXOnly = seller.publicKeyHex.slice(2);
    const leaf = p2tr_ns(2, [hexToBytes(sellerXOnly), hexToBytes(ORDNET_SALE_PUBLIC_KEY)])[0]!;
    const passthrough = p2tr(hexToBytes(sellerXOnly), { script: leaf.script }, NETWORK, true);
    const payoutScript = scriptPubKeyHex(payout.publicKeyHex, 'payment', 'mainnet');
    const tx = new Transaction({ lowR: true });
    tx.addInput({
      txid: '66'.repeat(32), index: 0, sequence: 0xffffffff,
      sighashType: SigHash.SINGLE_ANYONECANPAY,
      witnessUtxo: { script: passthrough.script, amount: 10_000n },
      tapInternalKey: passthrough.tapInternalKey,
      tapMerkleRoot: passthrough.tapMerkleRoot,
      tapLeafScript: passthrough.tapLeafScript!,
    });
    tx.addOutput({ script: hexToBytes(payoutScript), amount: 25_000n });
    const source = {
      backend: 'https://gateway.example', instanceId: 'gateway-1', classificationRevision: 'rev-1',
      coreTip: { height: 100, hash: 'bb'.repeat(32) }, indexTip: { height: 100, hash: 'bb'.repeat(32) },
      feeQuoteTimestamp: null, mempoolState: null,
    };
    const classification: UtxoClassification = {
      txid: '66'.repeat(32), vout: 0, valueSats: '10000',
      scriptPubKey: Array.from(passthrough.script, (byte) => byte.toString(16).padStart(2, '0')).join(''),
      confirmations: 0, primaryClass: 'inscribed',
      inscriptions: [{ inscriptionId: `${'66'.repeat(32)}i0`, satpoint: `${'66'.repeat(32)}:0:0` }],
      satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative',
      classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
    };
    const plan = bindUnavailable(createProviderPsbtPlan({
      psbtBase64: bytesToBase64(tx.toPSBT()),
      binding: {
        origin: 'https://ord.net', tabId: 1, frameId: 0,
        documentId: '123e4567-e89b-42d3-a456-426614174010',
        requestNonce: '123e4567-e89b-42d3-a456-426614174011', providerMethod: 'signPsbt',
      },
      network: 'mainnet', vaultId: 'vault-1', sessionId: 'session-1',
      accountId: marketplaceAccountId, account: 0,
      classifications: [classification],
      walletInputs: [{
        outpoint: `${'66'.repeat(32)}:0`,
        derivation: { accountId: marketplaceAccountId, account: 0, lane: 'ordinals', chain: 0, index: 0,
          path: seller.path, publicKeyHex: seller.publicKeyHex },
      }],
      source, broadcast: false, planId: 'ordnet-script-plan', now: 1_800_000_000_000,
      marketplace: {
        context: {
          version: 1, marketplaceId: 'ordnet', templateVersion: 'drey-1', action: 'list',
          role: 'seller', assetKind: 'inscription', workflowId: 'ord-wf-1', step: 2, stepCount: 3,
          identifiers: { inscriptionId: `${'66'.repeat(32)}i0` },
          economics: { sellerProceedsSats: '25000', payoutAddress: payout.address }, broadcaster: 'site',
        },
        resolution: {
          status: 'recognized', marketplaceId: 'ordnet', displayName: 'ord.net',
          templateId: 'ordnet-list', templateVersion: 'drey-1', flexible: true, reason: 'fixture',
        },
        selectedInputIndexes: [0],
      },
    }));
    const signed = signProviderPsbtPlan({
      plan, seed, requestedInputIndexes: [0], random: (length) => new Uint8Array(length).fill(9),
    });
    const reparsed = Transaction.fromPSBT(Uint8Array.from(Buffer.from(signed.psbtBase64, 'base64')));
    expect(reparsed.getInput(0).tapScriptSig).toHaveLength(1);
    expect(reparsed.getInput(0).tapScriptSig?.[0]?.[1].at(-1)).toBe(SigHash.SINGLE_ANYONECANPAY);
    expect(reparsed.getInput(0).tapKeySig).toBeUndefined();
    expect(reparsed.getInput(0).tapInternalKey).toEqual(passthrough.tapInternalKey);
  });
});
