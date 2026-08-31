import { beforeAll, describe, expect, it } from 'vitest';
import {
  NETWORK,
  OP,
  p2tr,
  Script,
  ScriptNum,
  SigHash,
  TAPROOT_UNSPENDABLE_KEY,
  Transaction,
} from '@scure/btc-signer';
import { publicAccountFromSeed } from '../../src/domain/accounts/public-account';
import { deriveAccountNode, deriveAddress } from '../../src/domain/keys/derivation';
import { mnemonicToSeed } from '../../src/domain/keys/mnemonic';
import { COMMUNITY_VAULT_NUMS_INTERNAL_KEY } from '../../src/domain/community-vault/contracts';
import type { UtxoClassification } from '../../src/domain/gateway/contract';
import {
  ORDNET_FOUNDRY_MAX_FEE_RESERVE_SATS,
  verifyOrdnetFoundryTimelockPath,
} from '../../src/domain/marketplaces/ordnet-foundry-path';
import { createProviderPsbtPlan } from '../../src/domain/transactions/provider-psbt';
import {
  createProviderPsbtGroupPlan,
  signProviderPsbtGroupPlan,
} from '../../src/domain/transactions/provider-psbt-group-plan';
import {
  prepareProviderPsbtGroupInputs,
  providerPsbtLinkedGroupBinding,
} from '../../src/domain/transactions/provider-psbt-group-prepare';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(() => installTestCryptoProvider());

const NOW = 1_800_000_000_000;
const UNLOCK_AT = 1_800_000_000;
const seed = mnemonicToSeed(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
);
const publicAccount = publicAccountFromSeed(seed, 'mainnet', 0);
const ordinals = deriveAccountNode(seed, 'ordinals', 'mainnet', 0);
const recipient = deriveAddress(ordinals, 'ordinals', 'mainnet', 0, 0);
ordinals.wipePrivateData();
const recipientKey = recipient.publicKeyHex.slice(2);
const source = {
  backend: 'https://gateway.example',
  instanceId: 'gateway-1',
  classificationRevision: 'rev-1',
  coreTip: { height: 100, hash: 'aa'.repeat(32) },
  indexTip: { height: 100, hash: 'aa'.repeat(32) },
  feeQuoteTimestamp: null,
  mempoolState: null,
};

function withdrawal(input: {
  unlockAt?: number;
  sequence?: number;
  sighash?: number;
  internalKey?: Uint8Array;
  scriptKey?: string;
  recipientKey?: string;
  inscriptionValue?: bigint;
  feeReserve?: bigint;
  outputValue?: bigint;
  extraOutput?: boolean;
  cltvOpcode?: number;
  version?: number;
  txidOffset?: number;
  lockTime?: number;
} = {}): Transaction {
  const unlockAt = input.unlockAt ?? UNLOCK_AT;
  const scriptKey = input.scriptKey ?? recipientKey;
  const leaf = Script.encode([
    ScriptNum(5, true).encode(BigInt(unlockAt)),
    input.cltvOpcode ?? OP.CHECKLOCKTIMEVERIFY,
    OP.DROP,
    hexToBytes(scriptKey),
    OP.CHECKSIG,
  ]);
  const internalKey = input.internalKey ?? TAPROOT_UNSPENDABLE_KEY;
  const timelock = p2tr(internalKey, { script: leaf }, NETWORK, true);
  const destination = p2tr(hexToBytes(input.recipientKey ?? recipientKey), undefined, NETWORK);
  const inscriptionValue = input.inscriptionValue ?? 10_000n;
  const feeReserve = input.feeReserve ?? 2_000n;
  const tx = new Transaction({
    version: input.version ?? 2,
    lockTime: input.lockTime ?? unlockAt,
    lowR: true,
  });
  for (const [index, amount] of [inscriptionValue, feeReserve].entries()) {
    tx.addInput({
      txid: (index + 1 + (input.txidOffset ?? 0)).toString(16).padStart(64, '0'),
      index: 0,
      sequence: input.sequence ?? 0xffff_fffd,
      sighashType: input.sighash ?? SigHash.DEFAULT,
      witnessUtxo: { amount, script: timelock.script },
      tapInternalKey: timelock.tapInternalKey,
      tapMerkleRoot: timelock.tapMerkleRoot,
      tapLeafScript: timelock.tapLeafScript!,
    });
  }
  tx.addOutput({ amount: input.outputValue ?? inscriptionValue, script: destination.script });
  if (input.extraOutput) tx.addOutput({ amount: 1n, script: destination.script });
  return tx;
}

describe('ord.net Foundry presale withdrawal path', () => {
  it('accepts only the canonical two-input CLTV self-return', () => {
    expect(verifyOrdnetFoundryTimelockPath(withdrawal(), [0, 1], recipientKey)).toEqual({
      recipientPublicKey: recipientKey,
      unlockAt: UNLOCK_AT,
      feeReserveSats: 2_000n,
      disableTweakSigner: true,
    });
    expect(COMMUNITY_VAULT_NUMS_INTERNAL_KEY).toBe(
      '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    );
  });

  it.each([
    [
      'b94e3956fec61b7a7ea65d5275f8ee1ade29c2c530499d08865df6d546bbe9e3',
      1_788_098_400,
      333n,
      330n,
      '57c5d3ba9fe75e7eb53caa0d17ff3c8d58c99d8ef10b1b3d23f9a9c23dc43028',
    ],
    [
      'c6dc083e4c97af2ac9938025cefc1c80ae34e6bb290fead50f10be0267962f05',
      1_784_865_600,
      330n,
      601n,
      '86d4a1e907091b5500aec2663ac2ec86e3fa8f6c3731e06bb4270a151dfd44de',
    ],
    [
      '3436e233a92a2811f7dfc279054c347c7e7be65a82b42280fe4dd42ccf339845',
      1_787_574_600,
      330n,
      394n,
      'd48fc4c06c340df3e79c6912f493d93fd36ce52791f8dec85cdbfbc268600368',
    ],
  ])('matches observed Foundry withdrawal %s', (_txid, unlockAt, value, fee, publicKey) => {
    expect(verifyOrdnetFoundryTimelockPath(withdrawal({
      unlockAt,
      inscriptionValue: value,
      feeReserve: fee,
      scriptKey: publicKey,
      recipientKey: publicKey,
    }), [0, 1], publicKey)).toMatchObject({ unlockAt, feeReserveSats: fee });
  });

  it.each([
    ['wrong signing indexes', () => verifyOrdnetFoundryTimelockPath(withdrawal(), [0], recipientKey)],
    ['wrong transaction version', () => verifyOrdnetFoundryTimelockPath(withdrawal({ version: 1 }), [0, 1], recipientKey)],
    ['CLTV time differs from locktime', () => verifyOrdnetFoundryTimelockPath(withdrawal({ unlockAt: UNLOCK_AT + 1, lockTime: UNLOCK_AT }), [0, 1], recipientKey)],
    ['wrong CLTV opcode', () => verifyOrdnetFoundryTimelockPath(withdrawal({ cltvOpcode: OP.CHECKSEQUENCEVERIFY }), [0, 1], recipientKey)],
    ['non-RBF sequence', () => verifyOrdnetFoundryTimelockPath(withdrawal({ sequence: 0xffff_ffff }), [0, 1], recipientKey)],
    ['wrong sighash', () => verifyOrdnetFoundryTimelockPath(withdrawal({ sighash: SigHash.ALL }), [0, 1], recipientKey)],
    ['wrong internal key', () => verifyOrdnetFoundryTimelockPath(withdrawal({ internalKey: hexToBytes('11'.repeat(32)) }), [0, 1], recipientKey)],
    ['wrong CLTV key', () => verifyOrdnetFoundryTimelockPath(withdrawal({ scriptKey: '22'.repeat(32) }), [0, 1], recipientKey)],
    ['wrong destination', () => verifyOrdnetFoundryTimelockPath(withdrawal({ recipientKey: '33'.repeat(32) }), [0, 1], recipientKey)],
    ['reduced inscription value', () => verifyOrdnetFoundryTimelockPath(withdrawal({ outputValue: 9_999n }), [0, 1], recipientKey)],
    ['extra output', () => verifyOrdnetFoundryTimelockPath(withdrawal({ extraOutput: true }), [0, 1], recipientKey)],
    ['excess fee reserve', () => verifyOrdnetFoundryTimelockPath(
      withdrawal({ feeReserve: ORDNET_FOUNDRY_MAX_FEE_RESERVE_SATS + 1n }), [0, 1], recipientKey,
    )],
  ])('rejects %s', (_label, run) => {
    expect(run).toThrow();
  });

  it('rejects changed control blocks, leaf versions, and Merkle paths', () => {
    const wrongControl = withdrawal();
    const [control, script] = wrongControl.getInput(0).tapLeafScript![0]!;
    wrongControl.updateInput(0, {
      tapLeafScript: [[{ ...control, internalKey: hexToBytes('44'.repeat(32)) }, script]],
    }, true);
    expect(() => verifyOrdnetFoundryTimelockPath(wrongControl, [0, 1], recipientKey)).toThrow();

    const wrongVersion = withdrawal();
    const [versionControl, versionScript] = wrongVersion.getInput(0).tapLeafScript![0]!;
    const changedVersionScript = Uint8Array.from(versionScript);
    changedVersionScript[changedVersionScript.length - 1] = 0xc2;
    wrongVersion.updateInput(0, {
      tapLeafScript: [[{ ...versionControl, version: 0xc2 }, changedVersionScript]],
    }, true);
    expect(() => verifyOrdnetFoundryTimelockPath(wrongVersion, [0, 1], recipientKey)).toThrow();

    const merklePath = withdrawal();
    const [pathControl, pathScript] = merklePath.getInput(0).tapLeafScript![0]!;
    merklePath.updateInput(0, {
      tapLeafScript: [[{ ...pathControl, merklePath: [hexToBytes('55'.repeat(32))] }, pathScript]],
    }, true);
    expect(() => verifyOrdnetFoundryTimelockPath(merklePath, [0, 1], recipientKey)).toThrow();
  });

  it('prepares and atomically signs a split-wallet future withdrawal', async () => {
    const tx = withdrawal();
    const psbtBase64 = bytesToBase64(tx.toPSBT());
    const selected = [{
      address: recipient.address,
      publicKey: recipient.publicKeyHex,
      disableTweakSigner: true,
      signingIndexes: [0, 1],
      sigHash: 0 as const,
    }];
    const item = {
      nodeId: 'withdrawal-1',
      psbtBase64,
      selectedInputIndexes: [0, 1],
      inputsToSign: selected,
    };
    const derivation = {
      accountId: publicAccount.accountId,
      account: 0,
      lane: 'ordinals' as const,
      chain: 0 as const,
      index: 0,
      path: recipient.path,
      publicKeyHex: recipient.publicKeyHex,
    };
    const prospectiveOutpoints = ['0'.repeat(63) + '1:0', '0'.repeat(63) + '2:0'];
    const preparation = prepareProviderPsbtGroupInputs({
      groupId: 'foundry-future-1',
      items: [item],
      externalClassifications: [],
      prospectiveOutpoints,
      source,
      walletControl: {
        network: 'mainnet',
        origin: 'https://ord.net',
        accountId: publicAccount.accountId,
        account: 0,
        candidates: [{ address: recipient.address, derivation }],
      },
    });
    const linked = providerPsbtLinkedGroupBinding(preparation, item.nodeId);
    const plan = createProviderPsbtPlan({
      psbtBase64,
      binding: {
        origin: 'https://ord.net',
        tabId: 1,
        frameId: 0,
        documentId: 'doc-1',
        requestNonce: 'nonce-1',
        providerMethod: 'signMultipleTransactions',
      },
      network: 'mainnet',
      vaultId: 'vault-1',
      sessionId: 'session-1',
      accountId: publicAccount.accountId,
      account: 0,
      classifications: linked.classifications,
      walletInputs: linked.walletInputs,
      walletOutputs: [{
        scriptPubKey: bytesToHex(tx.getOutput(0).script!),
        output: {
          valueSats: 10_000n,
          scriptPubKey: bytesToHex(tx.getOutput(0).script!),
          address: recipient.address,
          role: 'ordinal_change',
          derivation,
        },
      }],
      source,
      broadcast: false,
      selectedInputIndexes: [0, 1],
      signInputBindings: [{ address: recipient.address, inputIndexes: [0, 1] }],
      planId: 'foundry-withdrawal-plan',
      now: NOW,
      linkedGroup: linked.linkedGroup,
    });
    const group = createProviderPsbtGroupPlan({
      items: [{ nodeId: item.nodeId, plan, inputsToSign: selected }],
      groupId: preparation.groupId,
      now: NOW,
      approvalGeneration: 1,
      preparation,
    });
    expect(group.preparation?.prospectiveOutpoints).toEqual(prospectiveOutpoints);
    expect(group.items[0]!.plan.broadcast).toBe(false);
    const signed = await signProviderPsbtGroupPlan({
      plan: group,
      seed,
      now: () => NOW + 1,
      random: (length) => new Uint8Array(length).fill(7),
      yieldControl: async () => undefined,
    });
    const signedTx = Transaction.fromPSBT(base64ToBytes(signed.results[0]!.psbtBase64), {
      lowR: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    expect(signedTx.getInput(0).tapScriptSig).toHaveLength(1);
    expect(signedTx.getInput(1).tapScriptSig).toHaveLength(1);
  });

  it('requires authoritative asset classification once Foundry inputs exist', () => {
    const tx = withdrawal();
    const psbtBase64 = bytesToBase64(tx.toPSBT());
    const inputOutpoints = ['0'.repeat(63) + '1:0', '0'.repeat(63) + '2:0'];
    const selected = [{
      address: recipient.address,
      publicKey: recipient.publicKeyHex,
      signingIndexes: [0, 1],
      sigHash: 0 as const,
    }];
    const item = {
      nodeId: 'known-withdrawal',
      psbtBase64,
      selectedInputIndexes: [0, 1],
      inputsToSign: selected,
    };
    const derivation = {
      accountId: publicAccount.accountId,
      account: 0,
      lane: 'ordinals' as const,
      chain: 0 as const,
      index: 0,
      path: recipient.path,
      publicKeyHex: recipient.publicKeyHex,
    };
    const classifications: UtxoClassification[] = [
      {
        txid: '0'.repeat(63) + '1', vout: 0, valueSats: '10000',
        scriptPubKey: bytesToHex(tx.getInput(0).witnessUtxo!.script), confirmations: 1,
        primaryClass: 'inscribed' as const,
        inscriptions: [{ inscriptionId: `${'aa'.repeat(32)}i0`, satpoint: `${inputOutpoints[0]}:0` }],
        satRanges: null, unsupportedAssetDetected: false, confidence: 'authoritative' as const,
        classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
      },
      {
        txid: '0'.repeat(63) + '2', vout: 0, valueSats: '2000',
        scriptPubKey: bytesToHex(tx.getInput(1).witnessUtxo!.script), confirmations: 1,
        primaryClass: 'cardinal_clean' as const, inscriptions: [], satRanges: null,
        unsupportedAssetDetected: false, confidence: 'authoritative' as const,
        classifiedTip: source.coreTip, classificationRevision: source.classificationRevision,
      },
    ];
    const prepare = (records: typeof classifications) => prepareProviderPsbtGroupInputs({
      groupId: 'foundry-known-1',
      items: [item],
      externalClassifications: records,
      source,
      walletControl: {
        network: 'mainnet', origin: 'https://ord.net', accountId: publicAccount.accountId, account: 0,
        candidates: [{ address: recipient.address, derivation }],
      },
    });
    const preparation = prepare(classifications);
    expect(preparation.items[0]!.provenance).toEqual([
      expect.objectContaining({ kind: 'gateway', walletControl: 'ordnet_foundry_script_path' }),
      expect.objectContaining({ kind: 'gateway', walletControl: 'ordnet_foundry_script_path' }),
    ]);
    const linked = providerPsbtLinkedGroupBinding(preparation, item.nodeId);
    expect(() => createProviderPsbtPlan({
      psbtBase64,
      binding: {
        origin: 'https://ord.net', tabId: 1, frameId: 0, documentId: 'doc-known',
        requestNonce: 'nonce-known', providerMethod: 'signMultipleTransactions',
      },
      network: 'mainnet', vaultId: 'vault-1', sessionId: 'session-1',
      accountId: publicAccount.accountId, account: 0,
      classifications: linked.classifications,
      walletInputs: linked.walletInputs,
      walletOutputs: [{
        scriptPubKey: bytesToHex(tx.getOutput(0).script!),
        output: {
          valueSats: 10_000n, scriptPubKey: bytesToHex(tx.getOutput(0).script!),
          address: recipient.address, role: 'ordinal_change', derivation,
        },
      }],
      source, broadcast: false, selectedInputIndexes: [0, 1],
      signInputBindings: [{ address: recipient.address, inputIndexes: [0, 1] }],
      planId: 'foundry-known-plan', now: NOW, linkedGroup: linked.linkedGroup,
    })).not.toThrow();

    const shared = structuredClone(classifications);
    shared[0]!.inscriptions.push({
      inscriptionId: `${'bb'.repeat(32)}i0`,
      satpoint: `${inputOutpoints[0]}:1`,
    });
    const sharedPreparation = prepare(shared);
    const sharedLinked = providerPsbtLinkedGroupBinding(sharedPreparation, item.nodeId);
    expect(() => createProviderPsbtPlan({
      psbtBase64,
      binding: {
        origin: 'https://ord.net', tabId: 1, frameId: 0, documentId: 'doc-known',
        requestNonce: 'nonce-known', providerMethod: 'signMultipleTransactions',
      },
      network: 'mainnet', vaultId: 'vault-1', sessionId: 'session-1',
      accountId: publicAccount.accountId, account: 0,
      classifications: sharedLinked.classifications, walletInputs: sharedLinked.walletInputs,
      walletOutputs: [], source, broadcast: false, selectedInputIndexes: [0, 1],
      planId: 'foundry-shared-plan', now: NOW, linkedGroup: sharedLinked.linkedGroup,
    })).toThrow(/one offset-zero inscription/u);
  });

  it('rejects an explicit tweak request for a future Foundry withdrawal', () => {
    const tx = withdrawal();
    expect(() => prepareProviderPsbtGroupInputs({
      groupId: 'foundry-tweaked',
      items: [{
        nodeId: 'withdrawal-1', psbtBase64: bytesToBase64(tx.toPSBT()),
        selectedInputIndexes: [0, 1],
        inputsToSign: [{
          address: recipient.address, disableTweakSigner: false, signingIndexes: [0, 1],
        }],
      }],
      externalClassifications: [],
      prospectiveOutpoints: ['0'.repeat(63) + '1:0', '0'.repeat(63) + '2:0'],
      source,
      walletControl: {
        network: 'mainnet', origin: 'https://ord.net', accountId: publicAccount.accountId, account: 0,
        candidates: [{
          address: recipient.address,
          derivation: {
            accountId: publicAccount.accountId, account: 0, lane: 'ordinals', chain: 0, index: 0,
            path: recipient.path, publicKeyHex: recipient.publicKeyHex,
          },
        }],
      },
    })).toThrow(/active Ordinals signer/u);
  });
});
