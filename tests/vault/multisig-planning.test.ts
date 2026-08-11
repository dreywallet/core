import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { VaultPolicyIdentityV1, VaultUnsignedPlanV1 } from '../../src/domain/vault/multisig-contracts';
import { deriveVaultOutput } from '../../src/domain/vault/multisig-descriptors';
import { canonicalVaultPlanBytes, parseCanonicalVaultPlan } from '../../src/domain/vault/multisig-encoding';
import {
  recognizeVaultCreatedUnconfirmedChange,
  type VaultEvidenceSourceV1,
  type VaultUtxoV1,
} from '../../src/domain/vault/multisig-evidence';
import {
  buildVaultCardinalWithdrawal,
  buildVaultCpfp,
  buildVaultInscriptionWithdrawal,
  initialVaultCoordinatorChangeIndex,
  isVaultCoordinatorChangeIndex,
  parseApprovedVaultPlan,
  reserveVaultCoordinatorChangeIndex,
  vaultPlanTxid,
  VaultPlanBuildError,
} from '../../src/domain/vault/multisig-planning';
import { validateVaultAssetPolicy } from '../../src/domain/vault/multisig-asset-policy';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const vectors = JSON.parse(readFileSync(
  join(import.meta.dirname, '..', '..', 'vectors', 'vault-contracts-v1.json'),
  'utf8',
)) as { records: { mainnet: { policy: VaultPolicyIdentityV1; plan: VaultUnsignedPlanV1 } } };

const POLICY = vectors.records.mainnet.policy;
const DESTINATION = vectors.records.mainnet.plan.destination.address;
const NOW = '1785542401000';
const TIP = { height: 900_000, hash: '44'.repeat(32) };

function source(): VaultEvidenceSourceV1 {
  return {
    network: 'mainnet',
    backendInstanceIdHash: '55'.repeat(32),
    classificationRevisionHash: '66'.repeat(32),
    coreTip: TIP,
    indexTip: TIP,
    historyTip: TIP,
    ordTip: TIP,
    observedAtMs: NOW,
    validUntilMs: '1785543001000',
  };
}

function vaultUtxo(input: {
  txid: string;
  valueSats: string;
  index: number;
  classification?: 'cardinal_clean' | 'inscribed';
  inscriptions?: Array<{ inscriptionId: string; offsetSats: string }>;
}): VaultUtxoV1 {
  const owned = deriveVaultOutput(POLICY, 'receive', input.index);
  return {
    txid: input.txid,
    vout: 0,
    valueSats: input.valueSats,
    scriptPubKeyHex: owned.scriptPubKeyHex,
    branch: 'receive',
    derivationIndex: input.index,
    confirmations: 6,
    walletCreatedUnconfirmedChange: false,
    primaryClass: input.classification ?? 'cardinal_clean',
    confidence: 'authoritative',
    classificationComplete: true,
    satRangesComplete: true,
    inscriptions: input.inscriptions ?? [],
    rareSatDetected: false,
    unsupportedAssetDetected: false,
    userFrozen: false,
    dustQuarantined: false,
    refusal: null,
  };
}

function base() {
  return {
    policy: POLICY,
    source: source(),
    destinationAddress: DESTINATION,
    pairedSpendingWalletIdHash: '77'.repeat(32),
    feeRateSatPerKvB: '5000',
    changeDerivationIndex: 3,
    planId: '88'.repeat(16),
    requestId: '99'.repeat(16),
    createdAtMs: NOW,
    expiresAtMs: '1785542701000',
    broadcastIntent: 'broadcast' as const,
  };
}

describe('coordinator-neutral Vault planning', () => {
  it('partitions shared change derivation into disjoint coordinator lanes', () => {
    expect(initialVaultCoordinatorChangeIndex('extension')).toBe(0);
    expect(initialVaultCoordinatorChangeIndex('mobile')).toBe(1);
    expect(reserveVaultCoordinatorChangeIndex(0, 'extension')).toEqual({ index: 0, nextIndex: 2 });
    expect(reserveVaultCoordinatorChangeIndex(1, 'mobile')).toEqual({ index: 1, nextIndex: 3 });
    expect(isVaultCoordinatorChangeIndex(22, 'extension')).toBe(true);
    expect(isVaultCoordinatorChangeIndex(23, 'mobile')).toBe(true);
    expect(isVaultCoordinatorChangeIndex(22, 'mobile')).toBe(false);
    expect(() => reserveVaultCoordinatorChangeIndex(0, 'mobile')).toThrow('invalid mobile');
    expect(() => reserveVaultCoordinatorChangeIndex(1, 'extension')).toThrow('invalid extension');
  });

  it('builds one canonical B3-safe cardinal plan for either coordinator', () => {
    const built = buildVaultCardinalWithdrawal({
      ...base(),
      utxos: [vaultUtxo({ txid: 'aa'.repeat(32), valueSats: '150000', index: 0 })],
      amountSats: '50000',
    });
    expect(parseCanonicalVaultPlan(canonicalVaultPlanBytes(built.plan))).toEqual(built.plan);
    expect(parseApprovedVaultPlan({
      planDigest: built.plan.planDigest,
      canonicalPlanHex: Buffer.from(canonicalVaultPlanBytes(built.plan)).toString('hex'),
    })).toEqual(built.plan);
    expect(validateVaultAssetPolicy({
      policy: POLICY,
      plan: built.plan,
      psbtHex: built.psbtHex,
      evidence: built.evidence,
      nowMs: NOW,
    }).movement).toBe('cardinal');
  });

  it('selects additional clean inputs when the first cannot cover amount and fee', () => {
    const built = buildVaultCardinalWithdrawal({
      ...base(),
      utxos: [
        vaultUtxo({ txid: 'ab'.repeat(32), valueSats: '50500', index: 0 }),
        vaultUtxo({ txid: 'ac'.repeat(32), valueSats: '50000', index: 1 }),
      ],
      amountSats: '50000',
    });
    expect(built.selected).toHaveLength(2);
  });

  it('moves one complete inscription UTXO and pays fees only from clean inputs', () => {
    const inscriptionId = `${'cd'.repeat(32)}i0`;
    const protectedUtxo = vaultUtxo({
      txid: 'ad'.repeat(32),
      valueSats: '10000',
      index: 0,
      classification: 'inscribed',
      inscriptions: [{ inscriptionId, offsetSats: '600' }],
    });
    const built = buildVaultInscriptionWithdrawal({
      ...base(),
      utxos: [
        protectedUtxo,
        vaultUtxo({ txid: 'ae'.repeat(32), valueSats: '50000', index: 1 }),
      ],
      inscriptionId,
    });
    expect(built.selected[0]).toBe(protectedUtxo);
    expect(built.plan.outputs[0]!.valueSats).toBe(protectedUtxo.valueSats);
    expect(built.plan.assetEffects[0]).toMatchObject({
      kind: 'inscription', assetId: inscriptionId, inputOffsetSats: '600', outputOffsetSats: '600',
    });
    expect(validateVaultAssetPolicy({
      policy: POLICY,
      plan: built.plan,
      psbtHex: built.psbtHex,
      evidence: built.evidence,
      nowMs: NOW,
    }).movement).toBe('inscription');
  });

  it('builds a B3-safe CPFP only from the exact fresh parent change', () => {
    const parent = buildVaultCardinalWithdrawal({
      ...base(),
      utxos: [vaultUtxo({ txid: 'd1'.repeat(32), valueSats: '100000', index: 0 })],
      amountSats: '90000',
    });
    const parentChange = parent.plan.outputs.find((output) => output.purpose === 'vault-change')!;
    const parentTxid = vaultPlanTxid(parent.plan);
    const scannedChildInput: VaultUtxoV1 = {
      txid: parentTxid,
      vout: parentChange.outputIndex,
      valueSats: parentChange.valueSats,
      scriptPubKeyHex: parentChange.scriptPubKeyHex,
      branch: 'change',
      derivationIndex: parentChange.derivationIndex!,
      confirmations: 0,
      walletCreatedUnconfirmedChange: false,
      primaryClass: 'cardinal_clean',
      confidence: 'authoritative',
      classificationComplete: true,
      satRangesComplete: true,
      inscriptions: [],
      rareSatDetected: false,
      unsupportedAssetDetected: false,
      userFrozen: false,
      dustQuarantined: false,
      refusal: 'unconfirmed',
    };
    const childInput = recognizeVaultCreatedUnconfirmedChange(scannedChildInput, parent.plan);
    expect(childInput).toMatchObject({ walletCreatedUnconfirmedChange: true, refusal: null });
    const child = buildVaultCpfp({
      ...base(),
      planId: 'a8'.repeat(16),
      requestId: 'a9'.repeat(16),
      feeRateSatPerKvB: '12000',
      utxos: [childInput],
      previousPlan: parent.plan,
    });
    expect(child.plan.replacement).toEqual({
      kind: 'cpfp', replacesTxid: null, parentTxid,
    });
    expect(child.selected).toEqual([childInput]);
    expect(validateVaultAssetPolicy({
      policy: POLICY,
      plan: child.plan,
      psbtHex: child.psbtHex,
      evidence: child.evidence,
      nowMs: NOW,
      previousPlan: parent.plan,
    }).replacement).toBe('cpfp');
  });

  it('refuses co-located or unconfirmed inscription movement in policy v1', () => {
    const inscriptionId = `${'ce'.repeat(32)}i0`;
    const protectedUtxo = vaultUtxo({
      txid: 'af'.repeat(32),
      valueSats: '10000',
      index: 0,
      classification: 'inscribed',
      inscriptions: [
        { inscriptionId, offsetSats: '600' },
        { inscriptionId: `${'cf'.repeat(32)}i0`, offsetSats: '700' },
      ],
    });
    expect(() => buildVaultInscriptionWithdrawal({
      ...base(),
      utxos: [protectedUtxo, vaultUtxo({ txid: 'b0'.repeat(32), valueSats: '50000', index: 1 })],
      inscriptionId,
    })).toThrow(VaultPlanBuildError);
  });
});
