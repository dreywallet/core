import { beforeAll, describe, expect, it } from 'vitest';
import type { WalletUtxo } from '../../src/domain/classification/types';
import type { StatusCapabilities, Tip } from '../../src/domain/gateway/contract';
import {
  computeVaultInputAssetEvidenceHash,
  VAULT_FULL_SAT_SAFETY_CAPABILITIES,
} from '../../src/domain/vault/multisig-asset-policy';
import {
  buildVaultAssetPolicyEvidence,
  deriveVaultEvidenceSource,
  finalizeVaultUtxoEvidence,
  projectVaultUtxo,
  summarizeVaultBalance,
  vaultEvidenceExpired,
  VAULT_EVIDENCE_TTL_MS,
  type VaultEvidenceSourceV1,
} from '../../src/domain/vault/multisig-evidence';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';

beforeAll(installTestCryptoProvider);

const TIP: Tip = { height: 880_000, hash: 'aa'.repeat(32) };
const NOW = 1_752_969_600_000;

function status(overrides: Partial<StatusCapabilities> = {}): StatusCapabilities {
  return {
    instanceId: 'gateway-1',
    network: 'mainnet',
    protocolVersion: 2,
    protocolMin: 1,
    protocolMax: 2,
    requestNonce: 'nonce',
    timestamp: '2026-08-02T00:00:00.000Z',
    coreTip: TIP,
    indexTip: TIP,
    historyTip: TIP,
    ordTip: TIP,
    classificationRevision: 'rev-1',
    capabilities: [...VAULT_FULL_SAT_SAFETY_CAPABILITIES],
    eligibleSafetyModes: ['full_sat_safety'],
    activeRevision: 'rev-1',
    mempoolObservedAt: '2026-08-02T00:00:00.000Z',
    serverTime: '2026-08-02T00:00:00.000Z',
    signature: 'sig',
    ...overrides,
  } as StatusCapabilities;
}

function source(): VaultEvidenceSourceV1 {
  const result = deriveVaultEvidenceSource({
    network: 'mainnet',
    status: status(),
    scan: {
      instanceId: 'gateway-1',
      classificationRevision: 'rev-1',
      coreTip: TIP,
      indexTip: TIP,
    },
    nowMs: NOW,
  });
  if (!result.ok) throw new Error('expected coherent source');
  return result.source;
}

function utxo(overrides: Partial<WalletUtxo> = {}): WalletUtxo {
  return {
    outpoint: { txid: 'cc'.repeat(32), vout: 0 },
    valueSats: 100_000n,
    scriptPubKey: `0020${'dd'.repeat(32)}`,
    account: 0,
    lane: 'payment',
    chain: 0,
    addressIndex: 0,
    height: 879_999,
    walletCreatedChange: false,
    facts: {
      primaryClass: 'cardinal_clean',
      inscriptions: [],
      satRanges: [{ start: '1', end: '2', rarity: 'common' }],
      unsupportedAssetDetected: false,
      confidence: 'authoritative',
      classifiedTip: TIP,
      classificationRevision: 'rev-1',
    },
    flags: { userFrozen: false, dustQuarantined: false },
    ...overrides,
  } as WalletUtxo;
}

describe('coordinator-neutral Vault evidence', () => {
  it('accepts one complete Full Sat Safety source and expires at its declared boundary', () => {
    const current = source();
    expect(vaultEvidenceExpired(current, NOW + VAULT_EVIDENCE_TTL_MS)).toBe(false);
    expect(vaultEvidenceExpired(current, NOW + VAULT_EVIDENCE_TTL_MS + 1)).toBe(true);
  });

  it('fails closed on absent, insufficient, or conflicting gateway evidence', () => {
    const scan = {
      instanceId: 'gateway-1', classificationRevision: 'rev-1', coreTip: TIP, indexTip: TIP,
    };
    expect(deriveVaultEvidenceSource({ network: 'mainnet', status: null, scan, nowMs: NOW }))
      .toEqual({ ok: false, refusal: 'gateway_unavailable' });
    expect(deriveVaultEvidenceSource({
      network: 'mainnet', status: status({ capabilities: [] }), scan, nowMs: NOW,
    })).toEqual({ ok: false, refusal: 'capabilities_insufficient' });
    expect(deriveVaultEvidenceSource({
      network: 'mainnet', status: status({ classificationRevision: 'other' }), scan, nowMs: NOW,
    })).toEqual({ ok: false, refusal: 'conflicting_source' });
  });

  it('withholds a bad UTXO without hiding its value', () => {
    const current = source();
    const good = projectVaultUtxo(utxo(), current)!;
    const held = projectVaultUtxo(utxo({
      outpoint: { txid: 'ee'.repeat(32), vout: 1 },
      valueSats: 25_000n,
      flags: { userFrozen: true, dustQuarantined: false },
    }), current)!;
    expect(held.refusal).toBe('user_frozen');
    expect(summarizeVaultBalance([good, held])).toEqual({
      totalSats: '125000', movableSats: '100000', immovableSats: '25000', inscriptionCount: 0,
    });
  });

  it('refuses an inscription whose satpoint names another outpoint', () => {
    const bad = utxo({
      facts: {
        ...utxo().facts!,
        primaryClass: 'inscribed',
        inscriptions: [{ inscriptionId: `${'ff'.repeat(32)}i0`, satpoint: `${'99'.repeat(32)}:0:600` }],
      },
    });
    expect(projectVaultUtxo(bad, source())).toBeNull();
  });

  it('uses the same evidence hash on every platform and binds plan input order', () => {
    const current = source();
    const projected = projectVaultUtxo(utxo(), current)!;
    const first = finalizeVaultUtxoEvidence(projected, current, 0);
    expect(first.evidenceHash).toBe(computeVaultInputAssetEvidenceHash(first));
    expect(first.evidenceHash).not.toBe(finalizeVaultUtxoEvidence(projected, current, 1).evidenceHash);
  });

  it('assembles the complete B3 evidence record', () => {
    const current = source();
    const evidence = buildVaultAssetPolicyEvidence({
      source: current,
      policyId: '11'.repeat(32),
      planId: '22'.repeat(16),
      planDigest: '33'.repeat(32),
      utxos: [projectVaultUtxo(utxo(), current)!],
    });
    expect(evidence.capabilities).toEqual([...VAULT_FULL_SAT_SAFETY_CAPABILITIES]);
    expect(evidence.inputs[0]!.inputIndex).toBe(0);
  });
});
