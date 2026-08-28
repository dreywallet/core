import { describe, expect, it } from 'vitest';
import {
  createProviderPsbtApprovalExplanation,
  providerPsbtApprovalExplanationSchema,
} from '../../src/domain/transactions/provider-psbt-approval';

const derivation = {
  accountId: `acct_signet_${'a'.repeat(64)}`,
  account: 0,
  lane: 'payment' as const,
  chain: 0 as const,
  index: 0,
  path: "m/84'/1'/0'/0/0",
  publicKeyHex: `02${'11'.repeat(32)}`,
};

function explanation(sighashes: number[]) {
  return createProviderPsbtApprovalExplanation({
    selectedInputIndexes: sighashes.map((_value, index) => index),
    inputs: sighashes.map((sighash, index) => ({
      valueSats: 10_000n,
      ownership: 'wallet' as const,
      derivation: { ...derivation, index, path: `m/84'/1'/0'/0/${index}` },
      sighash,
      classification: { inscriptions: [] },
    })),
    outputs: [0, 1].map((index) => ({
      valueSats: 8_000n,
      scriptPubKey: `0014${String(index + 1).repeat(40)}`,
      scriptType: 'p2wpkh' as const,
      address: `tb1qoutput${index}`,
      role: index === 0 ? 'recipient' as const : 'payment_change' as const,
      ...(index === 1 ? { derivation: { ...derivation, chain: 1 as const } } : {}),
    })),
    protectedSatFlow: [],
    inscriptionEffects: [],
    analysisWarnings: [],
    feeRateSatPerKvB: 2_000n,
    rbf: true,
    broadcast: false,
    genericListing: false,
  });
}

describe('provider PSBT approval explanation', () => {
  it('intersects guarantees across every signature because a site may use only a subset', () => {
    const mixed = explanation([1, 3]);
    expect(mixed.commitments).toEqual({
      inputs: 'fixed',
      outputs: 'changeable',
      fee: 'changeable',
      feeRate: 'fixed',
    });
    expect(mixed.outputs.map((output) => output.guaranteed)).toEqual([false, true]);
    expect(mixed.guaranteedWalletReturnSats).toBe('8000');
    expect(mixed.maximumWalletDebitSats).toBe('12000');
    expect(mixed.warningCodes).toContain('mixed_sighashes');

    const disjointSingles = explanation([3, 3]);
    expect(disjointSingles.outputs.map((output) => output.guaranteed)).toEqual([false, false]);
    expect(disjointSingles.guaranteedWalletReturnSats).toBe('0');
    expect(disjointSingles.maximumWalletDebitSats).toBe('20000');
  });

  it('marks ALL|ANYONECANPAY outputs fixed while keeping inputs and fee changeable', () => {
    const value = explanation([0x81]);
    expect(value.presentation).toBe('flexible');
    expect(value.commitments).toEqual({
      inputs: 'changeable',
      outputs: 'fixed',
      fee: 'changeable',
      feeRate: 'fixed',
    });
    expect(value.warningCodes).toEqual(['inputs_changeable', 'fee_changeable']);
  });

  it('marks the transaction output set changeable for SINGLE even when its one output is guaranteed', () => {
    const value = explanation([3]);
    expect(value.commitments).toEqual({
      inputs: 'fixed',
      outputs: 'changeable',
      fee: 'changeable',
      feeRate: 'fixed',
    });
    expect(value.outputs.map((output) => output.guaranteed)).toEqual([true, false]);
  });

  it('exports one strict runtime explanation boundary for every approval surface', () => {
    const value = explanation([0x81]);
    expect(providerPsbtApprovalExplanationSchema.parse(value)).toEqual(value);
    expect(providerPsbtApprovalExplanationSchema.safeParse({
      ...value,
      commitments: { ...value.commitments, outputs: 'changeable' },
    }).success).toBe(false);
    expect(providerPsbtApprovalExplanationSchema.safeParse({
      ...value,
      futureMeaning: true,
    }).success).toBe(false);
  });
});
