import { HDKey } from '@scure/bip32';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';
import { getCryptoProvider } from '../../src/domain/vault/crypto-provider';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import {
  createCommunityVaultPolicy,
} from '../../src/domain/community-vault/policy';
import {
  constructCommunityVaultPsbt,
  createCommunityVaultSpendPlan,
  validateCommunityVaultPsbt,
} from '../../src/domain/community-vault/psbt';
import type {
  CommunityVaultMode,
  CommunityVaultOwnerInputV1,
  CommunityVaultPolicyV1,
  CommunityVaultSpendPlanV1,
} from '../../src/domain/community-vault/contracts';

export function fixtureRoot(index: number): HDKey {
  const seed = getCryptoProvider().sha256(utf8ToBytes(`drey-community-vault-v1-owner-${index}`));
  return HDKey.fromMasterSeed(seed);
}

export function fixtureOwners(allocations: readonly number[]): { owners: CommunityVaultOwnerInputV1[]; roots: HDKey[] } {
  let nextUnit = 0;
  const roots: HDKey[] = [];
  const owners = allocations.map((count, index) => {
    const root = fixtureRoot(index);
    roots.push(root);
    const payout = root.deriveChild(1_000 + index);
    if (!payout.publicKey) throw new Error('fixture payout key unavailable');
    const payment = p2wpkh(payout.publicKey, NETWORK);
    payout.wipePrivateData();
    const units = Array.from({ length: count }, () => nextUnit++);
    return {
      ownerId: `owner-${index}`,
      capTableOrder: index,
      identityCommitmentHex: bytesToHex(getCryptoProvider().sha256(utf8ToBytes(`identity-${index}`))),
      payoutAddress: payment.address,
      payoutScriptPubKeyHex: bytesToHex(payment.script),
      campaignRoot: {
        version: 1 as const,
        masterFingerprintHex: root.fingerprint.toString(16).padStart(8, '0'),
        originPath: 'm' as const,
        campaignXpub: root.publicExtendedKey,
      },
      units,
    };
  });
  if (nextUnit !== 100) throw new Error('fixture allocations must total 100');
  return { owners, roots };
}

export function fixturePolicy(
  mode: CommunityVaultMode = 'open',
  allocations: readonly number[] = [20, 20, 20, 8, 1, 11, 20],
): { policy: CommunityVaultPolicyV1; roots: HDKey[] } {
  const { owners, roots } = fixtureOwners(allocations);
  return {
    policy: createCommunityVaultPolicy({
      version: 1,
      policyVersion: 1,
      network: 'mainnet',
      campaignId: `fixture-${mode}`,
      inscriptionId: `${'11'.repeat(32)}i0`,
      currentOutpoint: { txid: '11'.repeat(32), vout: 0 },
      mode,
      eligibility: 'anyone',
      creatorOwnerId: 'owner-0',
      termsVersion: 'terms-v1',
      capTableVersion: 1,
      owners,
    }),
    roots,
  };
}

export function fixtureSpendPlan(policy: CommunityVaultPolicyV1): CommunityVaultSpendPlanV1 {
  const destination = fixtureRoot(200).deriveChild(0);
  if (!destination.publicKey) throw new Error('fixture destination unavailable');
  const payment = p2wpkh(destination.publicKey, NETWORK);
  destination.wipePrivateData();
  const feeKey = fixtureRoot(201).deriveChild(0);
  if (!feeKey.publicKey) throw new Error('fixture fee key unavailable');
  const feePayment = p2wpkh(feeKey.publicKey, NETWORK);
  feeKey.wipePrivateData();
  return createCommunityVaultSpendPlan({
    version: 1,
    policyVersion: 1,
    network: 'mainnet',
    policyId: policy.policyId,
    capTableHash: policy.capTableHash,
    capTableVersion: policy.capTableVersion,
    planId: 'fixture-rotation-1',
    kind: 'rotation',
    createdAtMs: '1800000000000',
    expiresAtMs: '1800003600000',
    inputs: [
      {
        txid: policy.currentOutpoint.txid,
        vout: policy.currentOutpoint.vout,
        valueSats: '10000',
        scriptPubKeyHex: policy.scriptPubKeyHex,
        sequence: 0xffff_fffd,
      },
      {
        txid: '44'.repeat(32),
        vout: 1,
        valueSats: '2000',
        scriptPubKeyHex: bytesToHex(feePayment.script),
        sequence: 0xffff_fffd,
      },
    ],
    vaultInputIndex: 0,
    outputs: [
      { valueSats: '10000', scriptPubKeyHex: bytesToHex(payment.script) },
      { valueSats: '1000', scriptPubKeyHex: bytesToHex(feePayment.script) },
    ],
    feeSats: '1000',
    ordinalRoute: {
      inscriptionId: policy.inscriptionId,
      inputIndex: 0,
      inputOffsetSats: '0',
      outputIndex: 0,
      outputOffsetSats: '0',
      postageSats: '546',
    },
  });
}

/** Add the independent clean cardinal fee signature before unit approvals. */
export function fixtureFundedPsbt(policy: CommunityVaultPolicyV1, plan: CommunityVaultSpendPlanV1): string {
  const tx = Transaction.fromPSBT(hexToBytes(constructCommunityVaultPsbt(policy, plan)), { PSBTVersion: 0, lowR: true });
  const root = fixtureRoot(201);
  const feeKey = root.deriveChild(0);
  try {
    if (!feeKey.privateKey) throw new Error('fixture fee private key unavailable');
    tx.updateInput(1, { sighashType: SigHash.ALL }, true);
    tx.signIdx(feeKey.privateKey, 1, [SigHash.ALL]);
    tx.finalizeIdx(1);
  } finally {
    feeKey.wipePrivateData();
    root.wipePrivateData();
  }
  const psbtHex = bytesToHex(tx.toPSBT(0));
  validateCommunityVaultPsbt(policy, plan, psbtHex);
  return psbtHex;
}

export function deterministicAux() {
  let counter = 1;
  return (length: number): Uint8Array => {
    if (length !== 32) throw new Error('fixture expects 32-byte aux');
    return new Uint8Array(length).fill(counter++ & 0xff);
  };
}
