/** Deterministic, public, never-funded mainnet-format Community Vault v1 vectors. */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { HDKey } from '@scure/bip32';
import { NETWORK, SigHash, Transaction, p2wpkh } from '@scure/btc-signer';
import { setCryptoProvider, type CryptoProvider } from '../src/domain/vault/crypto-provider';
import { bytesToHex, hexToBytes } from '../src/domain/vault/encoding';
import { createCommunityVaultPolicy, serializeCommunityVaultPolicy } from '../src/domain/community-vault/policy';
import {
  approveCommunityVaultSpend,
  constructCommunityVaultPsbt,
  createCommunityVaultSpendPlan,
  finalizeCommunityVaultPsbt,
} from '../src/domain/community-vault/psbt';

const sha256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(bytes).digest());
const provider: CryptoProvider = {
  argon2id: async () => { throw new Error('unused'); },
  xchaEncrypt: () => { throw new Error('unused'); },
  xchaDecrypt: () => { throw new Error('unused'); },
  sha256,
  ed25519Verify: () => { throw new Error('unused'); },
  randomBytes: () => { throw new Error('vectors never use runtime randomness'); },
};
setCryptoProvider(provider);

const text = (value: string) => new TextEncoder().encode(value);
const root = (index: number) => HDKey.fromMasterSeed(sha256(text(`drey-community-vault-v1-owner-${index}`)));
const allocations = [20, 20, 20, 8, 1, 11, 20] as const;
let nextUnit = 0;
const roots: HDKey[] = [];
const owners = allocations.map((count, index) => {
  const campaignRoot = root(index);
  roots.push(campaignRoot);
  const payoutKey = campaignRoot.deriveChild(1_000 + index);
  if (!payoutKey.publicKey) throw new Error('vector payout key unavailable');
  const payout = p2wpkh(payoutKey.publicKey, NETWORK);
  payoutKey.wipePrivateData();
  return {
    ownerId: `owner-${index}`,
    capTableOrder: index,
    identityCommitmentHex: bytesToHex(sha256(text(`identity-${index}`))),
    payoutAddress: payout.address,
    payoutScriptPubKeyHex: bytesToHex(payout.script),
    campaignRoot: {
      version: 1 as const,
      masterFingerprintHex: campaignRoot.fingerprint.toString(16).padStart(8, '0'),
      originPath: 'm' as const,
      campaignXpub: campaignRoot.publicExtendedKey,
    },
    units: Array.from({ length: count }, () => nextUnit++),
  };
});
const policy = createCommunityVaultPolicy({
  version: 1, policyVersion: 1, network: 'mainnet', campaignId: 'fixture-open',
  inscriptionId: `${'11'.repeat(32)}i0`, currentOutpoint: { txid: '11'.repeat(32), vout: 0 },
  mode: 'open', eligibility: 'anyone', creatorOwnerId: 'owner-0', termsVersion: 'terms-v1',
  capTableVersion: 1, owners,
});
const destinationKey = root(200).deriveChild(0);
if (!destinationKey.publicKey) throw new Error('vector destination key unavailable');
const destination = p2wpkh(destinationKey.publicKey, NETWORK);
destinationKey.wipePrivateData();
const feeRoot = root(201);
const feeKey = feeRoot.deriveChild(0);
if (!feeKey.publicKey || !feeKey.privateKey) throw new Error('vector fee key unavailable');
const feePayment = p2wpkh(feeKey.publicKey, NETWORK);
const plan = createCommunityVaultSpendPlan({
  version: 1, policyVersion: 1, network: 'mainnet', policyId: policy.policyId,
  capTableHash: policy.capTableHash, capTableVersion: policy.capTableVersion,
  planId: 'fixture-rotation-1', kind: 'rotation', createdAtMs: '1800000000000', expiresAtMs: '1800003600000',
  inputs: [
    {
      txid: policy.currentOutpoint.txid, vout: 0, valueSats: '10000',
      scriptPubKeyHex: policy.scriptPubKeyHex, sequence: 0xffff_fffd,
    },
    {
      txid: '44'.repeat(32), vout: 1, valueSats: '2000',
      scriptPubKeyHex: bytesToHex(feePayment.script), sequence: 0xffff_fffd,
    },
  ],
  vaultInputIndex: 0,
  outputs: [
    { valueSats: '10000', scriptPubKeyHex: bytesToHex(destination.script) },
    { valueSats: '1000', scriptPubKeyHex: bytesToHex(feePayment.script) },
  ],
  feeSats: '1000',
  ordinalRoute: {
    inscriptionId: policy.inscriptionId, inputIndex: 0, inputOffsetSats: '0',
    outputIndex: 0, outputOffsetSats: '0', postageSats: '546',
  },
});
const unsignedPsbtHex = constructCommunityVaultPsbt(policy, plan);
const prepared = Transaction.fromPSBT(hexToBytes(unsignedPsbtHex), { PSBTVersion: 0, lowR: true });
prepared.updateInput(1, { sighashType: SigHash.ALL }, true);
prepared.signIdx(feeKey.privateKey, 1, [SigHash.ALL]);
prepared.finalizeIdx(1);
feeKey.wipePrivateData();
feeRoot.wipePrivateData();
const preparedPsbtHex = bytesToHex(prepared.toPSBT(0));
let psbtHex = preparedPsbtHex;
let auxCounter = 1;
const random = (length: number) => new Uint8Array(length).fill(auxCounter++ & 0xff);
for (let index = 0; index < 4; index += 1) {
  psbtHex = approveCommunityVaultSpend({
    policy, plan, psbtHex, ownerId: `owner-${index}`, signerRoot: roots[index]!,
    nowMs: '1800000000100', random,
  }).psbtHex;
}
const signed68PsbtHex = psbtHex;
const signed69 = approveCommunityVaultSpend({
  policy, plan, psbtHex, ownerId: 'owner-4', signerRoot: roots[4]!, nowMs: '1800000000100', random,
});
const finalized = finalizeCommunityVaultPsbt(policy, plan, signed69.psbtHex);

const vector = {
  vectorVersion: 1,
  generatedBy: 'scripts/generate-community-vault-vectors.ts',
  warning: 'PUBLIC DETERMINISTIC NEVER-FUNDED MAINNET-FORMAT TEST DATA ONLY',
  policy,
  policyBytesHex: bytesToHex(serializeCommunityVaultPolicy(policy)),
  plan,
  unsignedPsbtHex,
  preparedPsbtHex,
  signed68PsbtHex,
  signed69PsbtHex: signed69.psbtHex,
  finalized,
};
const outputPath = join(process.cwd(), 'vectors', 'community-vault-v1.json');
writeFileSync(outputPath, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`wrote ${outputPath}`);
for (const item of roots) item.wipePrivateData();
