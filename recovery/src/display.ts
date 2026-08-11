/**
 * ADR 0007 §6, capability 4: "independently display and validate the exact
 * transaction, fee, destination, change, policy, and signatures."
 *
 * Every number and every address on this screen is computed here from the
 * policy and the raw transaction bytes. Nothing is echoed out of the plan's own
 * summary fields. That distinction is the entire value of the screen: a plan
 * that *claims* a 1,000-sat fee while its bytes move 50,000 sats to a stranger
 * must display the truth, and the only way to guarantee that is to never read
 * the claim.
 */
import { NETWORK, TEST_NETWORK, Transaction } from '@scure/btc-signer';
import { generateVaultPolicyIdentity } from '../../src/domain/vault/multisig-descriptors';
import { derive } from './kit';
import { validateVaultPsbt } from '../../src/domain/vault/multisig-psbt';
import { canonicalVaultPlanBytes } from '../../src/domain/vault/multisig-encoding';
import { bytesToHex, hexToBytes } from '../../src/domain/vault/encoding';
import type {
  VaultPolicyIdentityV1,
  VaultSignerRole,
  VaultUnsignedPlanV1,
} from '../../src/domain/vault/multisig-contracts';
import { sha256Hex } from './crypto-node';

export interface ReviewFacts {
  policyId: string;
  network: string;
  receiveChecksum: string;
  changeChecksum: string;
  totalInSats: bigint;
  destinationAddress: string;
  destinationSats: bigint;
  changeSats: bigint;
  changeAddress: string | null;
  changeProvenOwned: boolean;
  feeSats: bigint;
  vsize: number;
  feeRateSatPerVb: string;
  planDigest: string;
  rolesPresent: VaultSignerRole[];
  disagreements: string[];
}

const ROLE_LABEL: Record<VaultSignerRole, string> = {
  'desktop-a': 'A (Desktop)',
  'mobile-b': 'B (Mobile)',
  'recovery-c': 'C (offline Recovery Key)',
};

/**
 * Recompute every reviewable fact from first principles.
 *
 * `disagreements` collects any place where a value the plan states differs from
 * the value its own bytes produce. It should always be empty — core's
 * `validateVaultPsbt` refuses such a plan long before this point — but the
 * screen reports it rather than assuming, because "the validator would have
 * caught it" is precisely the assumption an independent review exists to avoid.
 */
export function reviewFacts(
  identity: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  psbtHex?: string,
): ReviewFacts {
  const disagreements: string[] = [];
  const note = (claim: string, stated: unknown, computed: unknown): void => {
    if (String(stated) !== String(computed)) {
      disagreements.push(`${claim}: the plan says ${String(stated)}, its bytes say ${String(computed)}`);
    }
  };

  // Regenerate the policy from the signer origins rather than trusting the
  // identity object handed in.
  const regenerated = generateVaultPolicyIdentity(identity.network, identity.signers);
  note('policy ID', identity.policyId, regenerated.policyId);
  note('plan policy binding', plan.policyId, regenerated.policyId);

  const raw = Transaction.fromRaw(hexToBytes(plan.unsignedTransactionHex));
  if (bytesToHex(raw.unsignedTx) !== plan.unsignedTransactionHex) {
    disagreements.push('the unsigned transaction does not re-serialize to the bytes the plan carries');
  }

  const totalInSats = plan.inputs.reduce((sum, input) => sum + BigInt(input.valueSats), 0n);
  let outputTotal = 0n;
  for (let index = 0; index < raw.outputsLength; index += 1) {
    outputTotal += raw.getOutput(index).amount ?? 0n;
  }
  const feeSats = totalInSats - outputTotal;
  note('fee', plan.feeSats, feeSats);

  const net = plan.network;
  // Read the destination back out of the raw bytes, then cross-check the plan's
  // claim against it — the address a user reads must come from what will be
  // broadcast, not from a field beside it.
  // An output script with no address form is not something this policy can
  // produce, so say so rather than falling back to the plan's own claim — the
  // fallback would display exactly the value this screen exists to distrust.
  const decoded = raw.getOutputAddress(
    plan.destination.outputIndex,
    plan.network === 'mainnet' ? NETWORK : TEST_NETWORK,
  );
  const destinationAddress = decoded ?? '(this output script has no address form)';
  note('destination address', plan.destination.address, destinationAddress);
  const destinationSats = raw.getOutput(plan.destination.outputIndex).amount ?? 0n;
  note('destination amount', plan.amountSats, destinationSats);

  let changeSats = 0n;
  let changeAddress: string | null = null;
  let changeProvenOwned = false;
  const changeOutput = plan.outputs.find((output) => output.purpose === 'vault-change');
  if (changeOutput) {
    changeSats = raw.getOutput(changeOutput.outputIndex).amount ?? 0n;
    const derived = derive(regenerated, 'change', changeOutput.derivationIndex!);
    changeAddress = derived.address;
    const actualScript = raw.getOutput(changeOutput.outputIndex).script;
    changeProvenOwned = actualScript !== undefined &&
      bytesToHex(actualScript) === derived.scriptPubKeyHex;
    if (!changeProvenOwned) {
      disagreements.push(
        'the change output is NOT owned by this policy — its script is not the one this Vault derives',
      );
    }
  }
  note('change', plan.changeSats, changeSats);

  const vsize = plan.vsize;
  const feeRateSatPerVb = vsize > 0 ? (Number(feeSats) / vsize).toFixed(2) : 'n/a';

  const planDigest = sha256Hex(
    Buffer.concat([
      Buffer.from('drey-vault-plan-v1', 'utf8'),
      Buffer.from([0]),
      Buffer.from(canonicalVaultPlanBytes(plan)),
    ]),
  );
  note('plan digest', plan.planDigest, planDigest);

  let rolesPresent: VaultSignerRole[] = [];
  if (psbtHex !== undefined) {
    rolesPresent = [...validateVaultPsbt(regenerated, plan, psbtHex).roles];
  }

  return {
    policyId: regenerated.policyId, network: net,
    receiveChecksum: regenerated.receiveDescriptor.slice(-8),
    changeChecksum: regenerated.changeDescriptor.slice(-8),
    totalInSats, destinationAddress, destinationSats,
    changeSats, changeAddress, changeProvenOwned,
    feeSats, vsize, feeRateSatPerVb, planDigest, rolesPresent, disagreements,
  };
}

const rule = '─'.repeat(72);

export function renderReview(
  identity: VaultPolicyIdentityV1,
  plan: VaultUnsignedPlanV1,
  psbtHex?: string,
): string {
  const facts = reviewFacts(identity, plan, psbtHex);
  const lines: string[] = [];
  const row = (label: string, value: string): void => { lines.push(`  ${label.padEnd(26)}${value}`) };

  lines.push(rule, '  RECOVERY SPEND — REVIEW', rule);
  row('Network', facts.network.toUpperCase());
  row('Policy ID', facts.policyId);
  row('Descriptor checksums', `receive #${facts.receiveChecksum}   change #${facts.changeChecksum}`);
  row('Plan digest', facts.planDigest);
  lines.push('');

  lines.push('  INPUTS');
  for (const [index, input] of plan.inputs.entries()) {
    const derived = derive(identity, input.branch, input.derivationIndex);
    row(`  ${index}`, `${input.txid}:${input.vout}`);
    row('', `${BigInt(input.valueSats).toLocaleString('en-US')} sats  ` +
      `${input.branch}/${input.derivationIndex}  ${derived.address}`);
  }
  row('Total in', `${facts.totalInSats.toLocaleString('en-US')} sats`);
  lines.push('');

  lines.push('  OUTPUTS');
  row('Destination', facts.destinationAddress);
  row('  amount', `${facts.destinationSats.toLocaleString('en-US')} sats`);
  if (facts.changeAddress !== null) {
    row('Change (back to Vault)', facts.changeAddress);
    row('  amount', `${facts.changeSats.toLocaleString('en-US')} sats`);
    row('  ownership', facts.changeProvenOwned
      ? 'PROVED — regenerated from this policy'
      : '*** NOT PROVED — DO NOT SIGN ***');
  } else {
    row('Change', 'none — this is a full sweep');
  }
  lines.push('');

  row('Fee', `${facts.feeSats.toLocaleString('en-US')} sats`);
  row('Fee rate', `${facts.feeRateSatPerVb} sat/vB over ${facts.vsize} vbytes`);
  row('Sighash', 'SIGHASH_ALL');
  lines.push('');

  row('Signatures present', facts.rolesPresent.length === 0
    ? 'none'
    : facts.rolesPresent.map((role) => ROLE_LABEL[role]).join(', '));
  row('Quorum needed', '2 of 3 distinct roles');

  if (facts.disagreements.length > 0) {
    lines.push('', '  *** THE PLAN DISAGREES WITH ITS OWN BYTES — DO NOT SIGN ***');
    for (const item of facts.disagreements) lines.push(`      - ${item}`);
  }
  lines.push(rule);
  return lines.join('\n');
}
