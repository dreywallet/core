import { evaluateEligibility, type EligibilityContext } from '../classification/eligibility';
import { outpointKey, type WalletUtxo } from '../classification/types';
import {
  economicChangeThreshold,
  estimateVsize,
  feeForVsize,
  inputVbytes,
} from './fees';

export interface CoinSelectionRequest {
  utxos: readonly WalletUtxo[];
  eligibility: Omit<EligibilityContext, 'marginalFeeSatsFor'>;
  accountId: string;
  account: number;
  feeRate: bigint;
  targetSats: bigint;
  recipientScripts: readonly string[];
  changeScript: string;
  sendMax: boolean;
  selectedOutpoints?: ReadonlySet<string>;
  /**
   * §14.1 labelGroupKey per outpoint key. Absent or empty leaves selection
   * byte-for-byte unchanged.
   */
  labelGroupByOutpoint?: ReadonlyMap<string, string>;
}

export interface CoinSelection {
  inputs: WalletUtxo[];
  recipientSats: bigint;
  changeSats: bigint;
  feeSats: bigint;
  vsize: bigint;
}

export type CoinSelectionFailure =
  | 'insufficient_eligible_funds'
  | 'manual_selection_mismatch';

/**
 * Typed selection failure for callers that must preserve the distinction
 * between an exhausted eligible pool and an invalid manual selection. The
 * messages stay unchanged for compatibility with existing logs and tests.
 */
export class CoinSelectionError extends Error {
  constructor(readonly reason: CoinSelectionFailure) {
    super(reason === 'manual_selection_mismatch'
      ? 'manual selection contains an ineligible input'
      : 'insufficient funds');
    this.name = 'CoinSelectionError';
  }
}

function sumValues(utxos: readonly WalletUtxo[]): bigint {
  return utxos.reduce((sum, utxo) => sum + utxo.valueSats, 0n);
}

function stableStringOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function outpointOrder(a: WalletUtxo, b: WalletUtxo): number {
  return stableStringOrder(outpointKey(a.outpoint), outpointKey(b.outpoint));
}

function calculate(
  inputs: readonly WalletUtxo[],
  target: bigint,
  feeRate: bigint,
  recipientScripts: readonly string[],
  changeScript: string,
): CoinSelection | null {
  const total = sumValues(inputs);
  const withChangeVsize = estimateVsize(
    inputs.map((u) => u.scriptPubKey),
    [...recipientScripts, changeScript],
  );
  const withChangeFee = feeForVsize(withChangeVsize, feeRate);
  let change = total - target - withChangeFee;
  const threshold = economicChangeThreshold(changeScript, feeRate);
  if (change > threshold) {
    return {
      inputs: [...inputs],
      recipientSats: target,
      changeSats: change,
      feeSats: withChangeFee,
      vsize: withChangeVsize,
    };
  }

  const noChangeVsize = estimateVsize(inputs.map((u) => u.scriptPubKey), recipientScripts);
  const minimumFee = feeForVsize(noChangeVsize, feeRate);
  change = total - target - minimumFee;
  if (change < 0n) return null;
  return {
    inputs: [...inputs],
    recipientSats: target,
    changeSats: 0n,
    feeSats: total - target,
    vsize: noChangeVsize,
  };
}

/**
 * Excess over the target: everything the inputs carry beyond what the recipient
 * receives, whether it comes back as change or is dumped into the fee. Both
 * branches of calculate() give the same value for a given input set — change is
 * exactly `total - target - fee` — so this ranks input sets, not fee/change
 * splits. Ties break on input count in selectCoins.
 */
function waste(selection: CoinSelection): bigint {
  return selection.inputs.reduce((sum, utxo) => sum + utxo.valueSats, 0n)
    - selection.recipientSats;
}

/**
 * How many distinct §14.4 label groups this input set merges. Spending two
 * groups together publicly links them under the common-input-ownership
 * heuristic, so fewer is better — but only ever as a tie-break.
 *
 * Unlabeled inputs count toward no group: a user who labels nothing sees
 * exactly the selection they saw before.
 */
function distinctLabelGroups(
  selection: CoinSelection,
  labelGroupByOutpoint: ReadonlyMap<string, string>,
): number {
  if (labelGroupByOutpoint.size === 0) return 0;
  const groups = new Set<string>();
  for (const input of selection.inputs) {
    const group = labelGroupByOutpoint.get(outpointKey(input.outpoint));
    if (group !== undefined) groups.add(group);
  }
  return groups.size;
}

const NO_LABEL_GROUPS: ReadonlyMap<string, string> = new Map();

export function selectCoins(req: CoinSelectionRequest): CoinSelection {
  if (req.accountId.length === 0 || req.targetSats < 0n || req.feeRate <= 0n) {
    throw new RangeError('invalid selection target');
  }
  const ctx: EligibilityContext = {
    ...req.eligibility,
    marginalFeeSatsFor: (utxo) => feeForVsize(inputVbytes(utxo.scriptPubKey), req.feeRate),
  };
  const eligible = req.utxos
    .filter((utxo) => evaluateEligibility(utxo, ctx).eligible)
    .filter((utxo) =>
      utxo.accountId === req.accountId && utxo.account === req.account && utxo.lane === 'payment')
    .sort(outpointOrder);

  const candidates = req.selectedOutpoints
    ? eligible.filter((utxo) => req.selectedOutpoints!.has(outpointKey(utxo.outpoint)))
    : eligible;
  if (req.selectedOutpoints && candidates.length !== req.selectedOutpoints.size) {
    throw new CoinSelectionError('manual_selection_mismatch');
  }
  if (candidates.length === 0) throw new CoinSelectionError('insufficient_eligible_funds');

  if (req.sendMax) {
    const vsize = estimateVsize(candidates.map((u) => u.scriptPubKey), req.recipientScripts);
    const feeSats = feeForVsize(vsize, req.feeRate);
    const amount = sumValues(candidates) - feeSats;
    if (amount <= 0n) throw new CoinSelectionError('insufficient_eligible_funds');
    return { inputs: candidates, recipientSats: amount, changeSats: 0n, feeSats, vsize };
  }

  if (req.selectedOutpoints) {
    const selected = calculate(
      candidates,
      req.targetSats,
      req.feeRate,
      req.recipientScripts,
      req.changeScript,
    );
    if (!selected) throw new CoinSelectionError('insufficient_eligible_funds');
    return selected;
  }

  // Try exact/low-waste singles and pairs first, then deterministic smallest-
  // first accumulation. The bounded pair pass avoids exponential behavior.
  const options: CoinSelection[] = [];
  for (let i = 0; i < candidates.length; i += 1) {
    const single = calculate(
      [candidates[i]!], req.targetSats, req.feeRate, req.recipientScripts, req.changeScript,
    );
    if (single) options.push(single);
    if (candidates.length <= 64) {
      for (let j = i + 1; j < candidates.length; j += 1) {
        const pair = calculate(
          [candidates[i]!, candidates[j]!],
          req.targetSats,
          req.feeRate,
          req.recipientScripts,
          req.changeScript,
        );
        if (pair) options.push(pair);
      }
    }
  }
  const ascending = [...candidates].sort((a, b) =>
    a.valueSats === b.valueSats ? outpointOrder(a, b) : a.valueSats < b.valueSats ? -1 : 1,
  );
  const accumulated: WalletUtxo[] = [];
  for (const candidate of ascending) {
    accumulated.push(candidate);
    const result = calculate(
      accumulated, req.targetSats, req.feeRate, req.recipientScripts, req.changeScript,
    );
    if (result) {
      options.push(result);
      break;
    }
  }
  // §14.1: prefer not to merge label groups, but strictly below waste — a
  // privacy preference must never cost the user sats, and it never blocks or
  // narrows what is eligible. Deliberately silent: the §14.1 "Save X sats by
  // combining groups" prompt is not implemented, so the default send flow is
  // unchanged for a user who has never opened the UTXO manager.
  const labelGroups = req.labelGroupByOutpoint ?? NO_LABEL_GROUPS;
  options.sort((a, b) => {
    const aw = waste(a);
    const bw = waste(b);
    if (aw !== bw) return aw < bw ? -1 : 1;
    const ag = distinctLabelGroups(a, labelGroups);
    const bg = distinctLabelGroups(b, labelGroups);
    if (ag !== bg) return ag - bg;
    if (a.inputs.length !== b.inputs.length) return a.inputs.length - b.inputs.length;
    return stableStringOrder(
      a.inputs.map((u) => outpointKey(u.outpoint)).join('|'),
      b.inputs.map((u) => outpointKey(u.outpoint)).join('|'),
    );
  });
  const best = options[0];
  if (!best) throw new CoinSelectionError('insufficient_eligible_funds');
  return best;
}
