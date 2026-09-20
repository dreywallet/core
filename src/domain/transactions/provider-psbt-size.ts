import type { Transaction } from '@scure/btc-signer';
import { verifyOrdnetSaleScriptPath } from '../marketplaces/ordnet-script-path';
import { verifyOrdnetFoundryTimelockPath } from '../marketplaces/ordnet-foundry-path';
import { estimateVsize, scriptKind, witnessStackBytes } from './fees';
import type { AnalysisExpectedInput } from './analysis';

/** Provider witness bounds, shared by planning and independent reanalysis. */
export function estimateProviderVsize(
  tx: Transaction,
  inputs: readonly AnalysisExpectedInput[],
  outputScripts: readonly string[],
): bigint {
  const witnesses = inputs.map((planned, index) => {
    if (scriptKind(planned.scriptPubKey) === 'p2wpkh') return 108n;
    const leaves = tx.getInput(index).tapLeafScript;
    if (!leaves?.length) return witnessStackBytes([planned.sighash === 0 ? 64 : 65]);
    // Unknown counterparty leaves have no reliable final witness bound.
    if (planned.ownership !== 'wallet' || !planned.derivation || leaves.length !== 1) {
      throw new Error('unknown finalized witness size');
    }
    const key = planned.derivation.publicKeyHex.slice(2);
    let signatures: number;
    try {
      verifyOrdnetSaleScriptPath(tx, index, key);
      signatures = 2;
    } catch {
      verifyOrdnetFoundryTimelockPath(tx, [0, 1], key);
      signatures = 1;
    }
    const [control, scriptWithVersion] = leaves[0]!;
    // A counterparty signature may use a non-DEFAULT sighash. Count the
    // maximum signature size for pinned script paths, before weight rounding.
    return witnessStackBytes([
      ...Array<number>(signatures).fill(65),
      scriptWithVersion.length - 1,
      33 + 32 * control.merklePath.length,
    ]);
  });
  return estimateVsize(inputs.map((input) => input.scriptPubKey), outputScripts, witnesses);
}
