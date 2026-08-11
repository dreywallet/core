/** Coordinator-neutral Vault descriptor scanning over core's scan engine. */
import type { GatewayClient } from '../../gateway-client';
import type { Tip } from '../gateway/contract';
import type { Network } from '../keys/derivation';
import { scriptHashFromScriptPubKey } from '../keys/script-hash';
import {
  scanUnit,
  type IndexedScriptHash,
  type ScanUnitPorts,
  type ScanUnitResult,
} from '../../scan/scan-engine';
import type { ScanUnit } from '../../scan/scan-state';
import type { VaultPolicyIdentityV1 } from './multisig-contracts';
import { deriveVaultOutput } from './multisig-descriptors';

const VAULT_SCAN_UNIT: ScanUnit = { source: 'standard', account: 0, lane: 'payment' };
export const VAULT_MAX_INDEX_PER_BRANCH = 40;

export function vaultScriptHashes(
  policy: VaultPolicyIdentityV1,
  chain: 0 | 1,
  from: number,
  to: number,
): IndexedScriptHash[] {
  const branch = chain === 0 ? 'receive' : 'change';
  const hashes: IndexedScriptHash[] = [];
  for (let index = from; index < to; index += 1) {
    const output = deriveVaultOutput(policy, branch, index);
    hashes.push({
      chain,
      index,
      scriptHash: scriptHashFromScriptPubKey(output.scriptPubKeyHex),
      scriptPubKey: output.scriptPubKeyHex,
    });
  }
  return hashes;
}

export interface VaultScanOutcome {
  result: ScanUnitResult;
  source: {
    instanceId: string;
    classificationRevision: string;
    coreTip: Tip;
    indexTip: Tip;
  } | null;
}

export async function scanVaultPolicy(input: {
  policy: VaultPolicyIdentityV1;
  network: Network;
  gateway: GatewayClient;
  shouldCancel?: () => boolean;
  maxIndexPerBranch?: number;
  burnedChangeCount?: number;
}): Promise<VaultScanOutcome> {
  if (input.policy.network !== input.network) {
    throw new Error('Vault policy network differs from scan network');
  }
  let envelope: VaultScanOutcome['source'] = null;
  const ports: ScanUnitPorts = {
    network: input.network,
    snapshot: async (request) => {
      const response = await input.gateway.fetchSnapshot(request);
      if (response.ok) {
        envelope ??= {
          instanceId: response.value.instanceId,
          classificationRevision: response.value.classificationRevision,
          coreTip: response.value.coreTip,
          indexTip: response.value.indexTip,
        };
      }
      return response;
    },
    classify: (request) => input.gateway.classifyOutpoints(request),
    hashesFor: (_unit, chain, from, to) => vaultScriptHashes(input.policy, chain, from, to),
    shouldCancel: input.shouldCancel ?? (() => false),
  };

  const result = await scanUnit(VAULT_SCAN_UNIT, ports, {
    maxIndexPerChain: input.maxIndexPerBranch ?? VAULT_MAX_INDEX_PER_BRANCH,
    burnedChangeCount: input.burnedChangeCount ?? 0,
  });
  return { result, source: envelope };
}
