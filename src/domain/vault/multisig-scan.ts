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
/**
 * Hard bound on automatic widening, so a scan always terminates and a gateway
 * reporting every address as used cannot stall the client: 160 withdrawals per
 * coordinator, eight times the default bound.
 */
export const VAULT_SCAN_INDEX_CEILING = 320;

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
  const derived = new Map<string, IndexedScriptHash>();
  const ports: ScanUnitPorts = {
    network: input.network,
    snapshot: async (request) => {
      const response = await input.gateway.fetchSnapshot(request);
      if (response.ok) {
        // scanUnit may discard a complete attempt and retry on revision skew.
        // Retain the most recent successful snapshot so the returned source
        // belongs to the attempt that can ultimately succeed.
        envelope = {
          instanceId: response.value.instanceId,
          classificationRevision: response.value.classificationRevision,
          coreTip: response.value.coreTip,
          indexTip: response.value.indexTip,
        };
      }
      return response;
    },
    classify: (request) => input.gateway.classifyOutpoints(request),
    // Each widening pass rescans from index zero; derive every address once.
    hashesFor: (_unit, chain, from, to) => {
      const hashes: IndexedScriptHash[] = [];
      for (let index = from; index < to; index += 1) {
        const key = `${chain}:${index}`;
        let hash = derived.get(key);
        if (hash === undefined) {
          hash = vaultScriptHashes(input.policy, chain, index, index + 1)[0]!;
          derived.set(key, hash);
        }
        hashes.push(hash);
      }
      return hashes;
    },
    shouldCancel: input.shouldCancel ?? (() => false),
  };

  let cap = Math.min(input.maxIndexPerBranch ?? VAULT_MAX_INDEX_PER_BRANCH, VAULT_SCAN_INDEX_CEILING);
  for (;;) {
    const result = await scanUnit(VAULT_SCAN_UNIT, ports, {
      maxIndexPerChain: cap,
      burnedChangeCount: input.burnedChangeCount ?? 0,
    });
    // Change moves to ever-higher indexes, split between two coordinators that
    // cannot see each other's counters. Activity within the gap of the bound
    // means more may lie beyond it: widen and rescan instead of silently
    // leaving those funds out of balances and planning.
    if (!result.ok || !result.boundaryPrompt || cap >= VAULT_SCAN_INDEX_CEILING) {
      return { result, source: envelope };
    }
    cap = Math.min(cap * 2, VAULT_SCAN_INDEX_CEILING);
  }
}
