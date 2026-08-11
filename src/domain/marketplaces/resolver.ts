import { SigHash, Transaction } from '@scure/btc-signer';
import type { Network } from '../keys/derivation';
import { base64ToBytes, bytesToBase64 } from '../vault/encoding';
import { scriptKind } from '../transactions/fees';
import { MARKETPLACE_TEMPLATES, marketplaceForOrigin, type MarketplaceTemplate } from './registry';
import type { MarketplaceContext, MarketplaceResolution } from './types';
import { validateMarketplaceContextContract } from './contracts';

export interface MarketplacePsbtCandidate {
  canonicalPsbtBase64: string;
  byteLength: number;
  inputCount: number;
  outputCount: number;
  sighashes: number[];
  flexible: boolean;
  flexibleInputIndexes: number[];
  taprootScriptPathInputIndexes: number[];
}

function declaredSighash(tx: Transaction, index: number): number {
  const input = tx.getInput(index);
  if (input.sighashType !== undefined) return input.sighashType;
  if (!input.witnessUtxo?.script) throw new Error('PSBT input is missing its previous output');
  return scriptKind(Array.from(input.witnessUtxo.script, (byte) =>
    byte.toString(16).padStart(2, '0')).join('')) === 'p2wpkh' ? SigHash.ALL : SigHash.DEFAULT;
}

export function inspectMarketplacePsbt(psbtBase64: string): MarketplacePsbtCandidate {
  const bytes = base64ToBytes(psbtBase64);
  if (bytesToBase64(bytes) !== psbtBase64) throw new Error('non-canonical PSBT base64');
  const tx = Transaction.fromPSBT(bytes, { lowR: true });
  if (tx.inputsLength === 0 || tx.outputsLength === 0) throw new Error('empty PSBT');
  const sighashes: number[] = [];
  const flexibleInputIndexes: number[] = [];
  const taprootScriptPathInputIndexes: number[] = [];
  for (let index = 0; index < tx.inputsLength; index += 1) {
    const input = tx.getInput(index);
    const sighash = declaredSighash(tx, index);
    sighashes.push(sighash);
    if ((sighash & 0x80) !== 0 || (sighash & 0x03) === 2 || (sighash & 0x03) === 3) {
      flexibleInputIndexes.push(index);
    }
    if (input.tapLeafScript?.length) taprootScriptPathInputIndexes.push(index);
  }
  return {
    canonicalPsbtBase64: psbtBase64,
    byteLength: bytes.length,
    inputCount: tx.inputsLength,
    outputCount: tx.outputsLength,
    sighashes,
    flexible: flexibleInputIndexes.length > 0,
    flexibleInputIndexes,
    taprootScriptPathInputIndexes,
  };
}

function result(
  status: MarketplaceResolution['status'],
  template: MarketplaceTemplate | null,
  marketplaceId: MarketplaceResolution['marketplaceId'],
  flexible: boolean,
  reason: string,
): MarketplaceResolution {
  return {
    status,
    marketplaceId,
    displayName: template?.displayName ?? (marketplaceId === 'satflow' ? 'Satflow' : marketplaceId === 'ordnet' ? 'ord.net' : null),
    templateId: template?.templateId ?? null,
    templateVersion: template?.templateVersion ?? null,
    flexible,
    reason,
  };
}

export function resolveMarketplaceRequest(input: {
  origin: string;
  network: Network;
  context?: MarketplaceContext;
  candidate?: MarketplacePsbtCandidate;
  selectedInputIndexes?: readonly number[];
  method: 'signPsbt' | 'signMessage';
}): MarketplaceResolution {
  const knownByOrigin = marketplaceForOrigin(input.origin);
  const flexible = input.candidate?.flexible ?? false;
  if (knownByOrigin === null) {
    return result('unknown_marketplace', null, null, flexible,
      'The browser-derived origin is not in the compile-time marketplace registry.');
  }
  if (!input.context || input.context.marketplaceId !== knownByOrigin) {
    return result('known_template_mismatch', null, knownByOrigin, flexible,
      'The request did not provide matching versioned marketplace context.');
  }
  if (input.context.version !== 1 || input.context.templateVersion !== 'drey-1') {
    return result('known_marketplace_unknown_version', null, knownByOrigin, flexible,
      'The marketplace context version is not supported by this extension release.');
  }
  const candidates = MARKETPLACE_TEMPLATES.filter((entry) =>
    entry.marketplaceId === knownByOrigin && entry.origins.includes(input.origin) &&
    entry.templateVersion === input.context!.templateVersion && entry.action === input.context!.action &&
    entry.role === input.context!.role && entry.assetKind === input.context!.assetKind &&
    entry.networks.includes(input.network));
  if (candidates.length === 0) {
    return result('unsupported_action', null, knownByOrigin, flexible,
      'This marketplace action, role, asset, or network is not supported.');
  }
  if (candidates.length > 1) {
    // assertMarketplaceRegistryIntegrity rejects overlapping template keys, but
    // it runs in CI rather than at load: bricking the worker over a table defect
    // would take the whole wallet down. Resolve nothing instead of silently
    // taking the first match — an ambiguous policy is not a policy.
    return result('known_template_mismatch', null, knownByOrigin, flexible,
      'More than one pinned template matches this request.');
  }
  const template = candidates[0]!;
  const contract = validateMarketplaceContextContract(input.context);
  if (!contract.ok) {
    return result('known_template_mismatch', template, knownByOrigin, flexible, contract.reason);
  }
  if (input.method === 'signMessage') {
    if (template.steps.length !== 0 || input.context.step !== 1 || input.context.stepCount !== 1) {
      return result('known_template_mismatch', template, knownByOrigin, flexible,
        'The message request does not match the pinned message template.');
    }
    if (template.activation !== 'enabled') {
      return result('known_template_mismatch', template, knownByOrigin, false,
        'This pinned template is fixture-backed and is not enabled for live signing.');
    }
    return result('recognized', template, knownByOrigin, false, 'Exact origin and message template matched.');
  }
  if (!input.candidate || input.candidate.byteLength > template.maxPsbtBytes) {
    return result('known_template_mismatch', template, knownByOrigin, flexible, 'The PSBT is absent or exceeds the template limit.');
  }
  const rule = template.steps.find((item) => item.step === input.context!.step) ??
    (template.stepCount === 'context' ? template.steps[0] : undefined);
  const selected = input.selectedInputIndexes ?? input.candidate.sighashes.map((_, index) => index);
  if (!rule || selected.length === 0 || selected.some((index) =>
    !Number.isInteger(index) || index < 0 || index >= input.candidate!.inputCount ||
    !rule.allowedSighashes.includes(input.candidate!.sighashes[index]!)) ||
      (input.candidate.taprootScriptPathInputIndexes.some((index) => selected.includes(index)) &&
        !rule.allowTaprootScriptPath) ||
      (template.broadcaster !== 'context' && template.broadcaster !== input.context.broadcaster)) {
    return result('known_template_mismatch', template, knownByOrigin, flexible,
      'The PSBT shape, step, sighash, or Taproot path differs from the pinned template.');
  }
  if (template.activation !== 'enabled') {
    return result('known_template_mismatch', template, knownByOrigin, flexible,
      'This pinned template is fixture-backed and is not enabled for live signing.');
  }
  return result('recognized', template, knownByOrigin, flexible, 'Exact origin, version, action, and candidate policy matched.');
}

export function templateForResolution(resolution: MarketplaceResolution): MarketplaceTemplate | null {
  if (resolution.status !== 'recognized' || !resolution.templateId) return null;
  return MARKETPLACE_TEMPLATES.find((entry) => entry.templateId === resolution.templateId &&
    entry.templateVersion === resolution.templateVersion) ?? null;
}
