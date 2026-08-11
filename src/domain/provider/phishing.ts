/** Signed, expiring, data-only provider phishing policy (spec §6.4, §20.5). */
import { z } from 'zod';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../vault/encoding';
import { getCryptoProvider } from '../vault/crypto-provider';
import {
  normalizeProviderOrigin,
  type NormalizedProviderOrigin,
  type OriginWarning,
} from './origin';

const originEntrySchema = z
  .object({
    origin: z.string().min(1).max(2_048),
    reason: z.enum(['credential_theft', 'wallet_drainer', 'malware', 'confirmed_fraud']),
    appealUrl: z
      .string()
      .max(2_048)
      .url()
      .refine((value) => value.startsWith('https://'), 'HTTPS required'),
  })
  .strict();

const unsignedPhishingListBaseSchema = z
  .object({
    version: z.literal(1),
    issuedAtMs: z.number().int().nonnegative(),
    expiresAtMs: z.number().int().positive(),
    maliciousOrigins: z.array(originEntrySchema).max(10_000),
  })
  .strict();

const unsignedPhishingListSchema = unsignedPhishingListBaseSchema
  .refine((value) => value.expiresAtMs > value.issuedAtMs, 'expiry must follow issue time');

export const signedPhishingListSchema = unsignedPhishingListBaseSchema
  .extend({ signature: z.string().regex(/^[0-9a-f]{128}$/u) })
  .strict()
  .refine((value) => value.expiresAtMs > value.issuedAtMs, 'expiry must follow issue time');

export type SignedPhishingList = z.infer<typeof signedPhishingListSchema>;
export type UnsignedPhishingList = z.infer<typeof unsignedPhishingListSchema>;

export type PhishingListStatus = 'valid' | 'expired' | 'not_yet_valid' | 'invalid';
export type PhishingPolicyWarning = OriginWarning | 'security_list_invalid' | 'security_list_expired';

export type VerifiedPhishingList =
  | { status: 'valid'; list: SignedPhishingList }
  | { status: 'expired' | 'not_yet_valid'; list: SignedPhishingList }
  | { status: 'invalid' };

export interface PhishingDecision {
  action: 'allow' | 'warn' | 'block';
  origin: NormalizedProviderOrigin;
  listStatus: PhishingListStatus;
  warnings: readonly PhishingPolicyWarning[];
  blockReason?: SignedPhishingList['maliciousOrigins'][number]['reason'];
  appealUrl?: string;
}

const DOMAIN_TAG = utf8ToBytes('drey-provider-phishing-list-v1:');
export const MAX_PHISHING_LIST_BYTES = 1_000_000;

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
}

/** Deterministic signed bytes. The strict schema prevents unsigned fields. */
export function phishingListSigningBytes(list: UnsignedPhishingList): Uint8Array {
  const parsed = unsignedPhishingListSchema.parse(list);
  return concat(DOMAIN_TAG, utf8ToBytes(JSON.stringify(parsed)));
}

function hasCanonicalOrigins(list: SignedPhishingList): boolean {
  const seen = new Set<string>();
  for (const entry of list.maliciousOrigins) {
    let normalized: string;
    try {
      normalized = normalizeProviderOrigin(entry.origin).asciiOrigin;
    } catch {
      return false;
    }
    if (normalized !== entry.origin || seen.has(normalized)) return false;
    seen.add(normalized);
  }
  return true;
}

export function verifyPackagedPhishingList(
  bodyBytes: Uint8Array,
  publicKeyHex: string,
  nowMs: number,
): VerifiedPhishingList {
  if (!/^[0-9a-f]{64}$/u.test(publicKeyHex)) return { status: 'invalid' };
  if (bodyBytes.byteLength > MAX_PHISHING_LIST_BYTES) return { status: 'invalid' };
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bodyBytes));
  } catch {
    return { status: 'invalid' };
  }
  const parsed = signedPhishingListSchema.safeParse(raw);
  if (!parsed.success || !hasCanonicalOrigins(parsed.data)) return { status: 'invalid' };
  const { signature, ...unsigned } = parsed.data;
  const valid = getCryptoProvider().ed25519Verify(
    hexToBytes(signature),
    phishingListSigningBytes(unsigned),
    hexToBytes(publicKeyHex),
  );
  if (!valid) return { status: 'invalid' };
  if (nowMs < parsed.data.issuedAtMs) return { status: 'not_yet_valid', list: parsed.data };
  if (nowMs >= parsed.data.expiresAtMs) return { status: 'expired', list: parsed.data };
  return { status: 'valid', list: parsed.data };
}

export function evaluatePhishingOrigin(input: {
  origin: string;
  protectedHostnames?: readonly string[];
  listBodyBytes: Uint8Array;
  publicKeyHex: string;
  nowMs: number;
}): PhishingDecision {
  const origin = normalizeProviderOrigin(input.origin, input.protectedHostnames);
  const verified = verifyPackagedPhishingList(input.listBodyBytes, input.publicKeyHex, input.nowMs);
  const warnings = new Set<PhishingPolicyWarning>(origin.warnings);

  if (verified.status === 'valid') {
    const match = verified.list.maliciousOrigins.find(
      (entry) => entry.origin === origin.asciiOrigin,
    );
    if (match !== undefined) {
      return {
        action: 'block',
        origin,
        listStatus: 'valid',
        warnings: [...warnings],
        blockReason: match.reason,
        appealUrl: match.appealUrl,
      };
    }
  } else if (verified.status === 'expired') {
    warnings.add('security_list_expired');
  } else {
    warnings.add('security_list_invalid');
  }

  return {
    action: warnings.size === 0 ? 'allow' : 'warn',
    origin,
    listStatus: verified.status,
    warnings: [...warnings],
  };
}

/** Test/build tooling can use the same lowercase encoding without Node Buffer. */
export function phishingPublicKeyHex(publicKey: Uint8Array): string {
  return bytesToHex(publicKey);
}
