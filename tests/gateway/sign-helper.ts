/**
 * Test-only signer mirroring the gateway's signStatusBody: lets tests mint
 * validly signed bodies with arbitrary field mutations under a throwaway
 * keypair. Production code contains no signing path — verification only.
 */
import { getSodium } from '../helpers/sodium';
import { signingInput } from '../../src/domain/gateway/canonical';
import { signedEnvelopeFieldsSchema } from '../../src/domain/gateway/contract';

export interface TestKeypair {
  publicKeyHex: string;
  secretKey: Uint8Array;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function makeTestKeypair(): TestKeypair {
  const sodium = getSodium();
  const kp = sodium.crypto_sign_keypair();
  return { publicKeyHex: toHex(kp.publicKey), secretKey: kp.privateKey };
}

export function signTestBody(status: Record<string, unknown>, keypair: TestKeypair): Uint8Array {
  const sodium = getSodium();
  const encoder = new TextEncoder();
  const unsignedBytes = encoder.encode(JSON.stringify({ ...status, signature: '' }));
  const bodyHash = sodium.crypto_hash_sha256(unsignedBytes);
  const env = signedEnvelopeFieldsSchema.omit({ signature: true }).parse(status);
  const signature = sodium.crypto_sign_detached(signingInput(env, bodyHash), keypair.secretKey);
  return encoder.encode(JSON.stringify({ ...status, signature: toHex(signature) }));
}
