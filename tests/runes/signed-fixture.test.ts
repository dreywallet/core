import { readFileSync } from 'node:fs';
import { beforeAll, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { verifySignedResponse } from '../../src/domain/gateway/verify';
import { runeOutputsResponseSchema } from '../../src/domain/runes/evidence';
beforeAll(installTestCryptoProvider);
it('verifies generated signed complete Rune evidence and rejects exact-byte mutation', () => {
  const bodyBytes = new Uint8Array(readFileSync(new URL('../fixtures/gateway/rune.outputs.signed.json', import.meta.url)));
  const body = JSON.parse(new TextDecoder().decode(bodyBytes)) as { requestNonce: string; timestamp: string };
  const publicKeyHex = (JSON.parse(readFileSync(new URL('../fixtures/gateway/dev-public-key.json', import.meta.url), 'utf8')) as { publicKeyHex: string }).publicKeyHex;
  const input = { bodyBytes, expectedNonce: body.requestNonce, expectedNetwork: 'signet' as const,
    publicKeyHex, nowMs: Date.parse(body.timestamp), maxSkewMs: 300000, allowedProtocolVersions: [2] as const };
  const verified = verifySignedResponse(runeOutputsResponseSchema, input);
  expect(verified.ok).toBe(true);
  if (verified.ok) expect(verified.value.outputs[0]!.balances[0]!.amount).toBe('9007199254740993');
  const changed = new TextEncoder().encode(new TextDecoder().decode(bodyBytes).replace('9007199254740993', '9007199254740994'));
  expect(verifySignedResponse(runeOutputsResponseSchema, { ...input, bodyBytes: changed })).toEqual({ ok: false, reason: 'signature' });
  expect(verifySignedResponse(runeOutputsResponseSchema, { ...input, expectedNetwork: 'mainnet' })).toEqual({ ok: false, reason: 'wrong_network' });
});
