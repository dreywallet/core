import { describe, expect, it } from 'vitest';
import { MessageEnvelope, PROTOCOL_VERSION, parseEnvelope } from '../src/messaging/envelope';

const valid = {
  protocolVersion: PROTOCOL_VERSION,
  requestId: '3b9d5d84-9c3f-4f1a-9a24-1e1f0e2a5b6c',
  sender: 'popup',
  op: 'vault.status',
  payload: {},
};

describe('message envelope', () => {
  it('round-trips a valid envelope through serialization', () => {
    const parsed = parseEnvelope(JSON.parse(JSON.stringify(valid)));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.envelope).toEqual(MessageEnvelope.parse(valid));
  });

  it('rejects a wrong protocol version with a stable code', () => {
    const parsed = parseEnvelope({ ...valid, protocolVersion: 999 });
    expect(parsed).toEqual({ ok: false, code: 'ERR_PROTOCOL_MISMATCH' });
  });

  it('rejects unknown sender contexts', () => {
    expect(parseEnvelope({ ...valid, sender: 'evil-frame' }).ok).toBe(false);
  });

  it('rejects unknown extra fields', () => {
    expect(parseEnvelope({ ...valid, extra: 1 }).ok).toBe(false);
  });

  it('rejects non-objects', () => {
    for (const raw of [null, undefined, 42, 'hi', []]) {
      expect(parseEnvelope(raw).ok).toBe(false);
    }
  });
});
