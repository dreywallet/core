import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { installTestCryptoProvider } from './helpers/install-crypto-provider';
import {
  GatewayClient,
  MAX_RETRY_JITTER_MS,
  MIN_RETRY_JITTER_MS,
  NONCE_HEADER,
  SIGNED_ENDPOINT_DEADLINE_MS,
  STATUS_DEADLINE_MS,
  TRANSIENT_READ_RETRY_FLOORS_MS,
  type GatewayClientDeps,
} from '../src/gateway-client';
import { makeTestKeypair, signTestBody } from './gateway/sign-helper';
import { feeQuoteResponseSchema, fiatPriceQuoteSchema } from '../src/domain/gateway/contract';

const fixturesDir = join(import.meta.dirname, 'fixtures', 'gateway');
const signedBody = new Uint8Array(readFileSync(join(fixturesDir, 'status.signed.json')));
const signedFees = new Uint8Array(readFileSync(join(fixturesDir, 'fees.signed.json')));
const signedBroadcast = new Uint8Array(readFileSync(join(fixturesDir, 'broadcast.accepted.signed.json')));
const classifyTemplate = JSON.parse(
  readFileSync(join(fixturesDir, 'classify.mixed.signed.json'), 'utf8'),
) as Record<string, unknown>;
const snapshotTemplate = JSON.parse(
  readFileSync(join(fixturesDir, 'snapshot.clean.signed.json'), 'utf8'),
) as Record<string, unknown>;
const devPublicKeyHex = (
  JSON.parse(readFileSync(join(fixturesDir, 'dev-public-key.json'), 'utf8')) as {
    publicKeyHex: string;
  }
).publicKeyHex;
const fixtureTimestampMs = Date.parse(
  (JSON.parse(new TextDecoder().decode(signedBody)) as { timestamp: string }).timestamp,
);
// The fixture's requestNonce; the client must send exactly what it expects back.
const FIXTURE_NONCE = 'fixture-nonce-0001';

beforeAll(async () => {
  await installTestCryptoProvider();
});

afterEach(() => {
  vi.useRealTimers();
});

function makeClient(
  fetchFn: typeof fetch,
  overrides: Partial<GatewayClientDeps> = {},
): GatewayClient {
  return new GatewayClient({
    fetchFn,
    baseUrl: 'http://127.0.0.1:8080',
    publicKeyHex: devPublicKeyHex,
    expectedNetwork: 'signet',
    randomNonce: () => FIXTURE_NONCE,
    now: () => fixtureTimestampMs,
    ...overrides,
  });
}

describe('GatewayClient.fetchStatus', () => {
  it('sends the nonce header and returns the verified status', async () => {
    let capturedUrl: string | undefined;
    let capturedNonce: string | null | undefined;
    const fetchFn: typeof fetch = async (input, init) => {
      capturedUrl = String(input);
      capturedNonce = new Headers(init?.headers).get(NONCE_HEADER);
      return new Response(signedBody.slice().buffer, { status: 200 });
    };
    const result = await makeClient(fetchFn).fetchStatus();
    expect(capturedUrl).toBe('http://127.0.0.1:8080/v1/status');
    expect(capturedNonce).toBe(FIXTURE_NONCE);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.status.network).toBe('signet');
      expect(result.verifiedAtMs).toBe(fixtureTimestampMs);
    }
  });

  it('maps non-2xx responses to the http reason (Caddy 503 stub case)', async () => {
    const fetchFn: typeof fetch = async () =>
      new Response('{"status":"unavailable"}', { status: 503 });
    await expect(makeClient(fetchFn).fetchStatus()).resolves.toEqual({
      ok: false,
      reason: 'http',
      httpStatus: 503,
    });
  });

  it('owns a 10-second abortable deadline and never retries status', async () => {
    vi.useFakeTimers();
    let calls = 0;
    let observedSignal: AbortSignal | undefined;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      observedSignal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    };
    const pending = makeClient(fetchFn).fetchStatus();
    await vi.advanceTimersByTimeAsync(STATUS_DEADLINE_MS - 1);
    expect(observedSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toEqual({ ok: false, reason: 'timeout' });
    expect(observedSignal?.aborted).toBe(true);
    expect(calls).toBe(1);
  });

  it('propagates a caller abort distinctly and does not retry it', async () => {
    const caller = new AbortController();
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    };
    const pending = makeClient(fetchFn).fetchStatus(caller.signal);
    caller.abort();
    await expect(pending).resolves.toEqual({ ok: false, reason: 'aborted' });
    expect(calls).toBe(1);
  });

  it('maps a thrown fetch to network_error', async () => {
    const fetchFn: typeof fetch = async () => {
      throw new TypeError('Failed to fetch');
    };
    await expect(makeClient(fetchFn).fetchStatus()).resolves.toEqual({
      ok: false,
      reason: 'network_error',
    });
  });

  it('rejects a schema-violating 200 body', async () => {
    const fetchFn: typeof fetch = async () => new Response('{"hello":"world"}', { status: 200 });
    await expect(makeClient(fetchFn).fetchStatus()).resolves.toEqual({
      ok: false,
      reason: 'schema',
    });
  });

  it('rejects a replayed body whose nonce does not match this request', async () => {
    const fetchFn: typeof fetch = async () => new Response(signedBody.slice().buffer, { status: 200 });
    const result = await makeClient(fetchFn, { randomNonce: () => 'a'.repeat(32) }).fetchStatus();
    expect(result).toEqual({ ok: false, reason: 'nonce_mismatch' });
  });

  it('fails closed when built with the unprovisioned key sentinel', async () => {
    const fetchFn: typeof fetch = async () => new Response(signedBody.slice().buffer, { status: 200 });
    const result = await makeClient(fetchFn, { publicKeyHex: '' }).fetchStatus();
    expect(result).toEqual({ ok: false, reason: 'key_unprovisioned' });
  });
});

describe('GatewayClient M7 signed endpoints', () => {
  const nonce = '00112233445566778899aabbccddeeff';
  const feeTime = Date.parse((JSON.parse(new TextDecoder().decode(signedFees)) as { timestamp: string }).timestamp);

  it('verifies the flat fee envelope and request nonce', async () => {
    const fetchFn: typeof fetch = async (input, init) => {
      expect(String(input)).toBe('http://127.0.0.1:8080/v1/fees');
      expect(new Headers(init?.headers).get(NONCE_HEADER)).toBe(nonce);
      return new Response(signedFees.slice().buffer, { status: 200 });
    };
    const result = await makeClient(fetchFn, { randomNonce: () => nonce, now: () => feeTime }).fetchFees();
    expect(result.ok && result.value.tiers.map((tier) => tier.effectiveSatPerKvB)).toEqual([5000, 2000, 1000]);
  });

  it('verifies a signed display-only fiat quote', async () => {
    const keypair = makeTestKeypair();
    const feeEnvelope = feeQuoteResponseSchema.parse(JSON.parse(new TextDecoder().decode(signedFees)));
    const body = signTestBody({
      instanceId: feeEnvelope.instanceId,
      network: feeEnvelope.network,
      protocolVersion: 2,
      requestNonce: nonce,
      timestamp: feeEnvelope.timestamp,
      coreTip: feeEnvelope.coreTip,
      indexTip: feeEnvelope.indexTip,
      classificationRevision: feeEnvelope.classificationRevision,
      capabilities: feeEnvelope.capabilities,
      signature: '',
      base: 'BTC',
      quote: 'USD',
      priceUsdCentsPerBtc: '6565000',
      observedAt: feeEnvelope.timestamp,
      expiresAt: new Date(Date.parse(feeEnvelope.timestamp) + 120_000).toISOString(),
      quality: 'consensus',
      sourceCount: 3,
      maxDeviationBps: 15,
    }, keypair);
    const fetchFn: typeof fetch = async (input, init) => {
      expect(String(input)).toBe('http://127.0.0.1:8080/v1/price');
      expect(new Headers(init?.headers).get(NONCE_HEADER)).toBe(nonce);
      return new Response(body.slice().buffer, { status: 200 });
    };
    const result = await makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: () => nonce,
      now: () => feeTime,
    }).fetchPrice();
    expect(result.ok && fiatPriceQuoteSchema.parse(result.value)).toMatchObject({
      priceUsdCentsPerBtc: '6565000',
      quality: 'consensus',
    });
  });

  it('binds the signed broadcast response to the submitted txid and exact body', async () => {
    let submitted: unknown;
    const fetchFn: typeof fetch = async (_input, init) => {
      submitted = JSON.parse(String(init?.body));
      return new Response(signedBroadcast.slice().buffer, { status: 200 });
    };
    const client = makeClient(fetchFn, { randomNonce: () => nonce, now: () => feeTime });
    const txid = 'd'.repeat(64);
    const feeQuote = feeQuoteResponseSchema.parse(JSON.parse(new TextDecoder().decode(signedFees)));
    const request = { network: 'signet' as const, transactionHex: '00', txid,
      wtxid: 'e'.repeat(64), feeTarget: 6 as const, feeQuote };
    const accepted = await client.broadcastTransaction(request);
    expect(accepted.ok && accepted.value.status).toBe('accepted');
    expect(submitted).toEqual(request);

    const mismatched = await client.broadcastTransaction({ ...request, txid: 'c'.repeat(64) });
    expect(mismatched).toEqual({ ok: false, reason: 'schema' });
  });

  it('retries classification after a 5xx with bounded jitter and a fresh nonce', async () => {
    const keypair = makeTestKeypair();
    const nonces = ['a'.repeat(32), 'b'.repeat(32)];
    const seenNonces: string[] = [];
    const sleeps: number[] = [];
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
      seenNonces.push(requestNonce);
      calls += 1;
      if (calls === 1) return new Response('unavailable', { status: 503 });
      return new Response(
        signTestBody({ ...classifyTemplate, requestNonce }, keypair).slice().buffer,
        { status: 200 },
      );
    };
    const result = await makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: () => nonces.shift() ?? 'c'.repeat(32),
      retryJitterMs: () => 417,
      sleep: async (delayMs) => { sleeps.push(delayMs); },
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });
    expect(result.ok).toBe(true);
    expect(calls).toBe(2);
    expect(seenNonces).toEqual(['a'.repeat(32), 'b'.repeat(32)]);
    expect(sleeps).toEqual([417]);
    expect(sleeps[0]).toBeGreaterThanOrEqual(MIN_RETRY_JITTER_MS);
    expect(sleeps[0]).toBeLessThanOrEqual(MAX_RETRY_JITTER_MS);
  });

  it('quietly spans a transient read outage with bounded backoff and fresh nonces', async () => {
    const keypair = makeTestKeypair();
    const seenNonces: string[] = [];
    const sleeps: number[] = [];
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
      seenNonces.push(requestNonce);
      calls += 1;
      if (calls < 5) return new Response('catching up', { status: 503 });
      return new Response(
        signTestBody({ ...classifyTemplate, requestNonce }, keypair).slice().buffer,
        { status: 200 },
      );
    };
    const result = await makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: (() => {
        let nonce = 0;
        return () => String(++nonce).padStart(32, '0');
      })(),
      retryJitterMs: () => 417,
      sleep: async (delayMs) => { sleeps.push(delayMs); },
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });

    expect(result.ok).toBe(true);
    expect(calls).toBe(5);
    expect(new Set(seenNonces).size).toBe(5);
    expect(sleeps).toEqual([417, 917, 1_667, 2_667]);
  });

  it('uses the enriched activity snapshot when the gateway supports it', async () => {
    const keypair = makeTestKeypair();
    const urls: string[] = [];
    const enrichedSnapshot = {
      ...snapshotTemplate,
      activeScriptHashes: [
        ...new Set([
          ...(snapshotTemplate['utxos'] as Array<{ scriptHash: string }>).map((utxo) =>
            utxo.scriptHash),
          ...(snapshotTemplate['history'] as Array<{
            fundedScriptHashes: string[];
            spentScriptHashes: string[];
          }>).flatMap((entry) => [
            ...entry.fundedScriptHashes,
            ...entry.spentScriptHashes,
          ]),
        ]),
      ],
      historyCoverage: { status: 'complete', limitedScriptHashes: [] },
      history: (snapshotTemplate['history'] as Array<Record<string, unknown>>).map((entry) => ({
        ...entry,
        activitySource: {
          inputCount: 1,
          singleInputAddress: 'tb1qsource',
        },
      })),
    };
    const fetchFn: typeof fetch = async (input, init) => {
      urls.push(String(input));
      const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
      return new Response(
        signTestBody({ ...enrichedSnapshot, requestNonce }, keypair).slice().buffer,
        { status: 200 },
      );
    };
    const result = await makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: () => 'a'.repeat(32),
    }).fetchSnapshot({
      network: 'signet',
      scriptHashes: snapshotTemplate['requestedScriptHashes'] as string[],
    });

    expect(result.ok).toBe(true);
    expect(urls).toEqual(['http://127.0.0.1:8080/v1/wallet/scan-snapshot']);
    if (result.ok) {
      expect(result.value.history[0]?.activitySource).toEqual({
        inputCount: 1,
        singleInputAddress: 'tb1qsource',
      });
    }
  });

  it('falls back on an older gateway and keeps transient recovery for wallet snapshots', async () => {
    const keypair = makeTestKeypair();
    const urls: string[] = [];
    const bodies: unknown[] = [];
    let calls = 0;
    const fetchFn: typeof fetch = async (input, init) => {
      urls.push(String(input));
      bodies.push(JSON.parse(String(init?.body)));
      calls += 1;
      if (calls <= 2) return new Response('not found', { status: 404 });
      if (calls < 5) return new Response('catching up', { status: 503 });
      const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
      return new Response(
        signTestBody({ ...snapshotTemplate, requestNonce }, keypair).slice().buffer,
        { status: 200 },
      );
    };
    const result = await makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: (() => {
        let nonce = 0;
        return () => String(++nonce).padStart(32, '0');
      })(),
      retryJitterMs: () => 250,
      sleep: async () => undefined,
    }).fetchSnapshot({
      network: 'signet',
      scriptHashes: snapshotTemplate['requestedScriptHashes'] as string[],
      includeOrdinalFlow: true,
    });

    expect(result.ok).toBe(true);
    expect(calls).toBe(5);
    expect(urls.slice(0, 2)).toEqual([
      'http://127.0.0.1:8080/v1/wallet/scan-snapshot',
      'http://127.0.0.1:8080/v1/wallet/activity-snapshot',
    ]);
    expect(urls.slice(2)).toEqual([
      'http://127.0.0.1:8080/v1/wallet/snapshot',
      'http://127.0.0.1:8080/v1/wallet/snapshot',
      'http://127.0.0.1:8080/v1/wallet/snapshot',
    ]);
    expect(bodies.slice(0, 2)).toEqual(Array.from({ length: 2 }, () => ({
      network: 'signet',
      scriptHashes: snapshotTemplate['requestedScriptHashes'],
      includeOrdinalFlow: true,
    })));
    expect(bodies.slice(2)).toEqual(Array.from({ length: 3 }, () => ({
      network: 'signet',
      scriptHashes: snapshotTemplate['requestedScriptHashes'],
    })));
  });

  it('bounds sustained transient read retries to a ten-second-class envelope', async () => {
    const sleeps: number[] = [];
    let calls = 0;
    const result = await makeClient(async () => {
      calls += 1;
      return new Response('still catching up', { status: 503 });
    }, {
      retryJitterMs: () => 417,
      sleep: async (delayMs) => { sleeps.push(delayMs); },
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });

    expect(result).toEqual({ ok: false, reason: 'http', httpStatus: 503 });
    expect(calls).toBe(TRANSIENT_READ_RETRY_FLOORS_MS.length + 1);
    expect(sleeps).toEqual([417, 917, 1_667, 2_667, 3_167]);
    expect(sleeps.reduce((total, delay) => total + delay, 0)).toBe(8_835);
  });

  it('cancels transient read backoff without another request', async () => {
    const caller = new AbortController();
    let calls = 0;
    const result = await makeClient(async () => {
      calls += 1;
      return new Response('catching up', { status: 503 });
    }, {
      sleep: async () => {
        caller.abort();
        throw new DOMException('aborted', 'AbortError');
      },
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    }, caller.signal);

    expect(result).toEqual({ ok: false, reason: 'aborted' });
    expect(calls).toBe(1);
  });

  it('retries an owned 30-second classification timeout exactly once', async () => {
    vi.useFakeTimers();
    const keypair = makeTestKeypair();
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      if (calls === 1) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        });
      }
      const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
      return new Response(
        signTestBody({ ...classifyTemplate, requestNonce }, keypair).slice().buffer,
        { status: 200 },
      );
    };
    const pending = makeClient(fetchFn, {
      publicKeyHex: keypair.publicKeyHex,
      randomNonce: (() => {
        let nonce = 0;
        return () => String(++nonce).padStart(32, '0');
      })(),
      retryJitterMs: () => 250,
      sleep: async () => undefined,
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });
    await vi.advanceTimersByTimeAsync(SIGNED_ENDPOINT_DEADLINE_MS);
    await expect(pending).resolves.toMatchObject({ ok: true });
    expect(calls).toBe(2);
  });

  it('does not turn repeated full request timeouts into a multi-minute retry loop', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    };
    const pending = makeClient(fetchFn, {
      retryJitterMs: () => 250,
      sleep: async () => undefined,
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });

    await vi.advanceTimersByTimeAsync(SIGNED_ENDPOINT_DEADLINE_MS);
    expect(calls).toBe(2);
    await vi.advanceTimersByTimeAsync(SIGNED_ENDPOINT_DEADLINE_MS);
    await expect(pending).resolves.toEqual({ ok: false, reason: 'timeout' });
    expect(calls).toBe(2);
  });

  it.each(['network', 'body-read'] as const)(
    'retries a %s failure once and then verifies the response',
    async (failure) => {
      const keypair = makeTestKeypair();
      let calls = 0;
      const fetchFn: typeof fetch = async (_input, init) => {
        calls += 1;
        if (calls === 1) {
          if (failure === 'network') throw new TypeError('Failed to fetch');
          return {
            ok: true,
            status: 200,
            arrayBuffer: async () => { throw new TypeError('stream reset'); },
          } as unknown as Response;
        }
        const requestNonce = new Headers(init?.headers).get(NONCE_HEADER) ?? '';
        return new Response(
          signTestBody({ ...classifyTemplate, requestNonce }, keypair).slice().buffer,
          { status: 200 },
        );
      };
      const result = await makeClient(fetchFn, {
        publicKeyHex: keypair.publicKeyHex,
        randomNonce: (() => {
          let nonce = 0;
          return () => String(++nonce).padStart(32, '0');
        })(),
        retryJitterMs: () => 250,
        sleep: async () => undefined,
      }).classifyOutpoints({
        network: 'signet',
        outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
      });
      expect(result.ok).toBe(true);
      expect(calls).toBe(2);
    },
  );

  it('returns typed Retry-After metadata for 429 and never retries it', async () => {
    let calls = 0;
    let sleepCalls = 0;
    const fetchFn: typeof fetch = async () => {
      calls += 1;
      return new Response('slow down', { status: 429, headers: { 'Retry-After': '12' } });
    };
    const result = await makeClient(fetchFn, {
      sleep: async () => { sleepCalls += 1; },
    }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });
    expect(result).toEqual({
      ok: false,
      reason: 'rate_limited',
      httpStatus: 429,
      retryAfterMs: 12_000,
      retryAfterAtMs: fixtureTimestampMs + 12_000,
    });
    expect(calls).toBe(1);
    expect(sleepCalls).toBe(0);
  });

  it('parses an HTTP-date Retry-After and clamps a past date to zero delay', async () => {
    const retryAt = fixtureTimestampMs - 1_000;
    const fetchFn: typeof fetch = async () => new Response('slow down', {
      status: 429,
      headers: { 'Retry-After': new Date(retryAt).toUTCString() },
    });
    await expect(makeClient(fetchFn).fetchFees()).resolves.toEqual({
      ok: false,
      reason: 'rate_limited',
      httpStatus: 429,
      retryAfterMs: 0,
      retryAfterAtMs: retryAt,
    });
  });

  it('never generically retries broadcast, including 5xx responses', async () => {
    let calls = 0;
    const fetchFn: typeof fetch = async () => {
      calls += 1;
      return new Response('unavailable', { status: 503 });
    };
    const result = await makeClient(fetchFn).broadcastTransaction({
      network: 'signet',
      transactionHex: '00',
      txid: 'd'.repeat(64),
      wtxid: 'e'.repeat(64),
      feeTarget: 6,
      feeQuote: feeQuoteResponseSchema.parse(JSON.parse(new TextDecoder().decode(signedFees))),
    });
    expect(result).toEqual({ ok: false, reason: 'http', httpStatus: 503 });
    expect(calls).toBe(1);
  });

  it('applies a 30-second deadline without retry to fee requests', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    };
    const pending = makeClient(fetchFn).fetchFees();
    await vi.advanceTimersByTimeAsync(SIGNED_ENDPOINT_DEADLINE_MS);
    await expect(pending).resolves.toEqual({ ok: false, reason: 'timeout' });
    expect(calls).toBe(1);
  });

  it('does not retry terminal schema verification failures', async () => {
    let calls = 0;
    const fetchFn: typeof fetch = async () => {
      calls += 1;
      return new Response('{"bad":true}', { status: 200 });
    };
    const result = await makeClient(fetchFn, { sleep: async () => undefined }).classifyOutpoints({
      network: 'signet',
      outpoints: [{ txid: 'd'.repeat(64), vout: 0 }],
    });
    expect(result).toEqual({ ok: false, reason: 'schema' });
    expect(calls).toBe(1);
  });
});
