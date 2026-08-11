import { beforeAll, describe, expect, it } from 'vitest';
import { installTestCryptoProvider } from '../helpers/install-crypto-provider';
import { getSodium } from '../helpers/sodium';
import {
  evaluatePhishingOrigin,
  phishingListSigningBytes,
  phishingPublicKeyHex,
  MAX_PHISHING_LIST_BYTES,
  verifyPackagedPhishingList,
  type UnsignedPhishingList,
} from '../../src/domain/provider/phishing';
import {
  PACKAGED_PHISHING_LIST_BYTES,
  PHISHING_LIST_PUBLIC_KEY_HEX,
} from '../../src/domain/provider/packaged-phishing-list';
import { normalizeProviderOrigin } from '../../src/domain/provider/origin';
import { bytesToHex } from '../../src/domain/vault/encoding';

beforeAll(async () => {
  await installTestCryptoProvider();
});

function signedList(
  unsigned: UnsignedPhishingList,
  keypair = getSodium().crypto_sign_keypair(),
): { body: Uint8Array; publicKeyHex: string } {
  const signature = getSodium().crypto_sign_detached(phishingListSigningBytes(unsigned), keypair.privateKey);
  return {
    body: new TextEncoder().encode(JSON.stringify({ ...unsigned, signature: bytesToHex(signature) })),
    publicKeyHex: phishingPublicKeyHex(keypair.publicKey),
  };
}

function fixtureList(overrides: Partial<UnsignedPhishingList> = {}): UnsignedPhishingList {
  return {
    version: 1,
    issuedAtMs: 1_000,
    expiresAtMs: 10_000,
    maliciousOrigins: [
      {
        origin: 'https://evil.example',
        reason: 'wallet_drainer',
        appealUrl: 'https://support.drey.example/appeal',
      },
    ],
    ...overrides,
  };
}

describe('provider origin normalization', () => {
  it('uses a canonical ASCII origin and ignores path/query fragments', () => {
    expect(normalizeProviderOrigin('HTTPS://Example.COM:443/a?b=1#c')).toMatchObject({
      asciiOrigin: 'https://example.com',
      unicodeOrigin: 'https://example.com',
      asciiHostname: 'example.com',
      warnings: [],
    });
    expect(normalizeProviderOrigin('http://example.com:8080/path').asciiOrigin).toBe(
      'http://example.com:8080',
    );
    expect(normalizeProviderOrigin('http://[::1]:8080/path').unicodeOrigin).toBe(
      'http://[::1]:8080',
    );
  });

  it('rejects schemes and credential-bearing URLs that cannot be provider authority', () => {
    expect(() => normalizeProviderOrigin('chrome-extension://abc')).toThrow('unsupported');
    expect(() => normalizeProviderOrigin('file:///tmp/index.html')).toThrow('unsupported');
    expect(() => normalizeProviderOrigin('https://user:secret@example.com')).toThrow('credentialed');
    expect(() => normalizeProviderOrigin('not a URL')).toThrow('invalid');
  });

  it('shows Unicode and punycode while warning on mixed-script confusables', () => {
    const result = normalizeProviderOrigin('https://аpple.com/login', ['apple.com']);
    expect(result.asciiOrigin).toBe('https://xn--pple-43d.com');
    expect(result.unicodeOrigin).toBe('https://аpple.com');
    expect(result.warnings).toEqual(['punycode', 'mixed_script', 'confusable']);
  });
});

describe('signed packaged phishing policy', () => {
  it('ships a valid Drey-signed snapshot that allows the genuine ord.net origin', () => {
    const nowMs = Date.UTC(2026, 7, 10, 12);

    expect(
      verifyPackagedPhishingList(
        PACKAGED_PHISHING_LIST_BYTES,
        PHISHING_LIST_PUBLIC_KEY_HEX,
        nowMs,
      ),
    ).toMatchObject({ status: 'valid' });
    expect(
      evaluatePhishingOrigin({
        origin: 'https://ord.net',
        protectedHostnames: ['squirrelsystems.net', 'ord.net', 'liquidium.fi', 'satflow.com'],
        listBodyBytes: PACKAGED_PHISHING_LIST_BYTES,
        publicKeyHex: PHISHING_LIST_PUBLIC_KEY_HEX,
        nowMs,
      }),
    ).toMatchObject({ action: 'allow', listStatus: 'valid', warnings: [] });
  });

  it('hard-blocks an exact malicious origin only with a valid current signature', () => {
    const fixture = signedList(fixtureList());
    const decision = evaluatePhishingOrigin({
      origin: 'https://evil.example/path',
      listBodyBytes: fixture.body,
      publicKeyHex: fixture.publicKeyHex,
      nowMs: 5_000,
    });
    expect(decision).toMatchObject({
      action: 'block',
      listStatus: 'valid',
      blockReason: 'wallet_drainer',
      appealUrl: 'https://support.drey.example/appeal',
    });

    expect(
      evaluatePhishingOrigin({
        origin: 'https://safe.example',
        listBodyBytes: fixture.body,
        publicKeyHex: fixture.publicKeyHex,
        nowMs: 5_000,
      }),
    ).toMatchObject({ action: 'allow', listStatus: 'valid', warnings: [] });
  });

  it('warns and continues rather than trusting an expired malicious entry', () => {
    const fixture = signedList(fixtureList());
    const decision = evaluatePhishingOrigin({
      origin: 'https://evil.example',
      listBodyBytes: fixture.body,
      publicKeyHex: fixture.publicKeyHex,
      nowMs: 10_000,
    });
    expect(decision).toMatchObject({
      action: 'warn',
      listStatus: 'expired',
      warnings: ['security_list_expired'],
    });
    expect(decision.blockReason).toBeUndefined();
  });

  it('warns and continues on tampering, malformed keys, and not-yet-valid lists', () => {
    const fixture = signedList(fixtureList());
    const tampered = new TextEncoder().encode(
      new TextDecoder().decode(fixture.body).replace('evil.example', 'safe.example'),
    );
    expect(verifyPackagedPhishingList(tampered, fixture.publicKeyHex, 5_000)).toEqual({
      status: 'invalid',
    });
    expect(
      evaluatePhishingOrigin({
        origin: 'https://safe.example',
        listBodyBytes: fixture.body,
        publicKeyHex: '00',
        nowMs: 5_000,
      }),
    ).toMatchObject({ action: 'warn', listStatus: 'invalid', warnings: ['security_list_invalid'] });
    expect(
      evaluatePhishingOrigin({
        origin: 'https://safe.example',
        listBodyBytes: fixture.body,
        publicKeyHex: fixture.publicKeyHex,
        nowMs: 999,
      }),
    ).toMatchObject({ action: 'warn', listStatus: 'not_yet_valid', warnings: ['security_list_invalid'] });
    expect(
      verifyPackagedPhishingList(
        new Uint8Array(MAX_PHISHING_LIST_BYTES + 1),
        fixture.publicKeyHex,
        5_000,
      ),
    ).toEqual({ status: 'invalid' });
  });

  it('rejects a validly signed list with noncanonical or duplicate origins', () => {
    const noncanonical = signedList(
      fixtureList({
        maliciousOrigins: [
          {
            origin: 'https://EVIL.example:443',
            reason: 'confirmed_fraud',
            appealUrl: 'https://support.drey.example/appeal',
          },
        ],
      }),
    );
    expect(verifyPackagedPhishingList(noncanonical.body, noncanonical.publicKeyHex, 5_000)).toEqual({
      status: 'invalid',
    });

    const duplicate = fixtureList();
    duplicate.maliciousOrigins.push({ ...duplicate.maliciousOrigins[0]! });
    const signedDuplicate = signedList(duplicate);
    expect(verifyPackagedPhishingList(signedDuplicate.body, signedDuplicate.publicKeyHex, 5_000)).toEqual({
      status: 'invalid',
    });
  });
});
