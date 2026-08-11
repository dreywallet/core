import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../../src/domain/vault/encoding';
import {
  crc32,
  decodeBytewordsMinimal,
  encodeBytewordsMinimal,
} from '../../src/domain/ur/bytewords';
import { UrTransportError } from '../../src/domain/ur/errors';
import {
  decodeFountainPart,
  encodeFountainPart,
  findNominalFragmentLength,
  FixedRateUrDecoder,
  FixedRateUrEncoder,
} from '../../src/domain/ur/fixed-rate';

const vectors = JSON.parse(
  readFileSync(new URL('../../vectors/bc-ur-v2.json', import.meta.url), 'utf8'),
) as {
  bytewords: { bodyHex: string; minimal: string };
  singlePart: { type: string; cborHex: string; ur: string };
  fountainPart: {
    cborHex: string;
    value: { seqNum: number; seqLen: number; messageLen: number; checksum: number; dataHex: string };
  };
  fixedRate: {
    minFragmentLength: number;
    maxFragmentLength: number;
    checksum: number;
    messageHex: string;
    partCborHex: string[];
  };
};

function expectCode(fn: () => unknown, code: UrTransportError['code']): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(UrTransportError);
    expect((error as UrTransportError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe('BCR-2020-012 Bytewords', () => {
  it('matches the published CRC-32 vector', () => {
    expect(crc32(utf8ToBytes('Wolf'))).toBe(0x598c84dc);
  });

  it('matches the published minimal Bytewords vector exactly', () => {
    const body = hexToBytes(vectors.bytewords.bodyHex);
    const expected = vectors.bytewords.minimal;
    expect(encodeBytewordsMinimal(body)).toBe(expected);
    expect(decodeBytewordsMinimal(expected.toUpperCase())).toEqual(body);
  });

  it('refuses unknown codes, odd input, and a changed checksum', () => {
    expectCode(() => decodeBytewordsMinimal('aa'), 'invalid-bytewords');
    expectCode(() => decodeBytewordsMinimal('aaaaaaaaz'), 'invalid-bytewords');
    const encoded = encodeBytewordsMinimal(Uint8Array.of(1, 2, 3));
    const replacement = encoded.endsWith('ae') ? 'ad' : 'ae';
    const changed = `${encoded.slice(0, -2)}${replacement}`;
    expectCode(() => decodeBytewordsMinimal(changed), 'checksum-mismatch');
  });
});

describe('BCR-2024-001 fixed-rate MUR', () => {
  it('matches the published fragment-length and fountain-part CBOR vectors', () => {
    expect(findNominalFragmentLength(12_345, 1_005, 1_955)).toBe(1_764);
    const encoded = encodeFountainPart({
      ...vectors.fountainPart.value,
      data: hexToBytes(vectors.fountainPart.value.dataHex),
    });
    expect(bytesToHex(encoded)).toBe(vectors.fountainPart.cborHex);
    expect(decodeFountainPart(encoded)).toEqual({
      seqNum: vectors.fountainPart.value.seqNum,
      seqLen: vectors.fountainPart.value.seqLen,
      messageLen: vectors.fountainPart.value.messageLen,
      checksum: vectors.fountainPart.value.checksum,
      data: hexToBytes(vectors.fountainPart.value.dataHex),
    });
  });

  it('matches all nine published fixed-rate encoder CBOR parts', () => {
    const message = hexToBytes(vectors.fixedRate.messageHex);
    const encoder = new FixedRateUrEncoder('test-vector', message, {
      minFragmentLength: vectors.fixedRate.minFragmentLength,
      maxFragmentLength: vectors.fixedRate.maxFragmentLength,
    });
    expect(encoder.frames).toHaveLength(9);
    expect(crc32(message)).toBe(vectors.fixedRate.checksum);
    const partHex = encoder.frames.map((frame) => {
      const payload = frame.split('/')[2]!;
      return bytesToHex(decodeBytewordsMinimal(payload));
    });
    expect(partHex).toEqual(vectors.fixedRate.partCborHex);
  });

  it('cycles deterministically and reconstructs out of order', () => {
    const message = Uint8Array.from({ length: 97 }, (_, index) => index);
    const encoder = new FixedRateUrEncoder('drey-test', message, { maxFragmentLength: 20 });
    expect(encoder.isSinglePart).toBe(false);
    const cycle = encoder.frames.map(() => encoder.nextFrame());
    expect(cycle).toEqual(encoder.frames);
    expect(encoder.nextFrame()).toBe(encoder.frames[0]);
    encoder.reset();
    expect(encoder.nextFrame()).toBe(encoder.frames[0]);

    const decoder = new FixedRateUrDecoder({ expectedType: 'drey-test' });
    for (const frame of [...encoder.frames].reverse()) {
      decoder.receive(frame);
    }
    expect(decoder.result()).toEqual({ type: 'drey-test', cborMessage: message });
  });

  it('reports missing and duplicate parts precisely', () => {
    const encoder = new FixedRateUrEncoder('drey-test', new Uint8Array(80), {
      maxFragmentLength: 20,
    });
    const decoder = new FixedRateUrDecoder();
    expect(decoder.receive(encoder.frames[1]!)).toEqual({
      status: 'accepted', received: 1, expected: 4, missing: [1, 3, 4],
    });
    expect(decoder.receive(encoder.frames[1]!)).toEqual({
      status: 'duplicate', received: 1, expected: 4, missing: [1, 3, 4],
    });
  });

  it('refuses mixed sessions, conflicting duplicates, rateless parts, and non-canonical CBOR', () => {
    const first = new FixedRateUrEncoder('drey-test', new Uint8Array(80), { maxFragmentLength: 20 });
    const second = new FixedRateUrEncoder('drey-test', Uint8Array.from({ length: 80 }, () => 1), {
      maxFragmentLength: 20,
    });
    const mixed = new FixedRateUrDecoder();
    mixed.receive(first.frames[0]!);
    expectCode(() => mixed.receive(second.frames[1]!), 'mixed-session');

    const conflict = new FixedRateUrDecoder();
    conflict.receive(first.frames[0]!);
    const original = decodeFountainPart(decodeBytewordsMinimal(first.frames[0]!.split('/')[2]!));
    original.data[0] = original.data[0]! ^ 1;
    const conflicting = `ur:drey-test/1-${original.seqLen}/${encodeBytewordsMinimal(encodeFountainPart(original))}`;
    expectCode(() => conflict.receive(conflicting), 'conflicting-duplicate');

    const rateless = { ...original, seqNum: original.seqLen + 1 };
    const mixedPart = `ur:drey-test/${rateless.seqNum}-${rateless.seqLen}/${encodeBytewordsMinimal(encodeFountainPart(rateless))}`;
    expectCode(() => new FixedRateUrDecoder().receive(mixedPart), 'unsupported-mixed-part');

    const nonMinimal = hexToBytes('850c0818641a000012345678450105030305');
    expectCode(() => decodeFountainPart(nonMinimal), 'invalid-cbor');
  });

  it('uses single-part syntax and accepts case-insensitive transport', () => {
    const message = hexToBytes('a10143010203');
    const encoder = new FixedRateUrEncoder('drey-test', message);
    expect(encoder.isSinglePart).toBe(true);
    expect(encoder.frames[0]).toMatch(/^ur:drey-test\/[a-z]+$/u);
    const decoder = new FixedRateUrDecoder({ expectedType: 'DREY-TEST' });
    expect(decoder.receive(encoder.frames[0]!.toUpperCase())).toEqual({
      status: 'complete', type: 'drey-test', cborMessage: message,
    });
    expect(decoder.receive(encoder.frames[0]!)).toEqual({
      status: 'duplicate', received: 1, expected: 1, missing: [],
    });
  });

  it('matches the published single-part UR example exactly', () => {
    const message = hexToBytes(vectors.singlePart.cborHex);
    const encoder = new FixedRateUrEncoder(vectors.singlePart.type, message);
    expect(encoder.frames).toEqual([vectors.singlePart.ur]);
  });

  it('round-trips bounded arbitrary messages through single and multipart frames', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        fc.integer({ min: 10, max: 80 }),
        (message, maxFragmentLength) => {
          const encoder = new FixedRateUrEncoder('drey-test', message, {
            minFragmentLength: 1,
            maxFragmentLength,
          });
          const decoder = new FixedRateUrDecoder({ expectedType: 'drey-test' });
          for (const frame of [...encoder.frames].reverse()) decoder.receive(frame);
          expect(decoder.result()?.cborMessage).toEqual(message);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('refuses outer/inner disagreement, configured limit breaches, and bad reconstructed checksums', () => {
    const encoder = new FixedRateUrEncoder('drey-test', new Uint8Array(80), {
      maxFragmentLength: 20,
    });
    const outerMismatch = encoder.frames[0]!.replace('/1-4/', '/2-4/');
    expectCode(() => new FixedRateUrDecoder().receive(outerMismatch), 'invalid-ur');
    expectCode(
      () => new FixedRateUrDecoder({ maxParts: 3 }).receive(encoder.frames[0]!),
      'limit-exceeded',
    );

    const decoder = new FixedRateUrDecoder();
    for (const [index, frame] of encoder.frames.entries()) {
      const part = decodeFountainPart(decodeBytewordsMinimal(frame.split('/')[2]!));
      if (index === 0) part.data[0] = 1;
      const altered = `ur:drey-test/${part.seqNum}-${part.seqLen}/${encodeBytewordsMinimal(encodeFountainPart(part))}`;
      if (index === encoder.frames.length - 1) {
        expectCode(() => decoder.receive(altered), 'checksum-mismatch');
      } else {
        decoder.receive(altered);
      }
    }
  });
});
