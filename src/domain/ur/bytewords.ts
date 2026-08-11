/**
 * Bytewords minimal encoding (BCR-2020-012).
 *
 * UR uses the first and last letter of each four-letter word. The four-byte
 * CRC-32 is part of Bytewords itself, independent of the message checksum in
 * a multipart fountain part.
 */
import { UrTransportError } from './errors';

const BYTEWORDS = `
able acid also apex aqua arch atom aunt away axis back bald barn belt beta bias
blue body brag brew bulb buzz calm cash cats chef city claw code cola cook cost
crux curl cusp cyan dark data days deli dice diet door down draw drop drum dull
duty each easy echo edge epic even exam exit eyes fact fair fern figs film fish
fizz flap flew flux foxy free frog fuel fund gala game gear gems gift girl glow
good gray grim guru gush gyro half hang hard hawk heat help high hill holy hope
horn huts iced idea idle inch inky into iris iron item jade jazz join jolt jowl
judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi knob lamb
lava lazy leaf legs liar limp lion list logo loud love luau luck lung main many
math maze memo menu meow mild mint miss monk nail navy need news next noon note
numb obey oboe omit onyx open oval owls paid part peck play plus poem pool pose
puff puma purr quad quiz race ramp real redo rich road rock roof ruby ruin runs
rust safe saga scar sets silk skew slot soap solo song stub surf swan taco task
taxi tent tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user
vast very veto vial vibe view visa void vows wall wand warm wasp wave waxy webs
what when whiz wolf work yank yawn yell yoga yurt zaps zero zest zinc zone zoom
`
  .trim()
  .split(/\s+/u);

if (BYTEWORDS.length !== 256) {
  throw new Error('Bytewords table must contain exactly 256 words');
}

const MINIMAL_WORDS = BYTEWORDS.map((word) => `${word[0]}${word[3]}`);
const BYTE_BY_MINIMAL_WORD = new Map(MINIMAL_WORDS.map((word, byte) => [word, byte]));

if (BYTE_BY_MINIMAL_WORD.size !== 256) {
  throw new Error('Bytewords minimal codes must be unique');
}

/** IEEE CRC-32, serialized big-endian by Bytewords and MUR. */
export function crc32(bytes: Uint8Array): number {
  let checksum = 0xffff_ffff;
  for (const byte of bytes) {
    checksum ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      checksum = (checksum >>> 1) ^ (0xedb8_8320 & -(checksum & 1));
    }
  }
  return (checksum ^ 0xffff_ffff) >>> 0;
}

function checksumBytes(bytes: Uint8Array): Uint8Array {
  const checksum = crc32(bytes);
  return Uint8Array.of(
    checksum >>> 24,
    checksum >>> 16,
    checksum >>> 8,
    checksum,
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

/** Encode bytes as lowercase minimal Bytewords with the required CRC-32. */
export function encodeBytewordsMinimal(bytes: Uint8Array): string {
  const encoded = new Uint8Array(bytes.length + 4);
  encoded.set(bytes);
  encoded.set(checksumBytes(bytes), bytes.length);
  let result = '';
  for (const byte of encoded) result += MINIMAL_WORDS[byte]!;
  return result;
}

/** Decode and checksum minimal Bytewords. Input is case-insensitive. */
export function decodeBytewordsMinimal(value: string): Uint8Array {
  const normalized = value.toLowerCase();
  if (!/^[a-z]+$/u.test(normalized) || normalized.length < 8 || normalized.length % 2 !== 0) {
    throw new UrTransportError('invalid-bytewords', 'minimal Bytewords must be paired ASCII letters');
  }

  const decoded = new Uint8Array(normalized.length / 2);
  for (let offset = 0; offset < normalized.length; offset += 2) {
    const word = normalized.slice(offset, offset + 2);
    const byte = BYTE_BY_MINIMAL_WORD.get(word);
    if (byte === undefined) {
      throw new UrTransportError('invalid-bytewords', `unknown minimal Bytewords code ${word}`);
    }
    decoded[offset / 2] = byte;
  }

  const body = decoded.slice(0, -4);
  const expected = checksumBytes(body);
  const actual = decoded.slice(-4);
  if (!equalBytes(actual, expected)) {
    throw new UrTransportError('checksum-mismatch', 'Bytewords CRC-32 does not match');
  }
  return body;
}
