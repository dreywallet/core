/**
 * Provider-origin normalization and display warnings (spec §20.1, §20.5).
 *
 * Authorization always uses `asciiOrigin`, which is the URL implementation's
 * normalized ASCII/punycode origin. Unicode is display-only and can never be
 * fed back into an authorization comparison.
 */

export type OriginWarning = 'punycode' | 'mixed_script' | 'confusable';

export interface NormalizedProviderOrigin {
  asciiOrigin: string;
  unicodeOrigin: string;
  asciiHostname: string;
  unicodeHostname: string;
  warnings: readonly OriginWarning[];
}

const PUNYCODE_BASE = 36;
const PUNYCODE_TMIN = 1;
const PUNYCODE_TMAX = 26;
const PUNYCODE_SKEW = 38;
const PUNYCODE_DAMP = 700;
const PUNYCODE_INITIAL_BIAS = 72;
const PUNYCODE_INITIAL_N = 128;

function decodeDigit(codePoint: number): number {
  if (codePoint >= 48 && codePoint <= 57) return codePoint - 22;
  if (codePoint >= 65 && codePoint <= 90) return codePoint - 65;
  if (codePoint >= 97 && codePoint <= 122) return codePoint - 97;
  return PUNYCODE_BASE;
}

function adaptBias(deltaInput: number, points: number, first: boolean): number {
  let delta = first ? Math.floor(deltaInput / PUNYCODE_DAMP) : Math.floor(deltaInput / 2);
  delta += Math.floor(delta / points);
  let k = 0;
  const threshold = Math.floor(((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2);
  while (delta > threshold) {
    delta = Math.floor(delta / (PUNYCODE_BASE - PUNYCODE_TMIN));
    k += PUNYCODE_BASE;
  }
  return (
    k +
    Math.floor(
      ((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW),
    )
  );
}

/** Small, decode-only RFC 3492 implementation; avoids a runtime dependency. */
function decodePunycodeLabel(encoded: string): string | null {
  const output: number[] = [];
  const delimiter = encoded.lastIndexOf('-');
  let cursor = 0;
  if (delimiter >= 0) {
    for (const char of encoded.slice(0, delimiter)) {
      const codePoint = char.codePointAt(0);
      if (codePoint === undefined || codePoint >= 0x80) return null;
      output.push(codePoint);
    }
    cursor = delimiter + 1;
  }

  let n = PUNYCODE_INITIAL_N;
  let i = 0;
  let bias = PUNYCODE_INITIAL_BIAS;
  while (cursor < encoded.length) {
    const oldI = i;
    let weight = 1;
    for (let k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
      if (cursor >= encoded.length) return null;
      const digit = decodeDigit(encoded.charCodeAt(cursor));
      cursor += 1;
      if (digit >= PUNYCODE_BASE || digit > Math.floor((Number.MAX_SAFE_INTEGER - i) / weight)) {
        return null;
      }
      i += digit * weight;
      const threshold =
        k <= bias ? PUNYCODE_TMIN : k >= bias + PUNYCODE_TMAX ? PUNYCODE_TMAX : k - bias;
      if (digit < threshold) break;
      const multiplier = PUNYCODE_BASE - threshold;
      if (weight > Math.floor(Number.MAX_SAFE_INTEGER / multiplier)) return null;
      weight *= multiplier;
    }

    const outputLength = output.length + 1;
    bias = adaptBias(i - oldI, outputLength, oldI === 0);
    const increment = Math.floor(i / outputLength);
    if (increment > 0x10ffff - n) return null;
    n += increment;
    i %= outputLength;
    if (n >= 0xd800 && n <= 0xdfff) return null;
    output.splice(i, 0, n);
    i += 1;
  }

  try {
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

function unicodeHostname(asciiHostname: string): string {
  return asciiHostname
    .split('.')
    .map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label;
      return decodePunycodeLabel(label.slice(4)) ?? label;
    })
    .join('.');
}

function unicodeOrigin(url: URL, hostname: string): string {
  const host = hostname.startsWith('[') ? hostname : hostname.includes(':') ? `[${hostname}]` : hostname;
  return `${url.protocol}//${host}${url.port === '' ? '' : `:${url.port}`}`;
}

function scriptOf(character: string): string | null {
  if (!/\p{Letter}/u.test(character)) return null;
  if (/\p{Script=Latin}/u.test(character)) return 'latin';
  if (/\p{Script=Cyrillic}/u.test(character)) return 'cyrillic';
  if (/\p{Script=Greek}/u.test(character)) return 'greek';
  if (/\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}/u.test(character)) return 'cjk';
  if (/\p{Script=Hangul}/u.test(character)) return 'hangul';
  if (/\p{Script=Arabic}/u.test(character)) return 'arabic';
  if (/\p{Script=Hebrew}/u.test(character)) return 'hebrew';
  if (/\p{Script=Devanagari}/u.test(character)) return 'devanagari';
  return 'other';
}

const CONFUSABLES: Readonly<Record<string, string>> = {
  // Common Cyrillic/Greek homographs used in ASCII-domain lookalikes.
  'а': 'a', 'А': 'a', 'α': 'a', 'Α': 'a',
  'в': 'b', 'В': 'b', 'β': 'b', 'Β': 'b',
  'с': 'c', 'С': 'c', 'ϲ': 'c',
  'е': 'e', 'Е': 'e', 'ε': 'e', 'Ε': 'e',
  'н': 'h', 'Н': 'h', 'Η': 'h',
  'і': 'i', 'І': 'i', 'ι': 'i', 'Ι': 'i',
  'ј': 'j', 'Ј': 'j',
  'к': 'k', 'К': 'k', 'Κ': 'k',
  'м': 'm', 'М': 'm', 'Μ': 'm',
  'о': 'o', 'О': 'o', 'ο': 'o', 'Ο': 'o',
  'р': 'p', 'Р': 'p', 'ρ': 'p', 'Ρ': 'p',
  'ѕ': 's', 'Ѕ': 's',
  'т': 't', 'Т': 't', 'Τ': 't',
  'х': 'x', 'Х': 'x', 'χ': 'x', 'Χ': 'x',
  'у': 'y', 'У': 'y', 'υ': 'y', 'Υ': 'y',
};

function confusableSkeleton(value: string): string {
  let out = '';
  for (const char of value.normalize('NFKD')) {
    if (/\p{Mark}/u.test(char)) continue;
    out += CONFUSABLES[char] ?? char.toLowerCase();
  }
  return out;
}

export function normalizeProviderOrigin(
  value: string,
  protectedHostnames: readonly string[] = [],
): NormalizedProviderOrigin {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('invalid provider origin');
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.hostname === '') {
    throw new Error('unsupported provider origin');
  }
  if (url.username !== '' || url.password !== '') throw new Error('credentialed provider URL');

  const asciiHostname = url.hostname.toLowerCase();
  const decodedHostname = unicodeHostname(asciiHostname);
  const warningSet = new Set<OriginWarning>();
  if (asciiHostname.split('.').some((label) => label.startsWith('xn--'))) {
    warningSet.add('punycode');
  }

  const scripts = new Set<string>();
  for (const char of decodedHostname) {
    const script = scriptOf(char);
    if (script !== null) scripts.add(script);
  }
  if (scripts.size > 1) warningSet.add('mixed_script');

  const skeleton = confusableSkeleton(decodedHostname);
  for (const protectedHostname of protectedHostnames) {
    let normalizedProtected: string;
    try {
      normalizedProtected = new URL(`https://${protectedHostname}`).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (
      normalizedProtected !== asciiHostname &&
      confusableSkeleton(unicodeHostname(normalizedProtected)) === skeleton
    ) {
      warningSet.add('confusable');
      break;
    }
  }

  return {
    asciiOrigin: url.origin,
    unicodeOrigin: unicodeOrigin(url, decodedHostname),
    asciiHostname,
    unicodeHostname: decodedHostname,
    warnings: [...warningSet],
  };
}
