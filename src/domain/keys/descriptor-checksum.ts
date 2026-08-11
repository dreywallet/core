/** Descriptor checksum from BIP380 / Bitcoin Core's descriptor checksum algorithm. */
export function descriptorChecksum(payload: string): string {
  const inputCharset = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
  const checksumCharset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  let c = 1n;
  let cls = 0;
  let clsCount = 0;
  const polymod = (value: bigint, next: number): bigint => {
    const top = value >> 35n;
    let result = ((value & 0x7_ffff_ffffn) << 5n) ^ BigInt(next);
    const generators = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
    for (let i = 0; i < 5; i += 1) {
      if (((top >> BigInt(i)) & 1n) !== 0n) result ^= generators[i]!;
    }
    return result;
  };
  for (const character of payload) {
    const position = inputCharset.indexOf(character);
    if (position < 0) throw new Error('descriptor contains unsupported character');
    c = polymod(c, position & 31);
    cls = cls * 3 + (position >> 5);
    clsCount += 1;
    if (clsCount === 3) {
      c = polymod(c, cls);
      cls = 0;
      clsCount = 0;
    }
  }
  if (clsCount > 0) c = polymod(c, cls);
  for (let i = 0; i < 8; i += 1) c = polymod(c, 0);
  c ^= 1n;
  let checksum = '';
  for (let i = 0; i < 8; i += 1) {
    checksum += checksumCharset[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  }
  return checksum;
}
