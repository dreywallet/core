const SATS_PER_BTC = 100_000_000n;

export function usdCentsForSats(
  sats: bigint,
  priceUsdCentsPerBtc: string,
): bigint {
  if (sats < 0n || !/^[1-9][0-9]*$/u.test(priceUsdCentsPerBtc)) {
    throw new Error('invalid fiat conversion input');
  }
  const price = BigInt(priceUsdCentsPerBtc);
  return (sats * price + SATS_PER_BTC / 2n) / SATS_PER_BTC;
}

export function formatUsdFromSats(
  sats: bigint,
  priceUsdCentsPerBtc: string,
  locale: string,
): string {
  const cents = usdCentsForSats(sats, priceUsdCentsPerBtc);
  if (sats > 0n && cents === 0n) return '<$0.01';
  if (cents <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(Number(cents) / 100);
  }
  const whole = cents / 100n;
  const fraction = (cents % 100n).toString().padStart(2, '0');
  return `$${whole.toLocaleString(locale)}.${fraction}`;
}
