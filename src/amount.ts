/**
 * DCR amounts.
 *
 * Amounts are integer numbers of **atoms** (the smallest unit); 1 DCR =
 * 100,000,000 atoms. Values are `bigint` to avoid the precision loss that
 * floating point would introduce around 21 million coins.
 */

/** Atoms in one DCR. */
export const ATOMS_PER_COIN = 100_000_000n;

/** Decimal places in a DCR amount. */
export const COIN_DECIMALS = 8;

/**
 * Parse a decimal DCR string (e.g. "1.5", "-0.00000001") into atoms.
 * Accepts up to 8 fractional digits; more is an error.
 */
export function dcrToAtoms(dcr: string): bigint {
  const s = dcr.trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) throw new Error(`dcrToAtoms: invalid amount "${dcr}"`);
  const negative = s.startsWith("-");
  const body = negative ? s.slice(1) : s;
  const [intPart = "0", fracPart = ""] = body.split(".");
  if (fracPart.length > COIN_DECIMALS) {
    throw new Error(`dcrToAtoms: more than ${COIN_DECIMALS} decimal places`);
  }
  const frac = (fracPart + "00000000").slice(0, COIN_DECIMALS);
  const atoms = BigInt(intPart) * ATOMS_PER_COIN + BigInt(frac);
  return negative ? -atoms : atoms;
}

/**
 * Format atoms as a fixed 8-decimal DCR string (e.g. 150000000n → "1.50000000").
 */
export function atomsToDcr(atoms: bigint): string {
  const negative = atoms < 0n;
  const a = negative ? -atoms : atoms;
  const intPart = a / ATOMS_PER_COIN;
  const frac = (a % ATOMS_PER_COIN).toString().padStart(COIN_DECIMALS, "0");
  return `${negative ? "-" : ""}${intPart.toString()}.${frac}`;
}
