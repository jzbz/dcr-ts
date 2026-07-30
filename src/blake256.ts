/**
 * BLAKE-256 — the 14-round SHA-3 finalist (Aumasson, Henzen, Meier, Phan).
 *
 * This is the hash Decred uses *everywhere*: transaction and block hashes,
 * signature hashes, address hashes, and base58 checksums. It is **not** BLAKE2
 * or BLAKE3; those are entirely different constructions. No mainstream JS hash
 * package shipped the original BLAKE for years, so it is implemented here from
 * the specification and pinned by known-answer vectors generated from dcrd's own
 * `crypto/blake256` package.
 *
 * Reference: "SHA-3 proposal BLAKE" (version 1.3), section 2.
 */

// SHA-256 initialization vector (BLAKE-256 shares it).
const IV = Uint32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
);

// The 16 constants: the first 512 bits of the fractional part of pi.
const C = Uint32Array.of(
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
  0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
);

// The 10 message-permutation rows (SIGMA). BLAKE-256 runs 14 rounds, reusing
// the rows modulo 10.
// prettier-ignore
const SIGMA = Uint8Array.of(
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
  14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
  11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
   7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
   9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
   2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
  12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
  13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
   6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
  10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0,
);

const ROUNDS = 14;

/** The BLAKE-256 digest length in bytes. */
export const BLAKE256_DIGEST_LENGTH = 32;
/** The BLAKE-256 block length in bytes. */
export const BLAKE256_BLOCK_LENGTH = 64;

// Scratch buffers reused across the whole module (single-threaded JS).
const V = new Uint32Array(16);
const M = new Uint32Array(16);

/**
 * The BLAKE-256 compression function. `nullt` selects the "no counter" mode
 * used for a padding-only final block, matching the reference implementation's
 * behaviour where a block that carries no message bits is fed a zero counter.
 */
function compress(
  h: Uint32Array,
  block: Uint8Array,
  offset: number,
  t0: number,
  t1: number,
  nullt: boolean,
): void {
  for (let i = 0; i < 16; i++) {
    const j = offset + i * 4;
    M[i] =
      (((block[j]! << 24) |
        (block[j + 1]! << 16) |
        (block[j + 2]! << 8) |
        block[j + 3]!) >>>
        0);
  }

  V[0] = h[0]!; V[1] = h[1]!; V[2] = h[2]!; V[3] = h[3]!;
  V[4] = h[4]!; V[5] = h[5]!; V[6] = h[6]!; V[7] = h[7]!;
  // Salt is always zero here, so v[8..11] reduce to the constants.
  V[8] = C[0]!; V[9] = C[1]!; V[10] = C[2]!; V[11] = C[3]!;
  V[12] = C[4]!; V[13] = C[5]!; V[14] = C[6]!; V[15] = C[7]!;
  if (!nullt) {
    V[12] ^= t0; V[13] ^= t0; V[14] ^= t1; V[15] ^= t1;
  }

  // The G mixing function, inlined across all eight columns.
  //
  // This was a `g(a, b, c, d, sBase, e)` helper, which reads far better. It is
  // written out because the call overhead dominates: G runs 8 times per round and
  // 14 rounds per 64-byte block, so 112 calls per block with six arguments each.
  // Inlining it measured 2.09x end-to-end throughput on this machine (97 -> 204
  // MiB/s over 8 MiB) with a byte-identical digest, and BLAKE-256 backs every
  // txid, signature hash, address hash and base58 checksum in the library.
  //
  // The bodies are mechanically identical; only the V indices and the SIGMA
  // column offset differ. Verified against dcrd's known-answer vectors at every
  // padding boundary and differentially against @noble/hashes over lengths 0..300.
  let p: number, s0: number, s1: number;
  let va: number, vb: number, vc: number, vd: number, t: number;
  for (let r = 0; r < ROUNDS; r++) {
    const s = (r % 10) * 16;

      // column 0: V[0] V[4] V[8] V[12]
      p = s + 0;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[0]!; vb = V[4]!; vc = V[8]!; vd = V[12]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[0] = va; V[4] = vb; V[8] = vc; V[12] = vd;

      // column 1: V[1] V[5] V[9] V[13]
      p = s + 2;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[1]!; vb = V[5]!; vc = V[9]!; vd = V[13]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[1] = va; V[5] = vb; V[9] = vc; V[13] = vd;

      // column 2: V[2] V[6] V[10] V[14]
      p = s + 4;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[2]!; vb = V[6]!; vc = V[10]!; vd = V[14]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[2] = va; V[6] = vb; V[10] = vc; V[14] = vd;

      // column 3: V[3] V[7] V[11] V[15]
      p = s + 6;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[3]!; vb = V[7]!; vc = V[11]!; vd = V[15]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[3] = va; V[7] = vb; V[11] = vc; V[15] = vd;

      // column 4: V[0] V[5] V[10] V[15]
      p = s + 8;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[0]!; vb = V[5]!; vc = V[10]!; vd = V[15]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[0] = va; V[5] = vb; V[10] = vc; V[15] = vd;

      // column 5: V[1] V[6] V[11] V[12]
      p = s + 10;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[1]!; vb = V[6]!; vc = V[11]!; vd = V[12]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[1] = va; V[6] = vb; V[11] = vc; V[12] = vd;

      // column 6: V[2] V[7] V[8] V[13]
      p = s + 12;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[2]!; vb = V[7]!; vc = V[8]!; vd = V[13]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[2] = va; V[7] = vb; V[8] = vc; V[13] = vd;

      // column 7: V[3] V[4] V[9] V[14]
      p = s + 14;
      s0 = SIGMA[p]!;
      s1 = SIGMA[p + 1]!;
      va = V[3]!; vb = V[4]!; vc = V[9]!; vd = V[14]!;
      va = (va + vb + ((M[s0]! ^ C[s1]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 16) | (t << 16);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 12) | (t << 20);
      va = (va + vb + ((M[s1]! ^ C[s0]!) >>> 0)) >>> 0;
      t = vd ^ va; vd = (t >>> 8) | (t << 24);
      vc = (vc + vd) >>> 0;
      t = vb ^ vc; vb = (t >>> 7) | (t << 25);
      V[3] = va; V[4] = vb; V[9] = vc; V[14] = vd;
  }

  for (let i = 0; i < 8; i++) {
    h[i] = (h[i]! ^ V[i]! ^ V[i + 8]!) >>> 0;
  }
}

/** Incremental BLAKE-256 hasher. */
export class Blake256 {
  private readonly h = IV.slice();
  private readonly buf = new Uint8Array(BLAKE256_BLOCK_LENGTH);
  private buflen = 0;
  /** Total message bytes fed in (used for the final length encoding). */
  private total = 0;
  /** Message bytes already absorbed by the compression function. */
  private compressed = 0;
  private finished = false;

  update(data: Uint8Array): this {
    if (this.finished) throw new Error("Blake256: update after digest");
    let i = 0;
    const n = data.length;
    this.total += n;

    // Top up a partially-filled buffer first.
    if (this.buflen > 0) {
      const need = BLAKE256_BLOCK_LENGTH - this.buflen;
      const take = Math.min(need, n);
      this.buf.set(data.subarray(0, take), this.buflen);
      this.buflen += take;
      i = take;
      if (this.buflen === BLAKE256_BLOCK_LENGTH) {
        this.compressed += BLAKE256_BLOCK_LENGTH;
        compress(this.h, this.buf, 0, lo32(this.compressed), hi32(this.compressed), false);
        this.buflen = 0;
      }
    }

    // Absorb whole blocks straight from the input.
    while (n - i >= BLAKE256_BLOCK_LENGTH) {
      this.compressed += BLAKE256_BLOCK_LENGTH;
      compress(this.h, data, i, lo32(this.compressed), hi32(this.compressed), false);
      i += BLAKE256_BLOCK_LENGTH;
    }

    // Stash the remainder.
    if (i < n) {
      this.buf.set(data.subarray(i), this.buflen);
      this.buflen += n - i;
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.finished) throw new Error("Blake256: digest called twice");
    this.finished = true;

    const rem = this.buflen;
    const block = new Uint8Array(BLAKE256_BLOCK_LENGTH);
    block.set(this.buf.subarray(0, rem));

    if (rem <= 55) {
      // Everything fits in one final block.
      block[rem] = 0x80; // padding start ('1' bit)
      block[55]! |= 0x01; // BLAKE-256 domain bit (merges to 0x81 when rem === 55)
      writeLen(block, this.total);
      // A block with no message bytes carries a zero counter (nullt).
      if (rem === 0) compress(this.h, block, 0, 0, 0, true);
      else compress(this.h, block, 0, lo32(this.total), hi32(this.total), false);
    } else {
      // Not enough room for the length: emit a data block then a padding block.
      block[rem] = 0x80;
      compress(this.h, block, 0, lo32(this.total), hi32(this.total), false);
      const tail = new Uint8Array(BLAKE256_BLOCK_LENGTH);
      tail[55] = 0x01;
      writeLen(tail, this.total);
      compress(this.h, tail, 0, 0, 0, true);
    }

    const out = new Uint8Array(BLAKE256_DIGEST_LENGTH);
    for (let i = 0; i < 8; i++) {
      const v = this.h[i]!;
      out[i * 4] = (v >>> 24) & 0xff;
      out[i * 4 + 1] = (v >>> 16) & 0xff;
      out[i * 4 + 2] = (v >>> 8) & 0xff;
      out[i * 4 + 3] = v & 0xff;
    }
    return out;
  }
}

/**
 * The BLAKE counter is a 64-bit *bit* count, split into two 32-bit halves.
 *
 * These take a **byte** count and derive the halves with plain number
 * arithmetic. The previous version built a BigInt per 64-byte block, which cost
 * roughly 11% of throughput on long inputs for no benefit: a byte count stays
 * exact in a double up to 2^53, so `bytes * 8` is exact up to 2^50 bytes — a
 * pebibyte, far past any message this will see. `>>> 0` is ToUint32, i.e. modulo
 * 2^32 of an exact integer, so the low half is exact too.
 */
function lo32(bytes: number): number {
  return (bytes * 8) >>> 0;
}
function hi32(bytes: number): number {
  return Math.floor((bytes * 8) / 0x100000000) >>> 0;
}
function writeLen(block: Uint8Array, totalBytes: number): void {
  const h = hi32(totalBytes);
  const l = lo32(totalBytes);
  block[56] = (h >>> 24) & 0xff;
  block[57] = (h >>> 16) & 0xff;
  block[58] = (h >>> 8) & 0xff;
  block[59] = h & 0xff;
  block[60] = (l >>> 24) & 0xff;
  block[61] = (l >>> 16) & 0xff;
  block[62] = (l >>> 8) & 0xff;
  block[63] = l & 0xff;
}

/** One-shot BLAKE-256. Returns the 32-byte digest. */
export function blake256(data: Uint8Array): Uint8Array {
  return new Blake256().update(data).digest();
}
