/**
 * Little-endian byte reader/writer with Bitcoin/Decred "compact size" varints.
 *
 * All multi-byte integers in the Decred wire format are little-endian. Amounts
 * and a few counters are 64-bit, so those cross through `bigint`.
 */

/** Growable little-endian byte writer. */
export class Writer {
  private buf = new Uint8Array(256);
  private len = 0;

  private ensure(extra: number): void {
    if (this.len + extra <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.len + extra) cap *= 2;
    const next = new Uint8Array(cap);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
  }

  u8(v: number): this {
    this.ensure(1);
    this.buf[this.len++] = v & 0xff;
    return this;
  }

  u16(v: number): this {
    this.ensure(2);
    this.buf[this.len++] = v & 0xff;
    this.buf[this.len++] = (v >>> 8) & 0xff;
    return this;
  }

  u32(v: number): this {
    this.ensure(4);
    this.buf[this.len++] = v & 0xff;
    this.buf[this.len++] = (v >>> 8) & 0xff;
    this.buf[this.len++] = (v >>> 16) & 0xff;
    this.buf[this.len++] = (v >>> 24) & 0xff;
    return this;
  }

  u64(v: bigint): this {
    if (v < 0n || v > 0xffffffffffffffffn) throw new Error("u64 out of range");
    this.ensure(8);
    let x = v;
    for (let i = 0; i < 8; i++) {
      this.buf[this.len++] = Number(x & 0xffn);
      x >>= 8n;
    }
    return this;
  }

  /** Signed 64-bit little-endian (two's complement). Used for atom amounts. */
  i64(v: bigint): this {
    if (v < -(1n << 63n) || v >= 1n << 63n) throw new Error("i64 out of range");
    return this.u64(v < 0n ? v + (1n << 64n) : v);
  }

  bytes(b: Uint8Array): this {
    this.ensure(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
    return this;
  }

  /** Compact-size varint. */
  varInt(v: number | bigint): this {
    const n = typeof v === "bigint" ? v : BigInt(v);
    if (n < 0n) throw new Error("varInt: negative");
    if (n < 0xfdn) return this.u8(Number(n));
    if (n <= 0xffffn) return this.u8(0xfd).u16(Number(n));
    if (n <= 0xffffffffn) return this.u8(0xfe).u32(Number(n));
    return this.u8(0xff).u64(n);
  }

  /** A varint length prefix followed by the bytes themselves. */
  varBytes(b: Uint8Array): this {
    return this.varInt(b.length).bytes(b);
  }

  finish(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

/** Little-endian byte reader. */
export class Reader {
  private off = 0;
  constructor(private readonly data: Uint8Array) {}

  get offset(): number {
    return this.off;
  }

  get remaining(): number {
    return this.data.length - this.off;
  }

  private need(n: number): void {
    if (this.off + n > this.data.length) throw new Error("Reader: unexpected end of data");
  }

  u8(): number {
    this.need(1);
    return this.data[this.off++]!;
  }

  u16(): number {
    this.need(2);
    const v = this.data[this.off]! | (this.data[this.off + 1]! << 8);
    this.off += 2;
    return v >>> 0;
  }

  u32(): number {
    this.need(4);
    const v =
      (this.data[this.off]! |
        (this.data[this.off + 1]! << 8) |
        (this.data[this.off + 2]! << 16) |
        (this.data[this.off + 3]! << 24)) >>>
      0;
    this.off += 4;
    return v;
  }

  u64(): bigint {
    this.need(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(this.data[this.off + i]!);
    this.off += 8;
    return v;
  }

  /** Signed 64-bit little-endian (two's complement). */
  i64(): bigint {
    const v = this.u64();
    return v >= 1n << 63n ? v - (1n << 64n) : v;
  }

  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.data.slice(this.off, this.off + n);
    this.off += n;
    return out;
  }

  /**
   * Compact-size varint. Rejects non-canonical encodings (a value that could
   * have been encoded in fewer bytes), matching dcrd's `ErrNonCanonicalVarInt`.
   * Without this check two distinct byte strings could parse to the same
   * transaction while hashing to different ids.
   */
  varInt(): number {
    const first = this.u8();
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const v = this.u16();
      if (v < 0xfd) throw new Error("varInt: non-canonical encoding");
      return v;
    }
    if (first === 0xfe) {
      const v = this.u32();
      if (v < 0x10000) throw new Error("varInt: non-canonical encoding");
      return v;
    }
    const big = this.u64();
    if (big < 0x100000000n) throw new Error("varInt: non-canonical encoding");
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("varInt: too large");
    return Number(big);
  }

  varBytes(): Uint8Array {
    return this.bytes(this.varInt());
  }
}
