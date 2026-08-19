/**
 * Little-endian byte reader/writer with Bitcoin/Decred "compact size" varints.
 *
 * All multi-byte integers in the Decred wire format are little-endian. Amounts
 * and a few counters are 64-bit, so those cross through `bigint`.
 */
import { err } from "./errors.js";

/**
 * Copy `n` bytes out of `src` starting at `off`, always into a fresh buffer.
 *
 * Deliberately not `src.slice(off, off + n)`. `Uint8Array.prototype.slice`
 * copies, but Node's `Buffer` overrides it to return a *view* over the same
 * memory (deprecated, still the behaviour). Since `Buffer` is what
 * `fs.readFileSync`, `Buffer.from(hex, "hex")`, sockets and database drivers all
 * hand back, a `slice()` here would silently alias the caller's memory for the
 * most common input type: reusing or zeroing that buffer afterwards would mutate
 * an already-parsed transaction or key.
 */
export function copyOf(src: Uint8Array, off: number, n: number): Uint8Array {
  // Validated because this is exported: `subarray` clamps, so an out-of-range
  // read would silently return a short-then-zero-padded buffer rather than fail,
  // and a negative offset would read from the wrong place.
  if (!Number.isInteger(off) || !Number.isInteger(n) || off < 0 || n < 0) {
    throw err(
      "not-an-integer",
      "copyOf",
      `offset and length must be non-negative integers, got ${off}, ${n}`,
    );
  }
  if (off + n > src.length) {
    throw err(
      "out-of-range",
      "copyOf",
      `reading ${n} bytes at ${off} overruns a ${src.length}-byte source`,
    );
  }
  const out = new Uint8Array(n);
  out.set(src.subarray(off, off + n));
  return out;
}

/** Reject a value that would be silently truncated by a fixed-width write. */
function checkUint(v: number, bits: number, who: string): void {
  // Without this, `v & 0xff` quietly turns NaN into 0, -1 into 255 and 2**32
  // into 0 — writing a wire field the caller never asked for.
  if (!Number.isInteger(v) || v < 0 || v > (bits === 32 ? 0xffffffff : (1 << bits) - 1)) {
    throw err(
      Number.isInteger(v) ? "out-of-range" : "not-an-integer",
      `Writer.${who}`,
      `expected an integer in 0..2^${bits}-1, got ${v}`,
    );
  }
}

/** Growable little-endian byte writer. */
export class Writer {
  private buf = new Uint8Array(256);
  private view = new DataView(this.buf.buffer);
  private len = 0;

  private ensure(extra: number): void {
    if (this.len + extra <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.len + extra) cap *= 2;
    const next = new Uint8Array(cap);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
    this.view = new DataView(next.buffer);
  }

  u8(v: number): this {
    checkUint(v, 8, "u8");
    this.ensure(1);
    this.buf[this.len++] = v;
    return this;
  }

  u16(v: number): this {
    checkUint(v, 16, "u16");
    this.ensure(2);
    this.view.setUint16(this.len, v, true);
    this.len += 2;
    return this;
  }

  u32(v: number): this {
    checkUint(v, 32, "u32");
    this.ensure(4);
    this.view.setUint32(this.len, v, true);
    this.len += 4;
    return this;
  }

  // The 64-bit paths go through DataView rather than eight BigInt shift/mask
  // steps. Every input amount and output value in a transaction crosses one of
  // these, and the loop version measured ~33x slower on the primitive.
  u64(v: bigint): this {
    if (v < 0n || v > 0xffffffffffffffffn) throw err("out-of-range", "Writer.u64", "value must fit in an unsigned 64-bit integer");
    this.ensure(8);
    this.view.setBigUint64(this.len, v, true);
    this.len += 8;
    return this;
  }

  /** Signed 64-bit little-endian (two's complement). Used for atom amounts. */
  i64(v: bigint): this {
    if (v < -(1n << 63n) || v >= 1n << 63n) throw err("out-of-range", "Writer.i64", "value must fit in a signed 64-bit integer");
    this.ensure(8);
    this.view.setBigInt64(this.len, v, true);
    this.len += 8;
    return this;
  }

  bytes(b: Uint8Array): this {
    this.ensure(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
    return this;
  }

  /** Compact-size varint. */
  varInt(v: number | bigint): this {
    // Checked before the conversion, not after: `BigInt(1.5)`, `BigInt(NaN)` and
    // `BigInt(Infinity)` throw a bare `RangeError` from the engine, which would
    // escape the typed-error contract every other path in this class honours.
    if (typeof v === "number" && !Number.isInteger(v)) {
      throw err("not-an-integer", "Writer.varInt", `expected an integer, got ${v}`);
    }
    const n = typeof v === "bigint" ? v : BigInt(v);
    if (n < 0n) throw err("out-of-range", "Writer.varInt", "value must not be negative");
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
  private readonly view: DataView;
  constructor(private readonly data: Uint8Array) {
    // Honour byteOffset/byteLength so a subarray-backed input reads correctly.
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  get offset(): number {
    return this.off;
  }

  get remaining(): number {
    return this.data.length - this.off;
  }

  private need(n: number): void {
    if (this.off + n > this.data.length) throw err("unexpected-end", "Reader", `wanted ${n} more byte(s), ${this.data.length - this.off} remain`);
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
    const v = this.view.getBigUint64(this.off, true);
    this.off += 8;
    return v;
  }

  /** Signed 64-bit little-endian (two's complement). */
  i64(): bigint {
    this.need(8);
    const v = this.view.getBigInt64(this.off, true);
    this.off += 8;
    return v;
  }

  bytes(n: number): Uint8Array {
    // A negative or fractional length would slip past `need` (which only checks
    // the upper bound), read nothing, and then rewind the offset.
    if (!Number.isInteger(n) || n < 0) throw err(Number.isInteger(n) ? "out-of-range" : "not-an-integer", "Reader.bytes", `bad length ${n}`);
    this.need(n);
    const out = copyOf(this.data, this.off, n);
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
      if (v < 0xfd) throw err("non-canonical-varint", "Reader.varInt", "value could have been encoded in fewer bytes");
      return v;
    }
    if (first === 0xfe) {
      const v = this.u32();
      if (v < 0x10000) throw err("non-canonical-varint", "Reader.varInt", "value could have been encoded in fewer bytes");
      return v;
    }
    const big = this.u64();
    if (big < 0x100000000n) throw err("non-canonical-varint", "Reader.varInt", "value could have been encoded in fewer bytes");
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw err("out-of-range", "Reader.varInt", "value exceeds Number.MAX_SAFE_INTEGER");
    return Number(big);
  }

  varBytes(): Uint8Array {
    return this.bytes(this.varInt());
  }
}
