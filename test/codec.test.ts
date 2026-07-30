import { describe, expect, test } from "vitest";
import { Reader, Writer } from "../src/bytes.js";
import { bytesToHex, hexToBytes } from "./helpers.js";

/**
 * The `Writer`/`Reader` primitives had almost no direct coverage: the largest
 * thing the suite serialized was ~200 bytes, so the multi-byte varint forms and
 * the growth path never ran, and the fixed-width writers silently truncated
 * out-of-range input. The 64-bit paths now go through `DataView`, so their
 * boundary behaviour needs pinning independently of any transaction.
 */
describe("Writer fixed-width integers", () => {
  test("round-trip the full range at each width", () => {
    const w = new Writer();
    w.u8(0).u8(0xff).u16(0).u16(0xffff).u32(0).u32(0xffffffff);
    const r = new Reader(w.finish());
    expect([r.u8(), r.u8(), r.u16(), r.u16(), r.u32(), r.u32()]).toEqual([
      0, 0xff, 0, 0xffff, 0, 0xffffffff,
    ]);
  });

  test("little-endian byte order matches the wire format", () => {
    expect(bytesToHex(new Writer().u16(0x0201).finish())).toBe("0102");
    expect(bytesToHex(new Writer().u32(0x04030201).finish())).toBe("01020304");
    expect(bytesToHex(new Writer().u64(0x0807060504030201n).finish())).toBe("0102030405060708");
    expect(bytesToHex(new Writer().i64(-1n).finish())).toBe("ffffffffffffffff");
  });

  test("reject out-of-range values instead of truncating them", () => {
    // These used to be masked with `& 0xff` etc., quietly turning NaN into 0,
    // -1 into 255 and 2**32 into 0 — writing a field the caller never asked for.
    for (const bad of [-1, 256, 1.5, NaN, Infinity]) {
      expect(() => new Writer().u8(bad), `u8(${bad})`).toThrow(/expected an integer/);
    }
    for (const bad of [-1, 0x10000, 1.5, NaN]) {
      expect(() => new Writer().u16(bad), `u16(${bad})`).toThrow(/expected an integer/);
    }
    for (const bad of [-1, 0x100000000, 1.5, NaN]) {
      expect(() => new Writer().u32(bad), `u32(${bad})`).toThrow(/expected an integer/);
    }
    expect(() => new Writer().u64(-1n)).toThrow(/out of range/);
    expect(() => new Writer().u64(1n << 64n)).toThrow(/out of range/);
    expect(() => new Writer().i64(1n << 63n)).toThrow(/out of range/);
    expect(() => new Writer().i64(-(1n << 63n) - 1n)).toThrow(/out of range/);
  });

  test("64-bit boundaries survive the round-trip", () => {
    const cases: bigint[] = [
      0n,
      1n,
      0x7fffffffffffffffn, // max i64
      -(1n << 63n), // min i64
      -1n,
      (1n << 32n) - 1n,
      1n << 32n,
      21_000_000_00000000n, // MaxAmount in atoms
      -21_000_000_00000000n,
    ];
    for (const v of cases) {
      const r = new Reader(new Writer().i64(v).finish());
      expect(r.i64(), `i64 ${v}`).toBe(v);
    }
    for (const v of [0n, 1n, (1n << 64n) - 1n, 1n << 63n]) {
      const r = new Reader(new Writer().u64(v).finish());
      expect(r.u64(), `u64 ${v}`).toBe(v);
    }
  });
});

describe("Writer varints and growth", () => {
  test("each varint discriminant boundary round-trips", () => {
    // Nothing in the suite reached past the 1-byte form before.
    const cases: Array<[number, string]> = [
      [0, "00"],
      [0xfc, "fc"],
      [0xfd, "fdfd00"],
      [0xffff, "fdffff"],
      [0x10000, "fe00000100"],
      [0xffffffff, "feffffffff"],
      [0x100000000, "ff0000000001000000"],
    ];
    for (const [v, hex] of cases) {
      expect(bytesToHex(new Writer().varInt(v).finish()), `varInt(${v})`).toBe(hex);
      expect(new Reader(hexToBytes(hex)).varInt(), `read ${hex}`).toBe(v);
    }
    expect(() => new Writer().varInt(-1)).toThrow(/negative/);
  });

  test("grows past the initial buffer with the contents intact", () => {
    // The writer starts at 256 bytes and doubles; the growth path was never
    // executed, so check the payload rather than just the length.
    for (const n of [255, 256, 257, 1024, 100_000]) {
      const payload = new Uint8Array(n);
      for (let i = 0; i < n; i++) payload[i] = (i * 31 + 7) & 0xff;
      const out = new Writer().u32(0xdeadbeef).bytes(payload).u16(0xabcd).finish();
      expect(out.length, `n=${n}`).toBe(4 + n + 2);
      const r = new Reader(out);
      expect(r.u32()).toBe(0xdeadbeef);
      expect(bytesToHex(r.bytes(n)), `payload n=${n}`).toBe(bytesToHex(payload));
      expect(r.u16()).toBe(0xabcd);
      expect(r.remaining).toBe(0);
    }
  });

  test("varBytes round-trips across the varint boundary", () => {
    for (const n of [0, 1, 252, 253, 300]) {
      const payload = new Uint8Array(n).fill(0x5a);
      const r = new Reader(new Writer().varBytes(payload).finish());
      expect(bytesToHex(r.varBytes()), `n=${n}`).toBe(bytesToHex(payload));
    }
  });

  test("finish() is a snapshot, not a live view", () => {
    const w = new Writer().u32(1);
    const first = w.finish();
    w.u32(2);
    expect(first.length).toBe(4);
    expect(w.finish().length).toBe(8);
  });
});

describe("Reader bounds", () => {
  test("reading past the end throws rather than returning zeros", () => {
    for (const [hex, fn] of [
      ["", (r: Reader) => r.u8()],
      ["00", (r: Reader) => r.u16()],
      ["000000", (r: Reader) => r.u32()],
      ["00000000000000", (r: Reader) => r.u64()],
      ["00000000000000", (r: Reader) => r.i64()],
      ["02aa", (r: Reader) => r.varBytes()],
    ] as const) {
      expect(() => fn(new Reader(hexToBytes(hex))), hex).toThrow(/unexpected end/);
    }
  });

  test("offset and remaining track consumption", () => {
    const r = new Reader(hexToBytes("0102030405060708"));
    expect([r.offset, r.remaining]).toEqual([0, 8]);
    r.u32();
    expect([r.offset, r.remaining]).toEqual([4, 4]);
    r.bytes(4);
    expect([r.offset, r.remaining]).toEqual([8, 0]);
  });

  test("reads correctly from a subarray-backed input", () => {
    // The DataView must honour byteOffset, or a view into a larger buffer reads
    // from the wrong place.
    const backing = hexToBytes("ffffffff" + "0102030405060708" + "ffffffff");
    const view = backing.subarray(4, 12);
    expect(view.byteOffset).toBe(4);
    expect(new Reader(view).u64()).toBe(0x0807060504030201n);
    expect(new Reader(view).i64()).toBe(0x0807060504030201n);
  });
});
