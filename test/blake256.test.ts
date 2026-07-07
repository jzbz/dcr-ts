import { describe, expect, test } from "vitest";
import { blake256 as nobleBlake256 } from "@noble/hashes/blake1";
import { blake256, Blake256, hash256, hash160 } from "../src/hash.js";
import { bytesToHex, hexToBytes, vectors } from "./helpers.js";

describe("blake256", () => {
  test("canonical empty-string vector", () => {
    // The published BLAKE-256 known-answer value for the empty message.
    expect(bytesToHex(blake256(new Uint8Array()))).toBe(
      "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
    );
  });

  test("matches dcrd for every hash vector", () => {
    for (const v of vectors.hashes) {
      const input = hexToBytes(v.input);
      expect(bytesToHex(blake256(input)), `blake256(${v.input})`).toBe(v.blake256);
      expect(bytesToHex(hash256(input)), `hash256(${v.input})`).toBe(v.blake256d);
      expect(bytesToHex(hash160(input)), `hash160(${v.input})`).toBe(v.hash160);
    }
  });

  test("single-blake matches dcrd chainhash", () => {
    expect(bytesToHex(blake256(new TextEncoder().encode("abc")))).toBe(
      vectors.sanity.chainhash_abc,
    );
  });

  test("streaming update in chunks equals one-shot", () => {
    // Exercise every remainder length across block boundaries (0..200 bytes).
    for (let len = 0; len <= 200; len++) {
      const msg = new Uint8Array(len);
      for (let i = 0; i < len; i++) msg[i] = (i * 7 + 3) & 0xff;
      const oneShot = blake256(msg);

      // Feed one byte at a time.
      const h = new Blake256();
      for (let i = 0; i < len; i++) h.update(msg.subarray(i, i + 1));
      expect(bytesToHex(h.digest()), `1-byte chunks len=${len}`).toBe(bytesToHex(oneShot));

      // Feed in irregular chunks that straddle the 64-byte boundary.
      const h2 = new Blake256();
      let o = 0;
      for (const step of [1, 63, 64, 65, 13, 50]) {
        if (o >= len) break;
        h2.update(msg.subarray(o, Math.min(o + step, len)));
        o = Math.min(o + step, len);
      }
      if (o < len) h2.update(msg.subarray(o));
      expect(bytesToHex(h2.digest()), `irregular chunks len=${len}`).toBe(bytesToHex(oneShot));
    }
  });

  test("differential: agrees with @noble/hashes blake1 for lengths 0..300", () => {
    // An independent, audited BLAKE-256 implementation. Covers every padding
    // path: one-block (rem <= 55), the 0x81 merge (rem == 55), two-block
    // (rem 56..63) and the nullt final block (rem == 0, non-empty message).
    for (let len = 0; len <= 300; len++) {
      const msg = new Uint8Array(len);
      for (let i = 0; i < len; i++) msg[i] = (i * 31 + len) & 0xff;
      expect(bytesToHex(blake256(msg)), `len=${len}`).toBe(bytesToHex(nobleBlake256(msg)));
    }
  });

  test("rejects reuse after digest", () => {
    const h = new Blake256();
    h.update(new Uint8Array([1, 2, 3]));
    h.digest();
    expect(() => h.update(new Uint8Array([4]))).toThrow();
    expect(() => h.digest()).toThrow();
  });
});
