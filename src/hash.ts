/**
 * Decred hashing helpers built on {@link blake256}.
 *
 * Decred replaced Bitcoin's double-SHA-256 with BLAKE-256 across the protocol:
 *
 * - `hash256` (double BLAKE-256) — the checksum used by base58check and the
 *   extended-key serialization.
 * - `hash160` — RIPEMD-160 of a single BLAKE-256, used for pubkey/script hashes
 *   in addresses.
 *
 * Single-BLAKE-256 (used directly for txids, block hashes and signature hashes)
 * is just {@link blake256}.
 */
import { ripemd160 } from "@noble/hashes/ripemd160";
import { blake256 } from "./blake256.js";

export { blake256, Blake256 } from "./blake256.js";

/** Double BLAKE-256: `blake256(blake256(data))`. */
export function hash256(data: Uint8Array): Uint8Array {
  return blake256(blake256(data));
}

/** RIPEMD-160 of BLAKE-256: `ripemd160(blake256(data))`. The address hash. */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(blake256(data));
}
