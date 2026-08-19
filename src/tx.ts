/**
 * The Decred transaction wire format (`MsgTx`).
 *
 * A Decred transaction is split into a **prefix** and a **witness**. The prefix
 * holds the non-malleable data (outpoints, outputs, locktime, expiry); the
 * witness holds the input amounts, the block height/index of the funding output
 * and the signature scripts. The transaction id is the BLAKE-256 of the prefix
 * only, which is what makes it stable under signing.
 *
 * The 32-bit version word packs the real version in its low 16 bits and a
 * serialization-type selector in its high 16 bits.
 */
import { err } from "./errors.js";
import { blake256 } from "./hash.js";
import { copyOf, Reader, Writer } from "./bytes.js";

/** Transaction serialization selectors (encoded in the version word). */
export enum TxSerializeType {
  Full = 0,
  NoWitness = 1,
  OnlyWitness = 2,
}

/** Output tree: regular spends vs. the stake tree. */
export enum TxTree {
  Regular = 0,
  Stake = 1,
}

export const DEFAULT_TX_VERSION = 1;
export const MAX_SEQUENCE = 0xffffffff;
/**
 * Sentinel "unknown" input amount / block position used for unsigned inputs,
 * matching dcrd's `wire.NullValueIn` / `NullBlockHeight` / `NullBlockIndex`.
 *
 * Note the asymmetry, which is dcrd's and not a typo here: the null block
 * *height* is `0` ("it references the genesis block") while the null block
 * *index* is `0xffffffff`.
 */
export const NULL_VALUE_IN = -1n;
export const NULL_BLOCK_HEIGHT = 0;
export const NULL_BLOCK_INDEX = 0xffffffff;

export interface OutPoint {
  /** 32-byte transaction hash in internal (serialized) byte order. */
  hash: Uint8Array;
  index: number;
  tree: number;
}

export interface TxInput {
  previousOutPoint: OutPoint;
  sequence: number;
  // Witness fields:
  valueIn: bigint;
  blockHeight: number;
  blockIndex: number;
  signatureScript: Uint8Array;
}

export interface TxOutput {
  value: bigint;
  version: number;
  pkScript: Uint8Array;
}

function reverse(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i]!;
  return out;
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Pack the 32-bit version word: serialization type in the high 16 bits, the
 * transaction version in the low 16. Shared with the signature hash, whose
 * serialization types are its own (see sighash.ts).
 *
 * The version is range-checked rather than only masked, for the reason
 * `checkUint` gives in bytes.ts: `& 0xffff` quietly turns 65537 into 1, -1 into
 * 65535 and `NaN` into 0, so the caller would get bytes — and a txid, and a
 * signature — for a version they never asked for. The other 16-bit field in this
 * serializer, `TxOutput.version`, already throws on exactly these inputs, since
 * `writePrefixBody` writes it with `Writer.u16`. dcrd cannot express the case at
 * all: `wire.MsgTx.Version` is a uint16, and the high half of this word is the
 * serialization type — which is also why the mask cannot simply be dropped, as an
 * out-of-range version would then corrupt the serialization type.
 */
export function packVersion(version: number, serType: number): number {
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
    throw err(
      Number.isInteger(version) ? "out-of-range" : "not-an-integer",
      "tx.version",
      `expected an integer in 0..2^16-1, got ${version}`,
    );
  }
  return ((serType << 16) | version) >>> 0;
}

/** A mutable Decred transaction. */
export class Transaction {
  version = DEFAULT_TX_VERSION;
  inputs: TxInput[] = [];
  outputs: TxOutput[] = [];
  lockTime = 0;
  expiry = 0;

  /**
   * Add an input. Witness fields default to the "unsigned/unknown" sentinels.
   *
   * The outpoint and signature script are copied, so a caller that reuses or
   * scrubs its own buffers afterwards cannot silently rewrite this transaction's
   * bytes — which would change its txid and invalidate every signature already
   * computed over it, with nothing to detect the change.
   */
  addInput(
    previousOutPoint: OutPoint,
    opts: Partial<Omit<TxInput, "previousOutPoint">> = {},
  ): this {
    if (previousOutPoint.hash.length !== 32) {
      throw err(
        "bad-length",
        "tx.addInput",
        `outpoint hash must be 32 bytes, got ${previousOutPoint.hash.length}`,
      );
    }
    // dcrd types Tree as int8 and defines TxTreeUnknown = -1, but only Regular (0)
    // and Stake (1) are consensus-valid, and the unsigned writer would otherwise
    // reject anything else with a message about bytes rather than about the tree.
    // Parsing stays permissive (fromBytes accepts any byte, as dcrd's decoder
    // does); this is the construction path.
    if (previousOutPoint.tree !== TxTree.Regular && previousOutPoint.tree !== TxTree.Stake) {
      throw err(
        "out-of-range",
        "tx.addInput",
        `outpoint tree must be ${TxTree.Regular} (regular) or ${TxTree.Stake} (stake), ` +
          `got ${previousOutPoint.tree}`,
      );
    }
    this.inputs.push({
      previousOutPoint: {
        hash: copyOf(previousOutPoint.hash, 0, 32),
        index: previousOutPoint.index,
        tree: previousOutPoint.tree,
      },
      sequence: opts.sequence ?? MAX_SEQUENCE,
      valueIn: opts.valueIn ?? NULL_VALUE_IN,
      blockHeight: opts.blockHeight ?? NULL_BLOCK_HEIGHT,
      blockIndex: opts.blockIndex ?? NULL_BLOCK_INDEX,
      signatureScript: opts.signatureScript
        ? copyOf(opts.signatureScript, 0, opts.signatureScript.length)
        : new Uint8Array(0),
    });
    return this;
  }

  /** Add an output. The script is copied; see {@link addInput}. */
  addOutput(value: bigint, pkScript: Uint8Array, version = 0): this {
    this.outputs.push({ value, version, pkScript: copyOf(pkScript, 0, pkScript.length) });
    return this;
  }

  private writeVersion(w: Writer, serType: TxSerializeType): void {
    w.u32(packVersion(this.version, serType));
  }

  private writePrefixBody(w: Writer): void {
    w.varInt(this.inputs.length);
    for (const input of this.inputs) {
      const op = input.previousOutPoint;
      if (op.hash.length !== 32) throw err("bad-length", "tx", `outpoint hash must be 32 bytes, got ${op.hash.length}`);
      w.bytes(op.hash).u32(op.index).u8(op.tree).u32(input.sequence);
    }
    w.varInt(this.outputs.length);
    for (const out of this.outputs) {
      w.i64(out.value).u16(out.version).varBytes(out.pkScript);
    }
    w.u32(this.lockTime).u32(this.expiry);
  }

  private writeWitnessBody(w: Writer): void {
    w.varInt(this.inputs.length);
    for (const input of this.inputs) {
      w.i64(input.valueIn)
        .u32(input.blockHeight)
        .u32(input.blockIndex)
        .varBytes(input.signatureScript);
    }
  }

  /** Serialize as prefix ‖ witness (the full form). */
  serialize(): Uint8Array {
    const w = new Writer();
    this.writeVersion(w, TxSerializeType.Full);
    this.writePrefixBody(w);
    this.writeWitnessBody(w);
    return w.finish();
  }

  /** Serialize the prefix only (no witness). This is what the txid hashes. */
  serializePrefix(): Uint8Array {
    const w = new Writer();
    this.writeVersion(w, TxSerializeType.NoWitness);
    this.writePrefixBody(w);
    return w.finish();
  }

  /** Serialize the witness only. */
  serializeWitness(): Uint8Array {
    const w = new Writer();
    this.writeVersion(w, TxSerializeType.OnlyWitness);
    this.writeWitnessBody(w);
    return w.finish();
  }

  /** Raw 32-byte prefix hash (internal byte order). */
  hash(): Uint8Array {
    return blake256(this.serializePrefix());
  }

  /** The transaction id (reversed-hex display form of the prefix hash). */
  txid(): string {
    return toHex(reverse(this.hash()));
  }

  /** The witness hash id (display form). */
  witnessTxid(): string {
    return toHex(reverse(blake256(this.serializeWitness())));
  }

  /** The full hash id: `blake256(prefixHash ‖ witnessHash)`, display form. */
  fullTxid(): string {
    const concat = new Uint8Array(64);
    concat.set(blake256(this.serializePrefix()), 0);
    concat.set(blake256(this.serializeWitness()), 32);
    return toHex(reverse(blake256(concat)));
  }

  /** Parse a full (prefix ‖ witness) serialization. */
  static fromBytes(bytes: Uint8Array): Transaction {
    const r = new Reader(bytes);
    const versionWord = r.u32();
    const serType = (versionWord >>> 16) as TxSerializeType;
    if (serType !== TxSerializeType.Full) {
      throw err("invalid-argument", "tx.fromBytes", `expects the full serialization, got serialization type ${serType}`);
    }
    const tx = new Transaction();
    tx.version = versionWord & 0xffff;

    // Prefix.
    const numIn = r.varInt();
    const prefixes: OutPoint[] = [];
    const sequences: number[] = [];
    for (let i = 0; i < numIn; i++) {
      const hash = r.bytes(32);
      const index = r.u32();
      const tree = r.u8();
      const sequence = r.u32();
      prefixes.push({ hash, index, tree });
      sequences.push(sequence);
    }
    const numOut = r.varInt();
    for (let i = 0; i < numOut; i++) {
      const value = r.i64();
      const version = r.u16();
      const pkScript = r.varBytes();
      tx.outputs.push({ value, version, pkScript });
    }
    tx.lockTime = r.u32();
    tx.expiry = r.u32();

    // Witness.
    const numWit = r.varInt();
    if (numWit !== numIn) throw err("bad-length", "tx.fromBytes", `witness declares ${numWit} inputs, prefix declares ${numIn}`);
    for (let i = 0; i < numIn; i++) {
      const valueIn = r.i64();
      const blockHeight = r.u32();
      const blockIndex = r.u32();
      const signatureScript = r.varBytes();
      tx.inputs.push({
        previousOutPoint: prefixes[i]!,
        sequence: sequences[i]!,
        valueIn,
        blockHeight,
        blockIndex,
        signatureScript,
      });
    }
    if (r.remaining !== 0) throw err("trailing-bytes", "tx.fromBytes", `${r.remaining} byte(s) remain after the transaction`);
    return tx;
  }
}

/** Build an OutPoint from a txid *string* (reverses to internal byte order). */
export function outPointFromTxid(txid: string, index: number, tree = TxTree.Regular): OutPoint {
  if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
    throw err("invalid-argument", "outPointFromTxid", "txid must be 64 hex characters");
  }
  const display = new Uint8Array(32);
  for (let i = 0; i < 32; i++) display[i] = parseInt(txid.slice(i * 2, i * 2 + 2), 16);
  return { hash: reverse(display), index, tree };
}
