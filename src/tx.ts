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
import { blake256 } from "./hash.js";
import { Reader, Writer } from "./bytes.js";

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
/** Sentinel "unknown" input amount / block position used for unsigned inputs. */
export const NULL_VALUE_IN = -1n;
export const NULL_BLOCK_HEIGHT = 0xffffffff;
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

/** A mutable Decred transaction. */
export class Transaction {
  version = DEFAULT_TX_VERSION;
  inputs: TxInput[] = [];
  outputs: TxOutput[] = [];
  lockTime = 0;
  expiry = 0;

  /** Add an input. Witness fields default to the "unsigned/unknown" sentinels. */
  addInput(
    previousOutPoint: OutPoint,
    opts: Partial<Omit<TxInput, "previousOutPoint">> = {},
  ): this {
    this.inputs.push({
      previousOutPoint,
      sequence: opts.sequence ?? MAX_SEQUENCE,
      valueIn: opts.valueIn ?? NULL_VALUE_IN,
      blockHeight: opts.blockHeight ?? NULL_BLOCK_HEIGHT,
      blockIndex: opts.blockIndex ?? NULL_BLOCK_INDEX,
      signatureScript: opts.signatureScript ?? new Uint8Array(0),
    });
    return this;
  }

  /** Add an output. */
  addOutput(value: bigint, pkScript: Uint8Array, version = 0): this {
    this.outputs.push({ value, version, pkScript });
    return this;
  }

  private writeVersion(w: Writer, serType: TxSerializeType): void {
    w.u32(((serType << 16) | (this.version & 0xffff)) >>> 0);
  }

  private writePrefixBody(w: Writer): void {
    w.varInt(this.inputs.length);
    for (const input of this.inputs) {
      const op = input.previousOutPoint;
      if (op.hash.length !== 32) throw new Error("tx: outpoint hash must be 32 bytes");
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
      throw new Error("tx: fromBytes expects the full serialization");
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
    if (numWit !== numIn) throw new Error("tx: witness/prefix input count mismatch");
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
    if (r.remaining !== 0) throw new Error("tx: trailing bytes after transaction");
    return tx;
  }
}

/** Build an OutPoint from a txid *string* (reverses to internal byte order). */
export function outPointFromTxid(txid: string, index: number, tree = TxTree.Regular): OutPoint {
  if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
    throw new Error("outPointFromTxid: txid must be 64 hex characters");
  }
  const display = new Uint8Array(32);
  for (let i = 0; i < 32; i++) display[i] = parseInt(txid.slice(i * 2, i * 2 + 2), 16);
  return { hash: reverse(display), index, tree };
}
