import { ed25519, ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';

/**
 * CPace, CPACE-RISTR255-SHA512 as draft-irtf-cfrg-cpace-21 defines it (ADR
 * 0004): a balanced PAKE, so two of the owner's browsers holding the same
 * short code get the same key and a guesser gets one try. Written on
 * @noble/curves (audited) rather than a young library; tests hold it to the
 * draft's vectors. Randomness comes in from the caller, so this stays pure.
 */
const encoder = new TextEncoder();
const DSI = encoder.encode('CPaceRistretto255');
const ISK_DSI = encoder.encode('CPaceRistretto255_ISK');
const MAC_DSI = encoder.encode('CPaceMac');
const S_IN_BYTES = 128; // SHA-512's block size
const ORDER = ed25519.Point.Fn.ORDER;

const leb128 = (n: number) => {
  const out: number[] = [];
  let v = n;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
};
/** lv_cat: each part prefixed with its LEB128 length. */
const lv = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...leb128(p.length), ...p]));
const cat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));

function generator(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array) {
  const prefix = leb128(prs.length).length + prs.length + leb128(DSI.length).length + DSI.length + 1;
  const zpad = new Uint8Array(Math.max(S_IN_BYTES - prefix, 0));
  const derive = ristretto255_hasher.deriveToCurve;
  if (!derive) throw new Error('cpace: this @noble/curves has no ristretto255 one-way map');
  return derive(sha512(lv(DSI, prs, zpad, ci, sid)));
}

/** A scalar from 64 random bytes, reduced mod the group order; never 0. */
export function scalarFrom(random: Uint8Array): bigint {
  if (random.length !== 64) throw new Error('cpace: a scalar needs 64 random bytes');
  let n = 0n;
  for (let i = random.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(random[i] ?? 0);
  const s = n % ORDER;
  if (s === 0n) throw new Error('cpace: zero scalar');
  return s;
}

/** Y = g·y for this code (PRS), channel (CI) and session (sid). */
export function share(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array, y: bigint): Uint8Array {
  return generator(prs, ci, sid).multiply(y).toBytes();
}

/**
 * The intermediate session key from y and the peer's Y, initiator's share
 * first, or null when the peer's share is not a valid point or gives the
 * identity (a peer sending the identity would force a known key).
 */
export function sessionKey(
  y: bigint,
  sid: Uint8Array,
  initiator: { Y: Uint8Array; AD: Uint8Array },
  responder: { Y: Uint8Array; AD: Uint8Array },
  peerY: Uint8Array,
): Uint8Array | null {
  let K: Uint8Array;
  try {
    const point = ristretto255.Point.fromBytes(peerY).multiply(y);
    if (point.equals(ristretto255.Point.ZERO)) return null;
    K = point.toBytes();
  } catch {
    return null;
  }
  return sha512(cat(lv(ISK_DSI, sid, K), lv(initiator.Y, initiator.AD), lv(responder.Y, responder.AD)));
}

/**
 * A confirmation tag over one side's share: without checking the peer's,
 * a wrong code gives a different key, not an error.
 */
export function tag(isk: Uint8Array, sid: Uint8Array, Y: Uint8Array, AD: Uint8Array): Uint8Array {
  const key = sha512(cat(MAC_DSI, sid, isk));
  return hmac(sha512, key, lv(Y, AD));
}

/** Constant-time equality for tags. */
export function sameTag(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
