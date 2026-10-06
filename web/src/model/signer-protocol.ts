import type { RegistrationIntent } from './owner';
import { type IdentityRequest, parseIdentityRequest } from './signer-identity-ops';

/**
 * The console and its key signer talk over one MessageChannel (ADR 0048):
 * the signer lives on its own origin (keys.tilder.run), holds the device key,
 * and does only what an operation below names. The console sends intents,
 * never bytes to sign: the signer builds each statement. Anything else, or
 * anything out of shape, is refused.
 */
export const SIGNER_PROTOCOL = 1;

/** The first message: the signer, loaded in the console's iframe, is ready for a port. */
export const SIGNER_READY = 'tilder-signer/ready';
/** The console's answer: here is the port (in the event's ports). */
export const SIGNER_CONNECT = 'tilder-signer/connect';

type Transfer = {
  user: string;
  src: string;
  srcPath: Uint8Array;
  dst: string;
  dstPath: Uint8Array;
  notAfter: number;
  nonce: Uint8Array;
};

type DeviceRequest =
  | { id: number; op: 'version' }
  | { id: number; op: 'create' }
  | { id: number; op: 'public-key' }
  | { id: number; op: 'forget' }
  | { id: number; op: 'policy' }
  | { id: number; op: 'sign-hello'; nonce: Uint8Array }
  | { id: number; op: 'sign-offer'; machineId: string; sessionId: Uint8Array; offerDigest: Uint8Array }
  | { id: number; op: 'sign-transfer'; t: Transfer }
  | { id: number; op: 'sign-registration'; r: RegistrationIntent };

export type SignerReply =
  | { id: number; ok: true; value: unknown }
  /** `shown`: the message was written for the owner (ShownError); an older console ignores it. */
  | { id: number; ok: false; error: string; machines?: string[]; message?: string; shown?: boolean };

/**
 * The signer asking the console for something only the console can reach
 * (the server): a wrapped root under a lookup key, for a recovery.
 */
export type SignerCallback = { cb: number; op: 'fetch-blob'; lookup: Uint8Array };
export type ConsoleAnswer = { cb: number; blob: Uint8Array | null };

/** How long the owner's "allow on this machine" lasts in one browser (ADR 0048, the owner's call). */
export const APPROVAL_MS = 12 * 3600 * 1000;

/** A machine id as the protocol carries it. */
export const isMachineId = (v: unknown): v is string => typeof v === 'string' && ID.test(v);

// What a well-formed request carries (the console's own shapes, statements.ts):
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_PATH = 4096;

// Checked by tag, not instanceof: bytes cloned across a MessagePort may come
// from another realm, whose Uint8Array is another constructor.
const bytes = (v: unknown, min: number, max: number): v is Uint8Array =>
  Object.prototype.toString.call(v) === '[object Uint8Array]' &&
  (v as Uint8Array).length >= min &&
  (v as Uint8Array).length <= max;
const id = (v: unknown): v is string => typeof v === 'string' && ID.test(v);

function registration(v: unknown): RegistrationIntent | null {
  if (typeof v !== 'object' || v === null) return null;
  const g = v as Record<string, unknown>;
  if (!id(g.user) || !id(g.machineId) || !bytes(g.machineKey, 32, 32)) return null;
  if (!bytes(g.auth, 16, 16) || !bytes(g.proof, 32, 32)) return null;
  if (typeof g.at !== 'number' || !Number.isSafeInteger(g.at) || g.at < 0) return null;
  return { user: g.user, machineId: g.machineId, machineKey: g.machineKey, at: g.at, auth: g.auth, proof: g.proof };
}

function transfer(v: unknown): Transfer | null {
  if (typeof v !== 'object' || v === null) return null;
  const t = v as Record<string, unknown>;
  if (!id(t.user) || !id(t.src) || !id(t.dst)) return null;
  if (!bytes(t.srcPath, 1, MAX_PATH) || !bytes(t.dstPath, 1, MAX_PATH) || !bytes(t.nonce, 16, 16)) return null;
  if (typeof t.notAfter !== 'number' || !Number.isSafeInteger(t.notAfter) || t.notAfter <= 0) return null;
  return {
    user: t.user,
    src: t.src,
    srcPath: t.srcPath,
    dst: t.dst,
    dstPath: t.dstPath,
    notAfter: t.notAfter,
    nonce: t.nonce,
  };
}

type SignerRequest = DeviceRequest | ({ id: number } & IdentityRequest);

/** The request `data` is, when it is one this protocol knows in its shape; anything else is refused unread. */
export function parseRequest(data: unknown): SignerRequest | null {
  if (typeof data !== 'object' || data === null) return null;
  const r = data as Record<string, unknown>;
  const rid = r.id;
  if (typeof rid !== 'number' || !Number.isSafeInteger(rid) || rid < 0) return null;
  if (typeof r.op === 'string' && r.op.startsWith('id-')) {
    const identity = parseIdentityRequest(r);
    return identity ? { id: rid, ...identity } : null;
  }
  switch (r.op) {
    case 'version':
    case 'create':
    case 'public-key':
    case 'forget':
    case 'policy':
      return { id: rid, op: r.op };
    case 'sign-hello':
      return bytes(r.nonce, 16, 64) ? { id: rid, op: 'sign-hello', nonce: r.nonce } : null;
    case 'sign-offer':
      return id(r.machineId) && bytes(r.sessionId, 16, 16) && bytes(r.offerDigest, 32, 32)
        ? { id: rid, op: 'sign-offer', machineId: r.machineId, sessionId: r.sessionId, offerDigest: r.offerDigest }
        : null;
    case 'sign-transfer': {
      const t = transfer(r.t);
      return t ? { id: rid, op: 'sign-transfer', t } : null;
    }
    case 'sign-registration': {
      const g = registration(r.r);
      return g ? { id: rid, op: 'sign-registration', r: g } : null;
    }
    default:
      return null;
  }
}
