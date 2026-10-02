/**
 * The identity work the key signer does for the console (ADR 0048):
 * the root, its wraps, the certificate, the directory key all live in the
 * signer's origin; the console asks by name. Every argument is the
 * console's word, so each is checked for shape and size here, before any
 * of it reaches the identity code; a request out of shape is refused.
 */

/** How the owner opens the root: a passkey, or the recovery code (still typed into the console; ADR 0048 says what is left). */
export type UnlockArg = { passkey: true } | { recoveryCode: string };

type Signed = { statement: string; signature: Uint8Array };
/** A passkey the console just made (its id and PRF output), for the signer to wrap the root under. */
type MadePasskey = { credentialId: string; secret: Uint8Array };
type Wrap = { v: 1; kind: 'recovery' | 'prf'; credentialId?: string; salt: string; iv: string; ct: string };
type WrapBlob = { lookup: Uint8Array; blob: Uint8Array };

export type IdentityRequest =
  | { op: 'id-load' }
  | { op: 'id-prepare'; name: string; now: number }
  | { op: 'id-prepare-passkey'; token: string; made: MadePasskey }
  | { op: 'id-prepare-save'; token: string }
  | { op: 'id-unlock-methods' }
  | { op: 'id-renew'; how: UnlockArg; name: string; now: number }
  | { op: 'id-add-passkey'; how: UnlockArg; made: MadePasskey }
  | { op: 'id-passkey-ids' }
  | { op: 'id-register'; how: UnlockArg; machine: { id: string; publicKey: string }; now: number }
  | { op: 'id-revoke'; how: UnlockArg; current?: Signed; device: Uint8Array; now: number }
  | { op: 'id-grant'; how: UnlockArg; offer: { devicePublic: Uint8Array; name: string }; now: number }
  | { op: 'id-link-offer'; name: string }
  | {
      op: 'id-link-adopt';
      token: string;
      grant: { rootPublic: Uint8Array; user: string; cert: Signed; wraps: Wrap[]; directoryKey?: Uint8Array };
    }
  | { op: 'id-new-code'; how: UnlockArg }
  | { op: 'id-new-code-save'; token: string }
  | { op: 'id-finish-signin'; how: UnlockArg }
  | { op: 'id-forget' }
  | { op: 'id-learn-directory'; how: UnlockArg }
  | { op: 'id-directory-key' }
  | { op: 'id-recover'; how: UnlockArg; name: string; now: number }
  | { op: 'id-pending-wraps' }
  | { op: 'id-wraps-sent'; statement: string }
  | { op: 'id-keep-held'; held: { seq: number; blobs: WrapBlob[] } }
  | { op: 'id-new-device-signin' }
  | { op: 'id-import'; stored: Imported; pending: Pending | null };

/** A console's identity from before the signer held it (ADR 0048), handed over once. */
export type Imported = {
  v: 1;
  recoveryLookup?: string;
  wrapsSeq?: number;
  rootPublic: Uint8Array;
  user: string;
  name?: string;
  device: { publicKey: Uint8Array; privateKey?: CryptoKey };
  cert: Signed;
  wraps: Wrap[];
  directoryKey?: CryptoKey;
};
type Pending = Signed & { blobs: WrapBlob[] };

const MAX_STATEMENT = 16 * 1024;
const MAX_WRAPS = 16;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const B64 = /^[A-Za-z0-9_-]{1,512}$/;

type R = Record<string, unknown>;
const rec = (v: unknown): v is R => typeof v === 'object' && v !== null && !Array.isArray(v);
const bytes = (v: unknown, min: number, max: number): v is Uint8Array =>
  Object.prototype.toString.call(v) === '[object Uint8Array]' &&
  (v as Uint8Array).length >= min &&
  (v as Uint8Array).length <= max;
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max;
const cryptoKey = (v: unknown): v is CryptoKey => Object.prototype.toString.call(v) === '[object CryptoKey]';
const time = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const token = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{16,64}$/.test(v);

function made(v: unknown): MadePasskey | null {
  if (!rec(v) || !(typeof v.credentialId === 'string' && B64.test(v.credentialId))) return null;
  return bytes(v.secret, 32, 32) ? { credentialId: v.credentialId, secret: v.secret } : null;
}

function unlock(v: unknown): UnlockArg | null {
  if (!rec(v)) return null;
  if (v.passkey === true) return { passkey: true };
  return text(v.recoveryCode, 200) ? { recoveryCode: v.recoveryCode } : null;
}

function signed(v: unknown): Signed | null {
  return rec(v) && text(v.statement, MAX_STATEMENT) && bytes(v.signature, 64, 64)
    ? { statement: v.statement, signature: v.signature }
    : null;
}

function wrap(v: unknown): Wrap | null {
  if (!rec(v) || v.v !== 1 || (v.kind !== 'recovery' && v.kind !== 'prf')) return null;
  if (!text(v.salt, 512) || !text(v.iv, 512) || !text(v.ct, 1024)) return null;
  if (v.credentialId !== undefined && !(typeof v.credentialId === 'string' && B64.test(v.credentialId))) return null;
  return {
    v: 1,
    kind: v.kind,
    ...(typeof v.credentialId === 'string' ? { credentialId: v.credentialId } : {}),
    salt: v.salt,
    iv: v.iv,
    ct: v.ct,
  };
}

function blobs(v: unknown): WrapBlob[] | null {
  if (!Array.isArray(v) || v.length > MAX_WRAPS) return null;
  const out: WrapBlob[] = [];
  for (const b of v) {
    if (!rec(b) || !bytes(b.lookup, 16, 64) || !bytes(b.blob, 1, 8192)) return null;
    out.push({ lookup: b.lookup, blob: b.blob });
  }
  return out;
}

function wraps(v: unknown): Wrap[] | null {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_WRAPS) return null;
  const out = v.map(wrap);
  return out.some((w) => w === null) ? null : (out as Wrap[]);
}

function imported(v: unknown): Imported | null {
  if (!rec(v) || v.v !== 1 || !bytes(v.rootPublic, 32, 32) || !(typeof v.user === 'string' && ID.test(v.user)))
    return null;
  const d = v.device;
  if (!rec(d) || !bytes(d.publicKey, 32, 32) || (d.privateKey !== undefined && !cryptoKey(d.privateKey))) return null;
  const cert = signed(v.cert);
  const w = wraps(v.wraps);
  if (!cert || !w) return null;
  if (v.name !== undefined && !text(v.name, 100)) return null;
  if (v.recoveryLookup !== undefined && !(typeof v.recoveryLookup === 'string' && B64.test(v.recoveryLookup)))
    return null;
  if (v.wrapsSeq !== undefined && !(typeof v.wrapsSeq === 'number' && Number.isSafeInteger(v.wrapsSeq))) return null;
  if (v.directoryKey !== undefined && !cryptoKey(v.directoryKey)) return null;
  return {
    v: 1,
    rootPublic: v.rootPublic,
    user: v.user,
    device: { publicKey: d.publicKey, ...(d.privateKey ? { privateKey: d.privateKey as CryptoKey } : {}) },
    cert,
    wraps: w,
    ...(v.name !== undefined ? { name: v.name as string } : {}),
    ...(v.recoveryLookup !== undefined ? { recoveryLookup: v.recoveryLookup as string } : {}),
    ...(v.wrapsSeq !== undefined ? { wrapsSeq: v.wrapsSeq as number } : {}),
    ...(v.directoryKey ? { directoryKey: v.directoryKey as CryptoKey } : {}),
  };
}

function pending(v: unknown): Pending | null {
  const s = signed(v);
  const b = rec(v) ? blobs(v.blobs) : null;
  return s && b ? { ...s, blobs: b } : null;
}

/** The identity request `r` is, in its shape; null when it is not one. */
export function parseIdentityRequest(r: R): IdentityRequest | null {
  switch (r.op) {
    case 'id-load':
    case 'id-unlock-methods':
    case 'id-forget':
    case 'id-directory-key':
    case 'id-pending-wraps':
    case 'id-new-device-signin':
      return { op: r.op };
    case 'id-prepare':
    case 'id-recover': {
      if (!text(r.name, 100) || !time(r.now)) return null;
      if (r.op === 'id-prepare') return { op: r.op, name: r.name, now: r.now };
      const how = unlock(r.how);
      return how ? { op: r.op, how, name: r.name, now: r.now } : null;
    }
    case 'id-prepare-passkey': {
      const m = made(r.made);
      return token(r.token) && m ? { op: r.op, token: r.token, made: m } : null;
    }
    case 'id-add-passkey': {
      const how = unlock(r.how);
      const m = made(r.made);
      return how && m ? { op: r.op, how, made: m } : null;
    }
    case 'id-passkey-ids':
      return { op: r.op };
    case 'id-prepare-save':
    case 'id-new-code-save':
      return token(r.token) ? { op: r.op, token: r.token } : null;
    case 'id-renew': {
      const how = unlock(r.how);
      return how && text(r.name, 100) && time(r.now) ? { op: r.op, how, name: r.name, now: r.now } : null;
    }
    case 'id-new-code':
    case 'id-finish-signin':
    case 'id-learn-directory': {
      const how = unlock(r.how);
      return how ? { op: r.op, how } : null;
    }
    case 'id-register': {
      const how = unlock(r.how);
      const m = r.machine;
      if (!how || !time(r.now) || !rec(m) || !(typeof m.id === 'string' && ID.test(m.id))) return null;
      if (!(typeof m.publicKey === 'string' && B64.test(m.publicKey))) return null;
      return { op: r.op, how, machine: { id: m.id, publicKey: m.publicKey }, now: r.now };
    }
    case 'id-revoke': {
      const how = unlock(r.how);
      if (!how || !time(r.now) || !bytes(r.device, 32, 32)) return null;
      if (r.current === undefined) return { op: r.op, how, device: r.device, now: r.now };
      const current = signed(r.current);
      return current ? { op: r.op, how, current, device: r.device, now: r.now } : null;
    }
    case 'id-grant': {
      const how = unlock(r.how);
      const o = r.offer;
      if (!how || !time(r.now) || !rec(o) || !bytes(o.devicePublic, 32, 32) || !text(o.name, 100)) return null;
      return { op: r.op, how, offer: { devicePublic: o.devicePublic, name: o.name }, now: r.now };
    }
    case 'id-link-offer':
      return text(r.name, 100) ? { op: r.op, name: r.name } : null;
    case 'id-link-adopt': {
      const g = r.grant;
      if (
        !token(r.token) ||
        !rec(g) ||
        !bytes(g.rootPublic, 32, 32) ||
        !(typeof g.user === 'string' && ID.test(g.user))
      )
        return null;
      const cert = signed(g.cert);
      const w = wraps(g.wraps);
      if (!cert || !w) return null;
      if (g.directoryKey !== undefined && !bytes(g.directoryKey, 32, 32)) return null;
      return {
        op: r.op,
        token: r.token,
        grant: {
          rootPublic: g.rootPublic,
          user: g.user,
          cert,
          wraps: w,
          ...(g.directoryKey ? { directoryKey: g.directoryKey as Uint8Array } : {}),
        },
      };
    }
    case 'id-wraps-sent':
      return text(r.statement, MAX_STATEMENT) ? { op: r.op, statement: r.statement } : null;
    case 'id-keep-held': {
      const h = r.held;
      if (!rec(h) || !(typeof h.seq === 'number' && Number.isSafeInteger(h.seq) && h.seq >= 0)) return null;
      const b = blobs(h.blobs);
      return b ? { op: r.op, held: { seq: h.seq, blobs: b } } : null;
    }
    case 'id-import': {
      const stored = imported(r.stored);
      if (!stored) return null;
      if (r.pending === null) return { op: r.op, stored, pending: null };
      const p = pending(r.pending);
      return p ? { op: r.op, stored, pending: p } : null;
    }
    default:
      return null;
  }
}
