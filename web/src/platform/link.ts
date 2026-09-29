import { fromBase64Url, toBase64Url } from '@/model/base64';
import { sameTag, scalarFrom, sessionKey, share, tag } from '@/model/cpace';
import { parseDeviceCert } from '@/model/device-cert';
import type { LinkCode } from '@/model/link-code';
import { userIdPreimage } from '@/model/statements';
import { idOf, verify } from './crypto';
import type { RootWrap } from './root-wrap';

/**
 * Adding a device (ADR 0004): the owner's device and the new browser run
 * CPace over a mailbox the server relays, keyed by the code the owner shows.
 *
 *   new   → owner   Ya
 *   owner → new     Yb ‖ Tb
 *   new   → owner   Ta ‖ box(offer: the new device key and name)
 *   owner → new     box(grant: the root's certificate for that key, and the
 *                   wrapped root)
 *
 * Each side checks the other's tag before sending anything that matters, so
 * a wrong code (or a server in the middle) learns nothing and gets one try.
 * The owner is asked before the root is opened to sign; the new browser
 * checks the certificate names its own key under the root it was given.
 */
export type Mailbox = {
  /** The server's id for this mailbox: CPace's session id. */
  id: Uint8Array;
  post(data: Uint8Array): void;
  /** The other side's next post; rejects once the mailbox is closed. */
  next(): Promise<Uint8Array>;
  close(): void;
};

/** What the new browser asks for. */
export type Offer = { devicePublic: Uint8Array; name: string };

/** What the owner's device grants: enough for the new browser to be the owner's device. */
export type Grant = {
  rootPublic: Uint8Array;
  user: string;
  cert: { statement: string; signature: Uint8Array };
  wraps: RootWrap[];
  /**
   * The directory key's 32 bytes (ADR 0032), trusted as the wraps are: only
   * the device that matched the code opens the box. Absent from an owner's
   * device older than this; the new browser then learns it when it next
   * opens the root.
   */
  directoryKey?: Uint8Array;
};

/** The code did not match on both sides, or a message was not what this protocol sends. */
export class LinkFailed extends Error {}

const encoder = new TextEncoder();
const CI = encoder.encode('tilder/link/v1');
const AD_NEW = encoder.encode('new');
const AD_OWNER = encoder.encode('owner');
const SHARE = 32;
const TAG = 64;
const IV = 12;

const cat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));
// The nameplate goes into the password string, so a code only works in its own mailbox.
const prs = (code: LinkCode) => encoder.encode(`${code.nameplate}-${code.secret}`);
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

async function boxKey(isk: Uint8Array, sid: Uint8Array, purpose: 'offer' | 'grant') {
  const ikm = await crypto.subtle.importKey('raw', isk as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: sid as BufferSource, info: encoder.encode(`tilder/link/v1/${purpose}`) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(key: CryptoKey, value: unknown): Promise<Uint8Array> {
  const iv = random(IV);
  const plain = encoder.encode(JSON.stringify(value));
  return cat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain)));
}

async function open(key: CryptoKey, box: Uint8Array): Promise<unknown> {
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: box.slice(0, IV) }, key, box.slice(IV));
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new LinkFailed('A message from the other device did not open.');
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

function offerFrom(v: unknown): Offer {
  if (!isRecord(v) || typeof v.devicePublic !== 'string' || typeof v.name !== 'string' || v.name.length > 100)
    throw new LinkFailed('The new device sent something else.');
  const devicePublic = fromBase64Url(v.devicePublic);
  if (devicePublic.length !== 32) throw new LinkFailed('The new device sent something else.');
  return { devicePublic, name: v.name };
}

const isWrap = (w: unknown): w is RootWrap =>
  isRecord(w) &&
  w.v === 1 &&
  (w.kind === 'recovery' || w.kind === 'prf') &&
  (w.credentialId === undefined || typeof w.credentialId === 'string') &&
  typeof w.salt === 'string' &&
  typeof w.iv === 'string' &&
  typeof w.ct === 'string';

/**
 * The grant, checked: the root's own signature on a certificate for this
 * browser's key, and the user that root makes. Nothing else is taken on the
 * owner's word.
 */
async function grantFrom(v: unknown, devicePublic: Uint8Array): Promise<Grant> {
  const refused = () => new LinkFailed('Your other device sent a certificate that is not for this browser.');
  if (!isRecord(v) || typeof v.rootPublic !== 'string' || !isRecord(v.cert) || !Array.isArray(v.wraps)) throw refused();
  const { statement, signature } = v.cert;
  if (typeof statement !== 'string' || typeof signature !== 'string' || !v.wraps.every(isWrap)) throw refused();
  const rootPublic = fromBase64Url(v.rootPublic);
  const cert = parseDeviceCert(statement);
  const user = rootPublic.length === 32 ? await idOf(userIdPreimage(rootPublic)) : '';
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
  if (!cert || cert.user !== user || !same(cert.root, rootPublic) || !same(cert.device, devicePublic)) throw refused();
  const sig = fromBase64Url(signature);
  if (!(await verify(rootPublic, statement, sig))) throw refused();
  // A key of any other length is not one: dropped, and learned later.
  const key = typeof v.directoryKey === 'string' ? fromBase64Url(v.directoryKey) : null;
  const directoryKey = key && key.length === 32 ? key : undefined;
  return {
    rootPublic,
    user,
    cert: { statement, signature: sig },
    wraps: v.wraps,
    ...(directoryKey ? { directoryKey } : {}),
  };
}

/**
 * Closes the mailbox when a side fails, so the other side hears it at once
 * instead of waiting out the mailbox.
 */
async function closingOnFailure<T>(mailbox: Mailbox, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    mailbox.close();
    throw error;
  }
}

/** The new browser's side. Resolves to the checked grant. */
export function linkAsNew(mailbox: Mailbox, code: LinkCode, offer: Offer): Promise<Grant> {
  return closingOnFailure(mailbox, () => runNew(mailbox, code, offer));
}

async function runNew(mailbox: Mailbox, code: LinkCode, offer: Offer): Promise<Grant> {
  const sid = mailbox.id;
  const y = scalarFrom(random(64));
  const Ya = share(prs(code), CI, sid, y);
  mailbox.post(Ya);

  const reply = await mailbox.next();
  if (reply.length !== SHARE + TAG) throw new LinkFailed('Your other device sent something else.');
  const Yb = reply.subarray(0, SHARE);
  const isk = sessionKey(y, sid, { Y: Ya, AD: AD_NEW }, { Y: Yb, AD: AD_OWNER }, Yb);
  if (!isk || !sameTag(tag(isk, sid, Yb, AD_OWNER), reply.subarray(SHARE)))
    throw new LinkFailed('The code did not match. Ask your other device for a new one.');

  const sealed = await seal(await boxKey(isk, sid, 'offer'), {
    devicePublic: toBase64Url(offer.devicePublic),
    name: offer.name,
  });
  mailbox.post(cat(tag(isk, sid, Ya, AD_NEW), sealed));
  const grant = await open(await boxKey(isk, sid, 'grant'), await mailbox.next());
  return grantFrom(grant, offer.devicePublic);
}

/**
 * The owner's side. `decide` sees the checked offer (the code matched) and
 * returns the grant, after asking the owner and opening the root; throwing
 * there refuses the device.
 */
export function linkAsOwner(
  mailbox: Mailbox,
  code: LinkCode,
  decide: (offer: Offer) => Promise<Grant>,
): Promise<Offer> {
  return closingOnFailure(mailbox, () => runOwner(mailbox, code, decide));
}

async function runOwner(mailbox: Mailbox, code: LinkCode, decide: (offer: Offer) => Promise<Grant>): Promise<Offer> {
  const sid = mailbox.id;
  const Ya = await mailbox.next();
  if (Ya.length !== SHARE) throw new LinkFailed('The new device sent something else.');
  const y = scalarFrom(random(64));
  const Yb = share(prs(code), CI, sid, y);
  const isk = sessionKey(y, sid, { Y: Ya, AD: AD_NEW }, { Y: Yb, AD: AD_OWNER }, Ya);
  if (!isk) throw new LinkFailed('The new device sent something else.');
  mailbox.post(cat(Yb, tag(isk, sid, Yb, AD_OWNER)));

  // The new browser checks the code first, and leaves when it is wrong.
  const confirm = await mailbox.next().catch(() => {
    throw new LinkFailed('The new browser stopped before the code matched: often a typo. Try a new code.');
  });
  if (confirm.length <= TAG || !sameTag(tag(isk, sid, Ya, AD_NEW), confirm.subarray(0, TAG)))
    throw new LinkFailed('The code did not match on the new device. Nothing was added.');
  const offer = offerFrom(await open(await boxKey(isk, sid, 'offer'), confirm.subarray(TAG)));

  const grant = await decide(offer);
  mailbox.post(
    await seal(await boxKey(isk, sid, 'grant'), {
      rootPublic: toBase64Url(grant.rootPublic),
      cert: { statement: grant.cert.statement, signature: toBase64Url(grant.cert.signature) },
      wraps: grant.wraps,
      ...(grant.directoryKey ? { directoryKey: toBase64Url(grant.directoryKey) } : {}),
    }),
  );
  grant.directoryKey?.fill(0);
  return offer;
}
