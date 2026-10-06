import { fromBase64Url, toBase64Url } from '@/model/base64';
import { deviceCertStatement, deviceNamePreimage } from '@/model/device-cert';
import type { Identity } from '@/model/owner';
import { ShownError } from '@/model/problem';
import {
  type HeldWraps,
  mergeWraps,
  newDeviceReadiness,
  prfLookupPreimage,
  recoveryLookupPreimage,
  rootWrapsStatement,
  type WrapBlob,
} from '@/model/root-wraps';
import { sha256, sign } from './crypto';
import type { DeviceKeys } from './device-keys';
import { directoryKeyFrom } from './directory-key';
import type { KeyValue } from './kv';
import { type PasskeyUnlock, unlockWithPasskey } from './passkey';
import { type RootWrap, recoverySecret, unwrapRoot } from './root-wrap';

/**
 * What this browser keeps of the owner (ADR 0004, ADR 0021), and the steps
 * every identity action shares: opening the root, certifying a device,
 * queueing the root's wraps for the server.
 */
export const KEY = 'identity';
export const CERT_LIFETIME_S = 90 * 24 * 3600;
export const BACKDATE_S = 5 * 60; // absorbs a verifier's clock running behind

export type Stored = {
  v: 1;
  /** Where the server finds the recovery code's blob (ADR 0021); absent on identities made before. */
  recoveryLookup?: string;
  /** The seq of the last list of wraps signed here; the next is always greater. */
  wrapsSeq?: number;
  rootPublic: Uint8Array;
  user: string;
  /** Absent on identities made before names were kept. */
  name?: string;
  /** This browser's device key: its public half; the key signer holds the private one (ADR 0048). */
  device: { publicKey: Uint8Array };
  cert: { statement: string; signature: Uint8Array };
  wraps: RootWrap[];
  /**
   * Seals the owner's directory (ADR 0032), never exportable. Absent on a
   * device from before, until the root is next opened here.
   */
  directoryKey?: CryptoKey;
};

export const identityOf = (s: Stored, keys: DeviceKeys): Identity => ({
  rootPublic: s.rootPublic,
  user: s.user,
  name: s.name ?? thisDeviceName(),
  devicePublic: s.device.publicKey,
  cert: s.cert,
  signHello: (nonce) => keys.signHello(nonce),
  signOffer: (machineId, sessionId, offerDigest) => keys.signOffer(machineId, sessionId, offerDigest),
  signTransfer: (t) => keys.signTransfer(t),
  signRegistration: (r) => keys.signRegistration(r),
});

/**
 * How the owner opens the root for an admin action. `codeField`: the code
 * was typed into the key signer's own field (ADR 0054), which only the
 * signer reads; the console names the field.
 */
export type Unlock = { passkey: true } | { recoveryCode: string } | { codeField: string };

/** Its messages are written for the owner: shown as they are. */
export class UnlockFailed extends ShownError {}

/**
 * Changes the stored identity from its newest copy (ADR 0042): under the
 * browser's lock for it (Web Locks, as coder's console uses them), read
 * afresh, change, written. A copy read before a passkey or code prompt,
 * written back whole after it, put back what another tab changed meanwhile:
 * a new recovery code, a passkey. No lock is held across a prompt.
 */
export async function updateStored(kv: KeyValue, change: (current: Stored) => Stored): Promise<Stored> {
  const run = async () => {
    const current = await kv.get<Stored>(KEY);
    if (!current) throw new UnlockFailed('This browser has no identity yet.');
    const next = change(current);
    await kv.set(KEY, next);
    return next;
  };
  const locks = typeof navigator === 'undefined' ? undefined : navigator.locks;
  return locks ? locks.request('tilder-identity', run) : run();
}

/**
 * Opens the root for one admin action and forgets it afterwards (ADR 0004):
 * it lives only in this call, as a key WebCrypto will not export, unless
 * `extractable` asks for it to be wrapped again.
 */
export async function openRoot(kv: KeyValue, stored: Stored, how: Unlock, extractable = false): Promise<CryptoKey> {
  let secret: Uint8Array | null;
  let wrap: RootWrap | undefined;
  if ('passkey' in how) {
    const ids = stored.wraps.flatMap((w) => (w.kind === 'prf' && w.credentialId ? [w.credentialId] : []));
    const got: PasskeyUnlock = await unlockWithPasskey(ids);
    secret = got.secret;
    wrap = stored.wraps.find((w) => w.kind === 'prf' && w.credentialId === got.credentialId);
  } else if ('codeField' in how) {
    // The signer swaps the field for what was typed before this runs; here
    // there is no field to read.
    throw new UnlockFailed('Type your recovery code.');
  } else {
    secret = await recoverySecret(how.recoveryCode);
    wrap = stored.wraps.find((w) => w.kind === 'recovery');
    if (!secret) throw new UnlockFailed('That is not a recovery code: check it for typos.');
  }
  const root = wrap ? await unwrapRoot(wrap, secret, stored.user, stored.rootPublic, extractable) : null;
  // A device from before the directory learns its key now, the first time
  // the root is open here: a second, extractable copy, gone once derived.
  let learnKey = false;
  if (root && wrap && !stored.directoryKey) {
    const copy = await unwrapRoot(wrap, secret, stored.user, stored.rootPublic, true);
    if (copy) {
      stored.directoryKey = await directoryKeyFrom(copy);
      learnKey = true;
    }
  }
  // An identity made before the server kept wraps learns its recovery code's
  // lookup key now, the only time the code is at hand, and sends its wraps.
  const learn = root && 'recoveryCode' in how && !stored.recoveryLookup;
  if (learn) stored.recoveryLookup = toBase64Url(await sha256(recoveryLookupPreimage(secret)));
  secret.fill(0);
  if (!root) throw new UnlockFailed('That does not open this account.');
  if (learn || learnKey) {
    const { directoryKey, recoveryLookup } = stored;
    const fresh = await updateStored(kv, (current) => ({
      ...current,
      ...(learnKey && directoryKey ? { directoryKey } : {}),
      ...(learn && recoveryLookup ? { recoveryLookup } : {}),
    }));
    if (learn) await queueWraps(kv, root, fresh);
  }
  return root;
}

export async function signCert(
  root: CryptoKey,
  stored: Stored,
  nowSeconds: number,
  deviceName: string,
  device = stored.device.publicKey,
) {
  const notBefore = nowSeconds - BACKDATE_S;
  const statement = deviceCertStatement({
    user: stored.user,
    root: stored.rootPublic,
    device,
    nameHash: await sha256(deviceNamePreimage(deviceName)),
    revSeq: 0,
    notBefore,
    notAfter: notBefore + CERT_LIFETIME_S,
  });
  return { statement, signature: await sign(root, statement) };
}

/** The root's signed list of its wraps and the blobs, ready for the server (ADR 0021). */
type WrapsUpload = {
  statement: string;
  signature: Uint8Array;
  blobs: { lookup: Uint8Array; blob: Uint8Array }[];
};

const PENDING = 'pending-root-wraps';

/**
 * Signs the current list of wraps while the root is open and keeps it until
 * the server has it: a reload before then does not lose it. Each blob carries
 * the user and root public key a new browser needs to open it; they are the
 * wrap's associated data, so a server that changes them only makes it fail
 * to open. The seq is the time, so lists from two browsers still order.
 */
export async function queueWraps(kv: KeyValue, root: CryptoKey, stored: Stored, newCode = false): Promise<void> {
  const own: (WrapBlob & { kind: RootWrap['kind'] })[] = [];
  for (const wrap of stored.wraps) {
    const lookup =
      wrap.kind === 'recovery'
        ? stored.recoveryLookup && fromBase64Url(stored.recoveryLookup)
        : wrap.credentialId && (await sha256(prfLookupPreimage(wrap.credentialId)));
    if (!lookup) continue;
    const blob = new TextEncoder().encode(
      JSON.stringify({ v: 1, user: stored.user, rootPublic: toBase64Url(stored.rootPublic), wrap }),
    );
    own.push({ lookup, blob, kind: wrap.kind });
  }
  // Kept with the server's passkeys this browser does not have (ADR 0037).
  const held = await loadHeldWraps(kv);
  const blobs = mergeWraps(own, held, newCode);
  if (blobs.length === 0) return;
  const now = Math.floor(Date.now() / 1000);
  // The server keeps a list only if its seq beats the one it holds: a list
  // signed within the same second as the last (a new code right after the
  // first) was refused, and the old blob stayed. Milliseconds, and never
  // below the last seq signed here.
  // Above the server's too: another device's list may be the newer.
  const seq = Math.max(Date.now(), (stored.wrapsSeq ?? 0) + 1, (held?.seq ?? 0) + 1);
  stored.wrapsSeq = seq;
  await updateStored(kv, (current) => ({ ...current, wrapsSeq: Math.max(current.wrapsSeq ?? 0, seq) }));
  const entries = await Promise.all(blobs.map(async (b) => ({ lookup: b.lookup, digest: await sha256(b.blob) })));
  const statement = rootWrapsStatement(stored.user, seq, entries, now);
  await kv.set(PENDING, { statement, signature: await sign(root, statement), blobs } satisfies WrapsUpload);
}

const HELD = 'held-root-wraps';

/** What the server said it keeps (ADR 0037), or kept after a list was sent. */
export async function keepHeldWraps(kv: KeyValue, held: HeldWraps): Promise<void> {
  await kv.set(HELD, held);
}

/** What the server last said it keeps; null before it has said. */
async function loadHeldWraps(kv: KeyValue): Promise<HeldWraps | null> {
  return (await kv.get<HeldWraps | null>(HELD)) ?? null;
}

/**
 * Whether a new device can sign in with this browser's passkeys or recovery
 * code (ADR 0037), and whether one unlock here would make it so; null before
 * the server has said what it keeps.
 */
export async function newDeviceSignIn(
  kv: KeyValue,
): Promise<{ passkey: boolean; recovery: boolean; finish: boolean } | null> {
  const [stored, held] = await Promise.all([kv.get<Stored>(KEY), loadHeldWraps(kv)]);
  if (!stored || !held) return null;
  const passkeyLookups: Uint8Array[] = [];
  for (const w of stored.wraps)
    if (w.kind === 'prf' && w.credentialId) passkeyLookups.push(await sha256(prfLookupPreimage(w.credentialId)));
  return newDeviceReadiness(
    {
      passkeyLookups,
      recoveryLookup: stored.recoveryLookup ? fromBase64Url(stored.recoveryLookup) : null,
      hasRecovery: stored.wraps.some((w) => w.kind === 'recovery'),
    },
    held,
  );
}

/** Keeps `upload` as the list waiting for the server: one handed over from the console (ADR 0048). */
export async function keepPending(kv: KeyValue, upload: WrapsUpload): Promise<void> {
  await kv.set(PENDING, upload);
}

/** The signed list still waiting for the server, if any. */
export async function pendingWraps(kv: KeyValue): Promise<WrapsUpload | undefined> {
  return (await kv.get<WrapsUpload | null>(PENDING)) ?? undefined;
}

/** The server kept `sent`: drop it, unless a newer list was queued meanwhile. */
export async function wrapsSent(kv: KeyValue, sent: WrapsUpload): Promise<void> {
  if ((await pendingWraps(kv))?.statement === sent.statement) await kv.set(PENDING, null);
}

/** A name for this browser the owner will recognise in the device list: "Chrome on macOS". */
export function thisDeviceName(agent = navigator.userAgent): string {
  const browser = /Edg\//.test(agent)
    ? 'Edge'
    : /Firefox\//.test(agent)
      ? 'Firefox'
      : /Chrome\//.test(agent)
        ? 'Chrome'
        : /Safari\//.test(agent)
          ? 'Safari'
          : 'Browser';
  const os = /iPhone|iPad/.test(agent)
    ? 'iOS'
    : /Android/.test(agent)
      ? 'Android'
      : /Mac OS X/.test(agent)
        ? 'macOS'
        : /Windows/.test(agent)
          ? 'Windows'
          : /Linux/.test(agent)
            ? 'Linux'
            : 'unknown';
  return `${browser} on ${os}`;
}
