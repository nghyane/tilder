import { fromBase64Url, toBase64Url } from '@/model/base64';
import { deviceCertStatement, deviceNamePreimage } from '@/model/device-cert';
import type { Identity } from '@/model/owner';
import { registerStatement } from '@/model/register';
import { parseRevocations, type RevocationList, revocationsStatement } from '@/model/revocations';
import { recoveryLookupPreimage } from '@/model/root-wraps';
import { userIdPreimage } from '@/model/statements';
import { ACCOUNT_KV, ACCOUNT_LOCAL } from './account-state';
import { idOf, sha256, sign, verify } from './crypto';
import type { DeviceKeys } from './device-keys';
import { directoryKeyBytes, directoryKeyFrom, importDirectoryKey } from './directory-key';
import {
  BACKDATE_S,
  CERT_LIFETIME_S,
  identityOf,
  KEY,
  openRoot,
  queueWraps,
  type Stored,
  signCert,
  type Unlock,
  UnlockFailed,
  updateStored,
} from './identity-store';
import type { KeyValue } from './kv';
import type { Grant, Offer } from './link';
import type { PasskeyUnlock } from './passkey';
import { newRecoveryCode, wrapRoot } from './root-wrap';

export { recoverIdentity } from './identity-recover';
export type { Unlock } from './identity-store';
export { keepHeldWraps, newDeviceSignIn, pendingWraps, thisDeviceName, wrapsSent } from './identity-store';

/** This browser's identity, or null on a first visit. */
export async function loadIdentity(kv: KeyValue, keys: DeviceKeys): Promise<Identity | null> {
  const stored = await kv.get<Stored>(KEY);
  return stored?.v === 1 ? identityOf(stored, keys) : null;
}

/** The passkeys whose wraps this browser holds: a new one is made excluding them. */
export const passkeysOf = (stored: Stored) =>
  stored.wraps.flatMap((w) => (w.kind === 'prf' && w.credentialId ? [w.credentialId] : []));

/**
 * A new owner: a root, this browser's device key and the root's certificate
 * for it, and a recovery code the root is wrapped under. Nothing is stored
 * until `save`, which the console calls once the owner has written the code
 * down: a reload before that leaves no identity whose code was never seen.
 * The root is extractable only here, to be wrapped, and is dropped when this
 * returns.
 */
export async function prepareIdentity(
  keys: DeviceKeys,
  deviceName: string,
  nowSeconds: number,
): Promise<{
  identity: Identity;
  recoveryCode: string;
  /** Adds `made`, a passkey made just now, as a way to open the root too, while the root is still at hand. */
  addPasskey(made: PasskeyUnlock): Promise<void>;
  save(kv: KeyValue): Promise<void>;
}> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const rootPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const user = await idOf(userIdPreimage(rootPublic));
  const device = { publicKey: await keys.create() };
  const notBefore = nowSeconds - BACKDATE_S;
  const statement = deviceCertStatement({
    user,
    root: rootPublic,
    device: device.publicKey,
    nameHash: await sha256(deviceNamePreimage(deviceName)),
    revSeq: 0,
    notBefore,
    notAfter: notBefore + CERT_LIFETIME_S,
  });
  const cert = { statement, signature: await sign(pair.privateKey, statement) };
  const { code, secret } = await newRecoveryCode();
  const wraps = [await wrapRoot(pair.privateKey, secret, user, rootPublic)];
  const recoveryLookup = toBase64Url(await sha256(recoveryLookupPreimage(secret)));
  secret.fill(0);
  const directoryKey = await directoryKeyFrom(pair.privateKey);
  const stored: Stored = {
    v: 1,
    rootPublic,
    user,
    name: deviceName,
    device,
    cert,
    wraps,
    recoveryLookup,
    directoryKey,
  };
  let root: CryptoKey | null = pair.privateKey;
  return {
    identity: identityOf(stored, keys),
    recoveryCode: code,
    async addPasskey(made) {
      if (!root) throw new Error('already saved');
      stored.wraps.push(await wrapRoot(root, made.secret, user, rootPublic, made.credentialId));
      made.secret.fill(0);
    },
    async save(kv) {
      // Stored first: queueWraps records its seq on the stored identity.
      await kv.set(KEY, stored);
      if (root) await queueWraps(kv, root, stored);
      root = null; // from here the root exists only wrapped
    },
  };
}

/** Which ways this browser can open the root. */
export async function unlockMethods(kv: KeyValue): Promise<{ passkeys: number; recovery: boolean }> {
  const stored = await kv.get<Stored>(KEY);
  const wraps = stored?.wraps ?? [];
  return { passkeys: wraps.filter((w) => w.kind === 'prf').length, recovery: wraps.some((w) => w.kind === 'recovery') };
}

/** Renews this browser's certificate for another 90 days: an admin action. */
export async function renewCertificate(
  kv: KeyValue,
  keys: DeviceKeys,
  how: Unlock,
  deviceName: string,
  nowSeconds: number,
) {
  return (await renewAndRegister(kv, keys, how, deviceName, nowSeconds, [])).identity;
}

/**
 * Renews the certificate, and with the root open for it registers
 * `machines` as the root's (ADR 0053): machines a device registered, whose
 * registration would otherwise end with that device's certificate. One
 * unlock for both.
 */
export async function renewAndRegister(
  kv: KeyValue,
  keys: DeviceKeys,
  how: Unlock,
  deviceName: string,
  nowSeconds: number,
  machines: { id: string; publicKey: string }[],
) {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  const root = await openRoot(kv, stored, how);
  // The name the certificate binds stays the one this device shows.
  const cert = await signCert(root, stored, nowSeconds, stored.name ?? deviceName, stored.device.publicKey);
  const registrations = await Promise.all(
    machines.map(async (m) => {
      const statement = registerStatement(stored.user, m.id, fromBase64Url(m.publicKey), nowSeconds);
      return { statement, signature: await sign(root, statement) };
    }),
  );
  return { identity: identityOf(await updateStored(kv, (current) => ({ ...current, cert })), keys), registrations };
}

/** Adds `made`, a passkey made just now, as a way to open the root: the root is opened once more to wrap it. */
export async function addPasskey(kv: KeyValue, how: Unlock, made: PasskeyUnlock): Promise<void> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  const root = await openRoot(kv, stored, how, true);
  const wrap = await wrapRoot(root, made.secret, stored.user, stored.rootPublic, made.credentialId);
  made.secret.fill(0);
  // Only the new wrap is added, to the newest copy: another tab may have
  // changed the recovery code while this one waited on the passkey sheet.
  await queueWraps(kv, root, await updateStored(kv, (current) => ({ ...current, wraps: [...current.wraps, wrap] })));
}

/**
 * The root's registration of one machine (ADR 0004): an admin action, done
 * once the console has checked the machine proved its key at join.
 */
export async function registerMachine(
  kv: KeyValue,
  how: Unlock,
  machine: { id: string; publicKey: string },
  nowSeconds: number,
): Promise<{ statement: string; signature: Uint8Array }> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  const root = await openRoot(kv, stored, how);
  const statement = registerStatement(stored.user, machine.id, fromBase64Url(machine.publicKey), nowSeconds);
  return { statement, signature: await sign(root, statement) };
}

/**
 * A new list of removed devices (ADR 0004): the current one (checked against
 * the root) plus `device`, one seq on. The server takes it only as the
 * stored list's successor; a list that raced another is signed again.
 */
export async function revokeDevice(
  kv: KeyValue,
  how: Unlock,
  current: { statement: string; signature: Uint8Array } | undefined,
  device: Uint8Array,
  nowSeconds: number,
): Promise<{ statement: string; signature: Uint8Array }> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  let list: RevocationList = { seq: 0, devices: [] };
  if (current) {
    const parsed = parseRevocations(current.statement, stored.user);
    if (!parsed || !(await verify(stored.rootPublic, current.statement, current.signature))) {
      throw new UnlockFailed('The server’s list of removed devices is not yours: nothing was changed.');
    }
    list = parsed;
  }
  const root = await openRoot(kv, stored, how);
  const statement = revocationsStatement(
    stored.user,
    { seq: list.seq + 1, devices: [...list.devices, device] },
    nowSeconds,
  );
  return { statement, signature: await sign(root, statement) };
}

/**
 * The owner's grant to a new browser (ADR 0004): the root's certificate for
 * the key it offered, under the name it gave, and the wrapped root, so the
 * new browser can open the root the same ways this one can. An admin action.
 */
export async function grantDevice(kv: KeyValue, how: Unlock, offer: Offer, nowSeconds: number): Promise<Grant> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  // Extractable for this grant only: the new browser is handed the directory
  // key's bytes (ADR 0032), inside the link's sealed box, as it is the wraps.
  const root = await openRoot(kv, stored, how, true);
  const cert = await signCert(root, stored, nowSeconds, offer.name, offer.devicePublic);
  const directoryKey = await directoryKeyBytes(root);
  return { rootPublic: stored.rootPublic, user: stored.user, cert, wraps: stored.wraps, directoryKey };
}

/**
 * A browser being added to an existing owner: its device key, made before
 * the link runs so only the public half is offered, and `adopt`, which
 * stores the grant the link checked.
 */
export async function prepareLinkedDevice(
  keys: DeviceKeys,
  deviceName: string,
): Promise<{
  offer: Offer;
  adopt(kv: KeyValue, grant: Grant): Promise<Identity>;
}> {
  const device = { publicKey: await keys.create() };
  return {
    offer: { devicePublic: device.publicKey, name: deviceName },
    async adopt(kv, grant) {
      // The directory key's bytes are imported, never kept: stored, it is a
      // key WebCrypto will not export (importDirectoryKey zeroes the bytes).
      const { directoryKey: bytes, ...rest } = grant;
      const directoryKey = bytes ? await importDirectoryKey(bytes) : undefined;
      const stored: Stored = { v: 1, ...rest, name: deviceName, device, ...(directoryKey ? { directoryKey } : {}) };
      await kv.set(KEY, stored);
      return identityOf(stored, keys);
    },
  };
}

/**
 * A new recovery code for an owner who still has another way in (a passkey,
 * or the old code): the root is opened to wrap itself under the new code.
 * Nothing changes until `save`, which the console calls once the owner has
 * typed the new code back; then the old code no longer opens anything, here
 * or on the server (the new list of wraps replaces the old one).
 */
export async function prepareNewRecoveryCode(
  kv: KeyValue,
  how: Unlock,
): Promise<{ recoveryCode: string; save(): Promise<void> }> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  let root: CryptoKey | null = await openRoot(kv, stored, how, true);
  const { code, secret } = await newRecoveryCode();
  const wrap = await wrapRoot(root, secret, stored.user, stored.rootPublic);
  const recoveryLookup = toBase64Url(await sha256(recoveryLookupPreimage(secret)));
  secret.fill(0);
  return {
    recoveryCode: code,
    async save() {
      if (!root) throw new Error('already saved');
      // From the newest copy: another tab may have added a passkey meanwhile.
      const next = await updateStored(kv, (current) => ({
        ...current,
        wraps: [...current.wraps.filter((w) => w.kind !== 'recovery'), wrap],
        recoveryLookup,
      }));
      await queueWraps(kv, root, next, true);
      root = null;
    },
  };
}

/**
 * Puts what a new device needs on the server (ADR 0037): opens the root once
 * and signs the list of this browser's wraps, kept with the server's other
 * passkeys. With the recovery code, an identity made before ADR 0021 also
 * learns where its code's blob goes.
 */
export async function finishNewDeviceSignIn(kv: KeyValue, how: Unlock): Promise<void> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  const root = await openRoot(kv, stored, how);
  await queueWraps(kv, root, (await kv.get<Stored>(KEY)) ?? stored);
}

/**
 * Forgets the owner on this browser, to start over: a removed device, or an
 * owner who lost every way to open the root. The machines keep trusting the
 * old root; they must be joined again from a new one.
 */
export async function forgetIdentity(kv: KeyValue, keys: DeviceKeys): Promise<void> {
  await keys.forget();
  await forgetAccount(kv);
}

/** What this origin keeps of the account; the key signer forgets its own. */
export async function forgetAccount(kv: KeyValue): Promise<void> {
  for (const key of ACCOUNT_KV) await kv.set(key, null);
  try {
    for (const key of ACCOUNT_LOCAL) localStorage.removeItem(key);
  } catch {
    // No localStorage (a private window may refuse it): nothing kept there.
  }
}

/**
 * Opens the root only so this device learns the directory key (ADR 0032):
 * "Sync workspaces" on a device from before. The root is closed again.
 */
export async function learnDirectoryKey(kv: KeyValue, how: Unlock): Promise<void> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  await openRoot(kv, stored, how);
}

/** This device's directory key (ADR 0032), or null until the root is opened here once. */
export async function loadDirectoryKey(kv: KeyValue): Promise<CryptoKey | null> {
  return (await kv.get<Stored>(KEY))?.directoryKey ?? null;
}
