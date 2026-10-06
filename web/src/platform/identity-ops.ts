import type { Identity } from '@/model/owner';
import { ShownError } from '@/model/problem';
import type { HeldWraps } from '@/model/root-wraps';
import type { Imported } from '@/model/signer-identity-ops';
import type { DeviceKeys } from './device-keys';
import {
  addPasskey,
  finishNewDeviceSignIn,
  forgetAccount,
  forgetIdentity,
  grantDevice,
  keepHeldWraps,
  learnDirectoryKey,
  loadDirectoryKey,
  loadIdentity,
  newDeviceSignIn,
  passkeysOf,
  pendingWraps,
  prepareIdentity,
  prepareLinkedDevice,
  prepareNewRecoveryCode,
  recoverIdentity,
  registerMachine,
  renewAndRegister,
  revokeDevice,
  type Unlock,
  unlockMethods,
  wrapsSent,
} from './identity';
import { removeMachine } from './identity-machines';
import { KEY, type Stored } from './identity-store';
import type { KeyValue } from './kv';
import type { Grant, Offer } from './link';
import type { PasskeyUnlock } from './passkey';
import type { SignerKeys } from './signer';

/**
 * A new recovery code as this page may hold it: the code, with no key
 * signer (the in-page demo); its token with one, shown in the signer's own
 * frame and never here (ADR 0054).
 */
export type ShownCode = { code: string } | { token: string };

type Signed = { statement: string; signature: Uint8Array };

type WrapsUpload = NonNullable<Awaited<ReturnType<typeof pendingWraps>>>;

/**
 * The owner's identity as the console uses it (ADR 0048): held by the key
 * signer, on its own origin, in the product; held by this page only in the
 * in-page demo. The console never sees the root or the device key, only
 * what they sign and the public identity.
 */
export type IdentityOps = {
  load(): Promise<Identity | null>;
  prepare(
    name: string,
    now: number,
  ): Promise<{
    identity: Identity;
    shown: ShownCode;
    addPasskey(made: PasskeyUnlock): Promise<void>;
    save(): Promise<void>;
  }>;
  unlockMethods(): Promise<{ passkeys: number; recovery: boolean }>;
  /**
   * Renews this browser's certificate; with the same unlock, registers
   * `machines` as the root's (ADR 0053). An older signer ignores them and
   * returns none.
   */
  renew(
    how: Unlock,
    name: string,
    now: number,
    machines?: { id: string; publicKey: string }[],
  ): Promise<{ identity: Identity; registrations: Signed[] }>;
  /** Wraps the root under `made`, a passkey the console just made for the site (ADR 0048). */
  addPasskey(how: Unlock, made: PasskeyUnlock): Promise<void>;
  /** The root's next list of removed machines, with `machineId` (ADR 0052): opens the root. */
  removeMachine(how: Unlock, current: Signed | undefined, machineId: string, now: number): Promise<Signed>;
  /** The ids of the passkeys that already open the root: a new one is made excluding them. */
  passkeyIds(): Promise<string[]>;
  register(how: Unlock, machine: { id: string; publicKey: string }, now: number): Promise<Signed>;
  revoke(how: Unlock, current: Signed | undefined, device: Uint8Array, now: number): Promise<Signed>;
  grant(how: Unlock, offer: Offer, now: number): Promise<Grant>;
  link(name: string): Promise<{ offer: Offer; adopt(grant: Grant): Promise<Identity> }>;
  newCode(how: Unlock): Promise<{ shown: ShownCode; save(): Promise<void> }>;
  finishSignIn(how: Unlock): Promise<void>;
  forget(): Promise<void>;
  learnDirectory(how: Unlock): Promise<void>;
  directoryKey(): Promise<CryptoKey | null>;
  recover(how: Unlock, name: string, now: number): Promise<Identity>;
  pendingWraps(): Promise<WrapsUpload | undefined>;
  wrapsSent(sent: WrapsUpload): Promise<void>;
  keepHeld(held: HeldWraps): Promise<void>;
  newDeviceSignIn(): Promise<{ passkey: boolean; recovery: boolean; finish: boolean } | null>;
};

/** The identity in `kv` of this origin: the in-page demo's, and the signer's own. */
export function localIdentityOps(
  kv: KeyValue,
  keys: DeviceKeys,
  fetchBlob: (lookup: Uint8Array) => Promise<Uint8Array | null>,
): IdentityOps {
  return {
    load: () => loadIdentity(kv, keys),
    async prepare(name, now) {
      const p = await prepareIdentity(keys, name, now);
      return {
        identity: p.identity,
        shown: { code: p.recoveryCode },
        addPasskey: p.addPasskey,
        save: () => p.save(kv),
      };
    },
    unlockMethods: () => unlockMethods(kv),
    renew: (how, name, now, machines = []) => renewAndRegister(kv, keys, how, name, now, machines),
    addPasskey: (how, made) => addPasskey(kv, how, made),
    removeMachine: (how, current, machineId, now) => removeMachine(kv, how, current, machineId, now),
    passkeyIds: async () => {
      const stored = await kv.get<Stored>(KEY);
      return stored ? passkeysOf(stored) : [];
    },
    register: (how, machine, now) => registerMachine(kv, how, machine, now),
    revoke: (how, current, device, now) => revokeDevice(kv, how, current, device, now),
    grant: (how, offer, now) => grantDevice(kv, how, offer, now),
    async link(name) {
      const l = await prepareLinkedDevice(keys, name);
      return { offer: l.offer, adopt: (grant) => l.adopt(kv, grant) };
    },
    async newCode(how) {
      const n = await prepareNewRecoveryCode(kv, how);
      return { shown: { code: n.recoveryCode }, save: () => n.save() };
    },
    finishSignIn: (how) => finishNewDeviceSignIn(kv, how),
    forget: () => forgetIdentity(kv, keys),
    learnDirectory: (how) => learnDirectoryKey(kv, how),
    directoryKey: () => loadDirectoryKey(kv),
    recover: (how, name, now) => recoverIdentity(kv, keys, how, fetchBlob, name, now),
    pendingWraps: () => pendingWraps(kv),
    wrapsSent: (sent) => wrapsSent(kv, sent),
    keepHeld: (held) => keepHeldWraps(kv, held),
    newDeviceSignIn: () => newDeviceSignIn(kv),
  };
}

const isBytes = (v: unknown, n: number): v is Uint8Array =>
  Object.prototype.toString.call(v) === '[object Uint8Array]' && (v as Uint8Array).length === n;

class SignerNonsense extends ShownError {
  constructor() {
    super('The key signer answered nonsense.');
  }
}

/**
 * The identity the key signer holds, asked for by name. `kv` is this
 * origin's, for what the console keeps of the account (machines, the
 * workspace cache): forgotten along with the signer's.
 */
export function remoteIdentityOps(signer: SignerKeys, kv: KeyValue): IdentityOps {
  const call = signer.identity;
  // The public identity the signer answers with; its signing is the signer's too.
  const identity = (v: unknown): Identity => {
    const i = v as Partial<Identity> | null;
    if (
      !i ||
      !isBytes(i.rootPublic, 32) ||
      !isBytes(i.devicePublic, 32) ||
      typeof i.user !== 'string' ||
      typeof i.name !== 'string' ||
      typeof i.cert?.statement !== 'string' ||
      !isBytes(i.cert.signature, 64)
    )
      throw new SignerNonsense();
    return {
      rootPublic: i.rootPublic,
      user: i.user,
      name: i.name,
      devicePublic: i.devicePublic,
      cert: { statement: i.cert.statement, signature: i.cert.signature },
      signHello: (nonce) => signer.signHello(nonce),
      signOffer: (machineId, sessionId, offerDigest) => signer.signOffer(machineId, sessionId, offerDigest),
      signTransfer: (t) => signer.signTransfer(t),
      signRegistration: (r) => signer.signRegistration(r),
    };
  };
  const signed = (v: unknown): Signed => {
    const s = v as Partial<Signed> | null;
    if (typeof s?.statement !== 'string' || !isBytes(s.signature, 64)) throw new SignerNonsense();
    return { statement: s.statement, signature: s.signature };
  };
  const token = (v: unknown): string => {
    const t = (v as { token?: unknown } | null)?.token;
    if (typeof t !== 'string') throw new SignerNonsense();
    return t;
  };

  return {
    load: async () => {
      const v = await call('id-load');
      return v === null ? null : identity(v);
    },
    async prepare(name, now) {
      // The code stays in the signer: shown by its token, in its own frame (ADR 0054).
      const v = await call('id-prepare', { name, now, hide: true });
      const t = token(v);
      return {
        identity: identity((v as { identity?: unknown }).identity),
        shown: { token: t },
        addPasskey: async (made) => void (await call('id-prepare-passkey', { token: t, made })),
        save: async () => void (await call('id-prepare-save', { token: t })),
      };
    },
    async unlockMethods() {
      const v = (await call('id-unlock-methods')) as { passkeys?: unknown; recovery?: unknown } | null;
      if (typeof v?.passkeys !== 'number' || typeof v.recovery !== 'boolean') throw new SignerNonsense();
      return { passkeys: v.passkeys, recovery: v.recovery };
    },
    async renew(how, name, now, machines) {
      const v = await call('id-renew', { how, name, now, ...(machines?.length ? { machines } : {}) });
      const regs = (v as { registrations?: unknown } | null)?.registrations;
      return { identity: identity(v), registrations: Array.isArray(regs) ? regs.map(signed) : [] };
    },
    addPasskey: async (how, made) => void (await call('id-add-passkey', { how, made })),
    removeMachine: async (how, current, machine, now) =>
      signed(await call('id-remove-machine', { how, machine, now, ...(current ? { current } : {}) })),
    async passkeyIds() {
      const v = await call('id-passkey-ids');
      if (!Array.isArray(v) || !v.every((id) => typeof id === 'string')) throw new SignerNonsense();
      return v as string[];
    },
    register: async (how, machine, now) => signed(await call('id-register', { how, machine, now })),
    revoke: async (how, current, device, now) =>
      signed(await call('id-revoke', { how, device, now, ...(current ? { current } : {}) })),
    // Handed on over the link as it is: the new browser's signer checks it.
    grant: async (how, offer, now) => (await call('id-grant', { how, offer, now })) as Grant,
    async link(name) {
      const v = await call('id-link-offer', { name });
      const t = token(v);
      const offer = (v as { offer?: Partial<Offer> }).offer;
      if (!isBytes(offer?.devicePublic, 32) || typeof offer.name !== 'string') throw new SignerNonsense();
      return {
        offer: { devicePublic: offer.devicePublic, name: offer.name },
        adopt: async (grant) => identity(await call('id-link-adopt', { token: t, grant })),
      };
    },
    async newCode(how) {
      const v = await call('id-new-code', { how, hide: true });
      const t = token(v);
      return { shown: { token: t }, save: async () => void (await call('id-new-code-save', { token: t })) };
    },
    finishSignIn: async (how) => void (await call('id-finish-signin', { how })),
    async forget() {
      await call('id-forget');
      await forgetAccount(kv);
    },
    learnDirectory: async (how) => void (await call('id-learn-directory', { how })),
    async directoryKey() {
      const v = await call('id-directory-key');
      if (v !== null && Object.prototype.toString.call(v) !== '[object CryptoKey]') throw new SignerNonsense();
      return v as CryptoKey | null;
    },
    recover: async (how, name, now) => identity(await call('id-recover', { how, name, now })),
    async pendingWraps() {
      const v = (await call('id-pending-wraps')) as WrapsUpload | null;
      return v ?? undefined;
    },
    wrapsSent: async (sent) => void (await call('id-wraps-sent', { statement: sent.statement })),
    keepHeld: async (held) => void (await call('id-keep-held', { held })),
    newDeviceSignIn: async () =>
      (await call('id-new-device-signin')) as { passkey: boolean; recovery: boolean; finish: boolean } | null,
  };
}

/**
 * A browser from before the signer kept the identity (ADR 0048): this
 * origin's stored identity, and its wraps still waiting for the server, are
 * handed to the signer once; the copy here is forgotten a week later
 * (forgetMoved). The signer checks what it is handed and refuses it when it
 * already holds an identity.
 */
export async function moveToSigner(kv: KeyValue, signer: SignerKeys, now = Date.now()): Promise<void> {
  // As the console stored it before the signer: with the device's private key.
  const stored = await kv.get<Imported | null>(KEY);
  if (stored?.v !== 1) return;
  const pending = (await pendingWraps(kv)) ?? null;
  await signer.identity('id-import', { stored, pending });
  await kv.set(MOVED_AT, now);
}

/** When this browser's identity moved to the signer (ADR 0048): its copy here is kept a while after. */
const MOVED_AT = 'identity-moved-at';
/** The owner's call: a console rolled back within a week still finds the owner signed in. */
const KEEP_MOVED_MS = 7 * 24 * 3600 * 1000;

/**
 * Forgets this origin's copy of an identity the signer holds, once a week
 * has passed since it moved (ADR 0048): until then a console rolled back to
 * one from before still has it, as it had before the move.
 */
export async function forgetMoved(kv: KeyValue, now = Date.now()): Promise<void> {
  const at = await kv.get<number | null>(MOVED_AT);
  if (typeof at !== 'number' || now - at < KEEP_MOVED_MS) return;
  await kv.set(KEY, null);
  await kv.set('pending-root-wraps', null);
  await kv.set(MOVED_AT, null);
}
