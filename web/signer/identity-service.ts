import { toBase64Url } from '@/model/base64';
import { parseDeviceCert } from '@/model/device-cert';
import type { Identity } from '@/model/owner';
import type { IdentityRequest } from '@/model/signer-identity-ops';
import { userIdPreimage } from '@/model/statements';
import { idOf, sign, verify } from '@/platform/crypto';
import { adoptDeviceKey, type DeviceKeys } from '@/platform/device-keys';
import {
  addPasskey,
  finishNewDeviceSignIn,
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
  unlockMethods,
  wrapsSent,
} from '@/platform/identity';
import { removeMachine } from '@/platform/identity-machines';
import { KEY, keepPending, type Stored, type Unlock, UnlockFailed } from '@/platform/identity-store';
import type { KeyValue } from '@/platform/kv';
import type { CodeFields } from './code-fields';

/** The public side of this browser's identity: what the console may hold. */
const pub = (i: Identity) => ({
  rootPublic: i.rootPublic,
  user: i.user,
  name: i.name,
  devicePublic: i.devicePublic,
  cert: i.cert,
});

const newToken = () => toBase64Url(crypto.getRandomValues(new Uint8Array(16)));

type Prepared = Awaited<ReturnType<typeof prepareIdentity>>;
type Linking = Awaited<ReturnType<typeof prepareLinkedDevice>>;
type NewCode = Awaited<ReturnType<typeof prepareNewRecoveryCode>>;

/**
 * The identity work, in the signer's origin (ADR 0048): the same code the
 * console ran, on the signer's own store and key. Work that spans calls
 * (a new account before its code is saved, a link, a new code) is kept
 * here by a random token; the console holds only the token.
 */
/**
 * When the signer stops taking a code typed in the console, and stops giving
 * one to a console that does not ask it hidden (ADR 0054): a week after the
 * consoles that never do either shipped. A console tab older than that is
 * told to reload.
 */
export const LEGACY_UNTIL = Date.UTC(2026, 9, 14);

/** A request whose unlock is a passkey or the code itself: a named field taken. */
type Resolved = IdentityRequest extends infer T
  ? T extends { how: unknown }
    ? Omit<T, 'how'> & { how: Unlock }
    : T
  : never;

export function identityService(
  kv: KeyValue,
  keys: DeviceKeys,
  fetchBlob: (lookup: Uint8Array) => Promise<Uint8Array | null>,
  fields: CodeFields = { take: async () => null, used: () => undefined, stop: () => undefined },
  now: () => number = Date.now,
) {
  const prepared = new Map<string, Prepared>();
  const linking = new Map<string, Linking>();
  const newCodes = new Map<string, NewCode>();
  const take = <T>(map: Map<string, T>, token: string): T => {
    const v = map.get(token);
    if (!v) throw new UnlockFailed('That step has expired: start it again.');
    return v;
  };

  /** A new code in the making, for the code page to show by its token (ADR 0054). */
  const codeFor = (token: string) => prepared.get(token)?.recoveryCode ?? newCodes.get(token)?.recoveryCode ?? null;

  return Object.assign(run, { codeFor });

  async function run(asked: IdentityRequest): Promise<unknown> {
    // Until consoles from before ADR 0054 are gone, the signer still takes
    // a code the console typed, and gives a new code to a console that does
    // not ask it hidden; after, never (ADR 0054).
    const legacyOver = now() >= LEGACY_UNTIL;
    if (legacyOver && 'how' in asked && 'recoveryCode' in asked.how)
      throw new UnlockFailed('This page is out of date: reload it, then try again.');
    // A code typed into this origin's field stands in for the code: the
    // console named the field, never saw what is in it. It opens one action:
    // dropped once that worked (or failed for any reason but the code), kept
    // after a wrong code so the owner can fix a typo.
    if (!('how' in asked && 'codeField' in asked.how)) return perform(asked as Resolved, legacyOver);
    const field = asked.how.codeField;
    const code = await fields.take(field);
    if (!code) throw new UnlockFailed('Type your recovery code.');
    try {
      const out = await perform({ ...asked, how: { recoveryCode: code } } as Resolved, legacyOver);
      fields.used(field);
      return out;
    } catch (error) {
      if (!(error instanceof UnlockFailed)) fields.used(field);
      throw error;
    }
  }

  async function perform(r: Resolved, legacyOver: boolean): Promise<unknown> {
    switch (r.op) {
      case 'id-load': {
        const i = await loadIdentity(kv, keys);
        return i ? pub(i) : null;
      }
      case 'id-prepare': {
        const p = await prepareIdentity(keys, r.name, r.now);
        const token = newToken();
        prepared.clear(); // one account in the making at a time
        prepared.set(token, p);
        // A console from before ADR 0054 shows the code itself; a newer one
        // asks the signer's own frame for it, by the token.
        return { token, ...(r.hide || legacyOver ? {} : { recoveryCode: p.recoveryCode }), identity: pub(p.identity) };
      }
      case 'id-prepare-passkey':
        return take(prepared, r.token).addPasskey(r.made);
      case 'id-prepare-save': {
        await take(prepared, r.token).save(kv);
        prepared.delete(r.token);
        return null;
      }
      case 'id-unlock-methods':
        return unlockMethods(kv);
      case 'id-renew': {
        const { identity, registrations } = await renewAndRegister(kv, keys, r.how, r.name, r.now, r.machines ?? []);
        return { ...pub(identity), registrations };
      }
      case 'id-add-passkey':
        return addPasskey(kv, r.how, r.made);
      case 'id-remove-machine':
        return removeMachine(kv, r.how, r.current, r.machine, r.now);
      case 'id-passkey-ids': {
        const stored = await kv.get<Stored>(KEY);
        return stored ? passkeysOf(stored) : [];
      }
      case 'id-register':
        return registerMachine(kv, r.how, r.machine, r.now);
      case 'id-revoke':
        return revokeDevice(kv, r.how, r.current, r.device, r.now);
      case 'id-grant':
        return grantDevice(kv, r.how, r.offer, r.now);
      case 'id-link-offer': {
        const l = await prepareLinkedDevice(keys, r.name);
        const token = newToken();
        linking.clear();
        linking.set(token, l);
        return { token, offer: l.offer };
      }
      case 'id-link-adopt': {
        const l = take(linking, r.token);
        // The console checked the grant on the link; it is checked again
        // here, where it is kept: the root signed a certificate for this
        // very key, and the user is the root's.
        if (!(await certifies(r.grant, l.offer.devicePublic)))
          throw new UnlockFailed('The other device sent a grant that is not for this browser.');
        linking.delete(r.token);
        return pub(await l.adopt(kv, r.grant));
      }
      case 'id-new-code': {
        const n = await prepareNewRecoveryCode(kv, r.how);
        const token = newToken();
        newCodes.clear();
        newCodes.set(token, n);
        return { token, ...(r.hide || legacyOver ? {} : { recoveryCode: n.recoveryCode }) };
      }
      case 'id-new-code-save': {
        await take(newCodes, r.token).save();
        newCodes.delete(r.token);
        return null;
      }
      case 'id-finish-signin':
        return finishNewDeviceSignIn(kv, r.how);
      case 'id-forget':
        return forgetIdentity(kv, keys);
      case 'id-learn-directory':
        return learnDirectoryKey(kv, r.how);
      case 'id-directory-key':
        return loadDirectoryKey(kv);
      case 'id-recover':
        return pub(await recoverIdentity(kv, keys, r.how, fetchBlob, r.name, r.now));
      case 'id-pending-wraps':
        return (await pendingWraps(kv)) ?? null;
      case 'id-wraps-sent': {
        const pending = await pendingWraps(kv);
        if (pending?.statement === r.statement) await wrapsSent(kv, pending);
        return null;
      }
      case 'id-keep-held':
        return keepHeldWraps(kv, r.held);
      case 'id-new-device-signin':
        return newDeviceSignIn(kv);
      case 'id-import': {
        // Once, into a signer that holds no identity: never over one.
        if (await kv.get(KEY)) throw new UnlockFailed('The key signer already holds an identity.');
        const { stored } = r;
        const key = stored.device.privateKey;
        if (!(await certifies(stored, stored.device.publicKey))) throw new UnlockFailed('That identity is not whole.');
        if (key) {
          // The key handed over must be the certified one: it signs, and the certified half checks it.
          const probe = 'tilder key signer: the key handed over is the certified one';
          if (!(await verify(stored.device.publicKey, probe, await sign(key, probe))))
            throw new UnlockFailed('That identity is not whole.');
          await adoptDeviceKey(kv, { publicKey: stored.device.publicKey, privateKey: key });
        } else if (!sameBytes((await keys.publicKey()) ?? new Uint8Array(), stored.device.publicKey)) {
          throw new UnlockFailed('That identity is for a key this signer does not hold.');
        }
        await kv.set(KEY, { ...stored, device: { publicKey: stored.device.publicKey } });
        if (r.pending) await keepPending(kv, r.pending);
        return null;
      }
      default:
        throw new Error('refused');
    }
  }
}

/** The root certified `device` for its own user: a grant or an identity, checked where it is kept. */
async function certifies(
  i: { rootPublic: Uint8Array; user: string; cert: { statement: string; signature: Uint8Array } },
  device: Uint8Array,
): Promise<boolean> {
  const cert = parseDeviceCert(i.cert.statement);
  const user = await idOf(userIdPreimage(i.rootPublic));
  return (
    cert !== null &&
    user === i.user &&
    cert.user === user &&
    sameBytes(cert.root, i.rootPublic) &&
    sameBytes(cert.device, device) &&
    (await verify(i.rootPublic, i.cert.statement, i.cert.signature))
  );
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
