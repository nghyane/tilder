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
  pendingWraps,
  prepareIdentity,
  prepareLinkedDevice,
  prepareNewRecoveryCode,
  recoverIdentity,
  registerMachine,
  renewCertificate,
  revokeDevice,
  unlockMethods,
  wrapsSent,
} from '@/platform/identity';
import { KEY, keepPending, UnlockFailed } from '@/platform/identity-store';
import type { KeyValue } from '@/platform/kv';
import { type PasskeyUnlock, PasskeyUnsupported } from '@/platform/passkey';
import type { Made } from './made-passkeys';

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
export function identityService(
  kv: KeyValue,
  keys: DeviceKeys,
  fetchBlob: (lookup: Uint8Array) => Promise<Uint8Array | null>,
  takeMade: (nonce: string) => Promise<Made>,
) {
  const prepared = new Map<string, Prepared>();
  const linking = new Map<string, Linking>();
  const newCodes = new Map<string, NewCode>();
  const take = <T>(map: Map<string, T>, token: string): T => {
    const v = map.get(token);
    if (!v) throw new UnlockFailed('That step has expired: start it again.');
    return v;
  };

  // The passkey the signer's own button made under `nonce`, or why none was.
  const passkey = async (nonce: string): Promise<PasskeyUnlock> => {
    const m = await takeMade(nonce);
    if ('made' in m) return m.made;
    if (m.error === 'unsupported') throw new PasskeyUnsupported(m.message);
    throw new Error(m.message || 'No passkey was made. Try again.');
  };

  return async function run(r: IdentityRequest): Promise<unknown> {
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
        return { token, recoveryCode: p.recoveryCode, identity: pub(p.identity) };
      }
      case 'id-prepare-passkey':
        return take(prepared, r.token).addPasskey(await passkey(r.nonce));
      case 'id-prepare-save': {
        await take(prepared, r.token).save(kv);
        prepared.delete(r.token);
        return null;
      }
      case 'id-unlock-methods':
        return unlockMethods(kv);
      case 'id-renew':
        return pub(await renewCertificate(kv, keys, r.how, r.name, r.now));
      case 'id-add-passkey':
        return addPasskey(kv, r.how, await passkey(r.nonce));
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
        return { token, recoveryCode: n.recoveryCode };
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
  };
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
