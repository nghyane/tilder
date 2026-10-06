import { fromBase64Url, toBase64Url } from '@/model/base64';
import { CLOCK_SKEW_S, certTimeProblem, parseDeviceCert } from '@/model/device-cert';
import { parseMachineRemovals, removes } from '@/model/machine-removals';
import type { Machine } from '@/model/machines';
import type { Identity } from '@/model/owner';
import { deviceRegistrationAt, registrationAt } from '@/model/register';
import { hasDevice, parseRevocations, type RevocationList } from '@/model/revocations';
import { machineIdPreimage } from '@/model/statements';
import { idOf, verify } from './crypto';

type Signed = { statement: string; signature: Uint8Array };
type Kept<L> = { list: L; signed: Signed };

/** Where the newest list of removed machines this browser has checked is kept (ADR 0052). */
const REMOVALS_KEY = 'tilder:machine-removals';
/** Where the newest list of removed devices this browser has checked is kept (ADR 0053). */
const REVOCATIONS_KEY = 'tilder:revocations';

/**
 * The newest list of removed machines this browser has checked against the
 * root: the one the server sent, or the one kept from before if that is
 * newer. A server that sends an older list, or none, cannot bring a removed
 * machine back (ADR 0052).
 */
export const latestRemovals = (owner: Identity, sent?: Signed) =>
  latestKept(REMOVALS_KEY, owner, sent, (text) => parseMachineRemovals(text, owner.user));

/** The same for the root's list of removed devices: a device's registrations die with it (ADR 0053). */
export const latestRevocations = (owner: Identity, sent?: Signed) =>
  latestKept(REVOCATIONS_KEY, owner, sent, (text) => parseRevocations(text, owner.user));

async function latestKept<L extends { seq: number }>(
  key: string,
  owner: Identity,
  sent: Signed | undefined,
  parse: (text: string) => L | null,
): Promise<Kept<L> | null> {
  const check = async (signed: Signed | undefined): Promise<Kept<L> | null> => {
    if (!signed) return null;
    const list = parse(signed.statement);
    if (!list || !(await verify(owner.rootPublic, signed.statement, signed.signature))) return null;
    return { list, signed };
  };
  const kept = await check(readKept(key));
  const fresh = await check(sent);
  const newest = fresh && (!kept || fresh.list.seq > kept.list.seq) ? fresh : kept;
  if (newest && newest !== kept) {
    try {
      localStorage.setItem(
        key,
        JSON.stringify({ statement: newest.signed.statement, signature: toBase64Url(newest.signed.signature) }),
      );
    } catch {
      // Storage refused: the server's list still counts for this page.
    }
  }
  return newest;
}

function readKept(key: string): Signed | undefined {
  try {
    const raw = JSON.parse(localStorage.getItem(key) ?? 'null') as {
      statement?: unknown;
      signature?: unknown;
    } | null;
    if (typeof raw?.statement !== 'string' || typeof raw.signature !== 'string') return undefined;
    return { statement: raw.statement, signature: fromBase64Url(raw.signature) };
  } catch {
    return undefined;
  }
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * When a registration was signed, if it is the owner's: the root's
 * (ADR 0004), or a device's with that device's certificate from the root,
 * valid now, of a device the root has not removed (ADR 0053). Null for
 * anything else. Every part comes from the server and is checked here.
 */
async function registeredAt(
  m: Machine,
  key: Uint8Array,
  owner: Identity,
  revoked: RevocationList | null,
  nowSeconds: number,
): Promise<number | null> {
  const reg = m.registration;
  if (!reg) return null;
  const byRoot = registrationAt(reg.statement, owner.user, m.id, key);
  if (byRoot !== null) return (await verify(owner.rootPublic, reg.statement, reg.signature)) ? byRoot : null;
  // No list as new as this browser's own certificate says there is: the
  // server holds it back, and no device's registration counts until it comes.
  const ownRevSeq = parseDeviceCert(owner.cert.statement)?.revSeq ?? 0;
  if ((revoked?.seq ?? 0) < ownRevSeq) return null;
  const certificate = reg.deviceCertificate;
  const cert = certificate && parseDeviceCert(certificate.statement);
  if (!certificate || !cert || cert.user !== owner.user || !sameBytes(cert.root, owner.rootPublic)) return null;
  if (certTimeProblem(cert, nowSeconds) !== null || (revoked && hasDevice(revoked, cert.device))) return null;
  const at = deviceRegistrationAt(reg.statement, owner.user, m.id, key, cert.device);
  // Signed while the certificate held, as Go checks (identity.VerifyDeviceRegistration).
  if (at === null || at > nowSeconds + CLOCK_SKEW_S || at < cert.notBefore - CLOCK_SKEW_S) return null;
  if (at > cert.notAfter + CLOCK_SKEW_S) return null;
  const ok =
    (await verify(owner.rootPublic, certificate.statement, certificate.signature)) &&
    (await verify(cert.device, reg.statement, reg.signature));
  return ok ? at : null;
}

/**
 * Marks each machine confirmed when its registration is the owner's
 * (registeredAt), for exactly this id and key, and the id is the key's own
 * (ADR 0004), and the root's list of removed machines does not remove it
 * (ADR 0052). The server supplies all of it; none of it is taken on trust.
 */
export async function confirmMachines(
  machines: Machine[],
  owner: Identity,
  removals?: Signed,
  revocations?: Signed,
): Promise<Machine[]> {
  const removed = await latestRemovals(owner, removals);
  const revoked = await latestRevocations(owner, revocations);
  const nowSeconds = Math.floor(Date.now() / 1000);
  return Promise.all(
    machines.map(async (m) => {
      try {
        const key = fromBase64Url(m.publicKey);
        const at = await registeredAt(m, key, owner, revoked?.list ?? null, nowSeconds);
        const confirmed =
          at !== null && (await idOf(machineIdPreimage(key))) === m.id && !removes(removed?.list ?? null, m.id, at);
        return { ...m, confirmed };
      } catch {
        return { ...m, confirmed: false };
      }
    }),
  );
}

/**
 * Whether the agent proved this machine key with the join secret's private
 * half (identity.JoinProof): only the console that made the secret can tell,
 * so the server cannot slip in a key of its own at join.
 */
export async function joinProofHolds(auth: Uint8Array, machinePublic: Uint8Array, proof: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', auth as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'verify',
  ]);
  const message = new Uint8Array([...new TextEncoder().encode('tilder/join-proof/v2\n'), ...machinePublic]);
  return crypto.subtle.verify('HMAC', key, proof as BufferSource, message);
}
