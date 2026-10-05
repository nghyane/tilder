import { fromBase64Url, toBase64Url } from '@/model/base64';
import { type MachineRemovals, parseMachineRemovals, removes } from '@/model/machine-removals';
import type { Machine } from '@/model/machines';
import type { Identity } from '@/model/owner';
import { registrationAt } from '@/model/register';
import { machineIdPreimage } from '@/model/statements';
import { idOf, verify } from './crypto';

type Signed = { statement: string; signature: Uint8Array };
type KnownRemovals = { list: MachineRemovals; signed: Signed };

/** Where the newest list of removed machines this browser has checked is kept (ADR 0052). */
const REMOVALS_KEY = 'tilder:machine-removals';

/**
 * The newest list of removed machines this browser has checked against the
 * root: the one the server sent, or the one kept from before if that is
 * newer. A server that sends an older list, or none, cannot bring a removed
 * machine back (ADR 0052).
 */
export async function latestRemovals(owner: Identity, sent?: Signed): Promise<KnownRemovals | null> {
  const kept = await checked(owner, readKept());
  const fresh = await checked(owner, sent);
  const newest = fresh && (!kept || fresh.list.seq > kept.list.seq) ? fresh : kept;
  if (newest && newest !== kept) {
    try {
      localStorage.setItem(
        REMOVALS_KEY,
        JSON.stringify({ statement: newest.signed.statement, signature: toBase64Url(newest.signed.signature) }),
      );
    } catch {
      // Storage refused: the server's list still counts for this page.
    }
  }
  return newest;
}

async function checked(owner: Identity, signed: Signed | undefined): Promise<KnownRemovals | null> {
  if (!signed) return null;
  const list = parseMachineRemovals(signed.statement, owner.user);
  if (!list || !(await verify(owner.rootPublic, signed.statement, signed.signature))) return null;
  return { list, signed };
}

function readKept(): Signed | undefined {
  try {
    const raw = JSON.parse(localStorage.getItem(REMOVALS_KEY) ?? 'null') as {
      statement?: unknown;
      signature?: unknown;
    } | null;
    if (typeof raw?.statement !== 'string' || typeof raw.signature !== 'string') return undefined;
    return { statement: raw.statement, signature: fromBase64Url(raw.signature) };
  } catch {
    return undefined;
  }
}

/**
 * Marks each machine confirmed when its registration is the owner's root's,
 * for exactly this id and key, and the id is the key's own (ADR 0004), and
 * the root's list of removed machines does not remove it (ADR 0052). The
 * server supplies all of it; none of it is taken on trust.
 */
export async function confirmMachines(machines: Machine[], owner: Identity, removals?: Signed): Promise<Machine[]> {
  const removed = await latestRemovals(owner, removals);
  return Promise.all(
    machines.map(async (m) => {
      const reg = m.registration;
      if (!reg) return { ...m, confirmed: false };
      try {
        const key = fromBase64Url(m.publicKey);
        const at = registrationAt(reg.statement, owner.user, m.id, key);
        const confirmed =
          (await idOf(machineIdPreimage(key))) === m.id &&
          at !== null &&
          !removes(removed?.list ?? null, m.id, at) &&
          (await verify(owner.rootPublic, reg.statement, reg.signature));
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
