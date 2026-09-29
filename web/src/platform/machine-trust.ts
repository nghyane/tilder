import { fromBase64Url } from '@/model/base64';
import type { Machine } from '@/model/machines';
import type { Identity } from '@/model/owner';
import { registrationAt } from '@/model/register';
import { machineIdPreimage } from '@/model/statements';
import { idOf, verify } from './crypto';

/**
 * Marks each machine confirmed when its registration is the owner's root's,
 * for exactly this id and key, and the id is the key's own (ADR 0004). The
 * server supplies all of it; none of it is taken on trust.
 */
export async function confirmMachines(machines: Machine[], owner: Identity): Promise<Machine[]> {
  return Promise.all(
    machines.map(async (m) => {
      const reg = m.registration;
      if (!reg) return { ...m, confirmed: false };
      try {
        const key = fromBase64Url(m.publicKey);
        const confirmed =
          (await idOf(machineIdPreimage(key))) === m.id &&
          registrationAt(reg.statement, owner.user, m.id, key) !== null &&
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
