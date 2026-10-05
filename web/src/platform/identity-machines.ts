import { machineRemovalsStatement, parseMachineRemovals, withRemoved } from '@/model/machine-removals';
import { sign, verify } from './crypto';
import { KEY, openRoot, type Stored, type Unlock, UnlockFailed } from './identity-store';
import type { KeyValue } from './kv';

type Signed = { statement: string; signature: Uint8Array };

/**
 * The root's next list of removed machines (ADR 0052): `current` (checked
 * against the root first) plus `machineId`, removed as of now. An admin
 * action: the root is opened, and closed again.
 */
export async function removeMachine(
  kv: KeyValue,
  how: Unlock,
  current: Signed | undefined,
  machineId: string,
  nowSeconds: number,
): Promise<Signed> {
  const stored = await kv.get<Stored>(KEY);
  if (!stored) throw new UnlockFailed('This browser has no identity yet.');
  let list = null;
  if (current) {
    list = parseMachineRemovals(current.statement, stored.user);
    if (!list || !(await verify(stored.rootPublic, current.statement, current.signature))) {
      throw new UnlockFailed('The server’s list of removed machines is not yours: nothing was changed.');
    }
  }
  const root = await openRoot(kv, stored, how);
  const statement = machineRemovalsStatement(withRemoved(list, stored.user, machineId, nowSeconds));
  return { statement, signature: await sign(root, statement) };
}
