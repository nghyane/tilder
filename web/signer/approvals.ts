import { APPROVAL_MS, isMachineId } from '@/model/signer-protocol';
import type { KeyValue } from '@/platform/kv';

/**
 * The machines the owner allowed this browser's console to open shells and
 * copy files on, each for 12 hours (ADR 0048). Kept in the signer's origin,
 * written only by its confirm window: the console can read nothing here and
 * change nothing.
 */
export type Approvals = {
  allowed(machineId: string): Promise<boolean>;
  allow(machineId: string, nowMs: number): Promise<void>;
  /** Every machine of the owner's, for the same 12 hours (the owner's choice in the window). */
  allowAll(nowMs: number): Promise<void>;
  /**
   * Whether shells and copies wait for the owner's OK at all: off unless the
   * owner turned it on in the signer's window (the owner's call, 01/10).
   */
  asking(): Promise<boolean>;
  setAsking(on: boolean): Promise<void>;
};

const ASKING = 'ask-before-shells';

const KEY = 'approvals';
/** The entry for "all my machines": not a machine id, which cannot contain it. */
const ALL = '*';

export function approvalsIn(kv: KeyValue, now: () => number = Date.now): Approvals {
  const read = async () => (await kv.get<Record<string, number> | null>(KEY)) ?? {};
  return {
    async allowed(machineId) {
      const all = await read();
      const live = (until: number | undefined) => typeof until === 'number' && until > now();
      return live(all[machineId]) || live(all[ALL]);
    },
    async allow(machineId, nowMs) {
      if (!isMachineId(machineId)) throw new Error('not a machine id');
      await put(machineId, nowMs);
    },
    allowAll: (nowMs) => put(ALL, nowMs),
    asking: async () => (await kv.get<boolean | null>(ASKING)) === true,
    setAsking: (on) => kv.set(ASKING, on),
  };
  async function put(entry: string, nowMs: number) {
    const all = await read();
    // Expired entries go as new ones come.
    const kept = Object.fromEntries(Object.entries(all).filter(([, until]) => until > nowMs));
    await kv.set(KEY, { ...kept, [entry]: nowMs + APPROVAL_MS });
  }
}
