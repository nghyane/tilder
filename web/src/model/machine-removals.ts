/**
 * The root's list of removed machines (ADR 0052), byte for byte as Go writes
 * it (identity.MachineRemovals). A registration never expires, so a machine
 * stays removed as of a time: one registered after it (added back) counts
 * again, one registered at or before it does not.
 */
type RemovedMachine = { id: string; at: number };
type MachineRemovals = { user: string; seq: number; machines: RemovedMachine[]; at: number };

const MACHINE_ID = /^[A-Za-z0-9_-]{22}$/;
/** As Go bounds it: a longer list is refused before it is read. */
const MAX_REMOVED = 4096;

const byId = (a: RemovedMachine, b: RemovedMachine) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

export function machineRemovalsStatement(l: MachineRemovals): string {
  const machines = l.machines.map((m) => `${m.id}:${m.at}`).join(',');
  return `tilder/machine-removals/v2\nuser=${l.user}\nseq=${l.seq}\nmachines=${machines}\nat=${l.at}\n`;
}

/** The list `text` is, if it is exactly the canonical text for `user`; null otherwise. Not the signature. */
export function parseMachineRemovals(text: string, user: string): MachineRemovals | null {
  if (text.length > 96 + MAX_REMOVED * 36) return null;
  const m =
    /^tilder\/machine-removals\/v2\nuser=([^\n]*)\nseq=(0|[1-9][0-9]{0,15})\nmachines=([^\n]*)\nat=(-?[0-9]{1,16})\n$/.exec(
      text,
    );
  if (!m || m[1] !== user) return null;
  const machines: RemovedMachine[] = [];
  if (m[3]) {
    const entries = (m[3] ?? '').split(',');
    if (entries.length > MAX_REMOVED) return null;
    for (const e of entries) {
      const [id, when] = e.split(':');
      if (!id || !MACHINE_ID.test(id) || when === undefined || !/^-?[0-9]{1,16}$/.test(when)) return null;
      machines.push({ id, at: Number(when) });
    }
  }
  const list = { user, seq: Number(m[2]), machines, at: Number(m[4]) };
  return machineRemovalsStatement(list) === text && isCanonical(machines) ? list : null;
}

function isCanonical(machines: RemovedMachine[]): boolean {
  for (let i = 1; i < machines.length; i++) {
    const prev = machines[i - 1];
    const cur = machines[i];
    if (!prev || !cur || byId(prev, cur) >= 0) return false;
  }
  return true;
}

/** The next list: `current`'s machines plus `id` removed at `at`, one seq on. */
export function withRemoved(current: MachineRemovals | null, user: string, id: string, at: number): MachineRemovals {
  const kept = (current?.machines ?? []).filter((m) => m.id !== id);
  const previous = current?.machines.find((m) => m.id === id);
  // Removed again later: the later time, so a registration in between no longer counts.
  const machines = [...kept, { id, at: Math.max(at, previous?.at ?? at) }].sort(byId);
  return { user, seq: (current?.seq ?? 0) + 1, machines, at };
}

/** Whether `list` removes machine `id` for a registration signed at `registeredAt`. */
export const removes = (list: MachineRemovals | null, id: string, registeredAt: number) =>
  list?.machines.some((m) => m.id === id && registeredAt <= m.at) ?? false;
