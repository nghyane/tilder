import type { Machine } from './machines';

/**
 * The names the owner gives their machines (ADR 0052), kept in the sealed
 * directory so the server never sees them and every device shows the same.
 * A name is changed as of a time and the later change wins a merge; ""
 * means back to the name the machine gives itself, and is kept so an older
 * name on a device that was away does not come back.
 */
export type MachineName = { name: string; at: number };
export type MachineNames = Record<string, MachineName>;

const MACHINE_ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_MACHINE_NAME = 64;
/** As many as the server lets a user have removed: a directory is read as carefully as anything else. */
const MAX_NAMES = 4096;

/** Why `name` cannot be a machine's name, or null. */
export function machineNameProblem(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed === '') return 'Enter a name.';
  if (trimmed.length > MAX_MACHINE_NAME) return `At most ${MAX_MACHINE_NAME} characters.`;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: a name with control characters is refused
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return 'A name cannot hold control characters.';
  return null;
}

const later = (a: MachineName, b: MachineName) => (a.at !== b.at ? (a.at > b.at ? a : b) : a.name >= b.name ? a : b);

/** Both sides' names as one; the same on every device, whatever the order. */
export function mergeMachineNames(a: MachineNames, b: MachineNames): MachineNames {
  const out: MachineNames = { ...a };
  for (const [id, n] of Object.entries(b)) {
    const mine = out[id];
    out[id] = mine ? later(mine, n) : n;
  }
  return out;
}

/**
 * `id` named `name` as of now, or one past the change it replaces if this
 * device's clock is behind, so the edit wins over what it was made on. The
 * machine's own name (`own`) is stored as "": back to following the machine.
 */
export function renamed(names: MachineNames, id: string, name: string, own: string, now: number): MachineNames {
  const trimmed = name.trim();
  return { ...names, [id]: { name: trimmed === own ? '' : trimmed, at: Math.max(now, (names[id]?.at ?? 0) + 1) } };
}

/** The names as devices compare them: sorted, so equal names give equal text. */
export const namesKey = (names: MachineNames) =>
  JSON.stringify(
    Object.keys(names)
      .sort()
      .map((id) => [id, names[id]?.name, names[id]?.at]),
  );

/** The names a directory holds; anything malformed is left out. */
export function parseMachineNames(v: unknown): MachineNames {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return {};
  const out: MachineNames = {};
  for (const [id, n] of Object.entries(v).slice(0, MAX_NAMES)) {
    if (!MACHINE_ID.test(id) || typeof n !== 'object' || n === null) continue;
    const { name, at } = n as Record<string, unknown>;
    if (typeof name !== 'string' || typeof at !== 'number' || !Number.isFinite(at)) continue;
    if (name !== '' && machineNameProblem(name) !== null) continue;
    out[id] = { name, at };
  }
  return out;
}

/** The machines with the owner's names; `hostname` keeps the name each gives itself. */
export const withNames = (machines: Machine[], names: MachineNames): Machine[] =>
  machines.map((m) => {
    const name = names[m.id]?.name;
    return name ? { ...m, name, hostname: m.name } : m;
  });
