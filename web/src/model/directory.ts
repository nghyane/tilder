import { type Layout, parseLayout } from './layout';

/**
 * The owner's directory (ADR 0006, 0032): their workspaces, as every device
 * of theirs holds them. The server stores it sealed and cannot merge it;
 * devices merge it, field by field within a workspace (after Firefox's
 * logins merge), so a rename on one device and a new tab on another both
 * survive. A deletion is kept as a tombstone for a while so a device that
 * was away does not bring it back.
 */

/** A folder of a machine at the top of a workspace's tree; `path` is base64url, "" the home. */
export type DirectoryRoot = { machineId: string; path: string };

/** The parts of a workspace merged apart from each other. */
type Field = 'name' | 'roots' | 'layout';
const FIELDS: Field[] = ['name', 'roots', 'layout'];

/** When each field last changed, ms; the later one wins a merge. */
export type Stamps = Record<Field, number>;

export type WorkspaceEntry = {
  id: string;
  name: string;
  roots: DirectoryRoot[];
  /**
   * The tabs and groups; null until a device has laid it out. Only its
   * shape is shared (layoutShape): which tab is in front and which group
   * has focus stay with each device, so a tap on the phone does not move
   * the laptop's view.
   */
  layout: Layout | null;
  /** When it last changed, ms: the latest of its stamps, or when it was deleted. */
  updatedAt: number;
  /** Stamped by the sync on every change (stampChanges); absent, every field counts as updatedAt. */
  stamps?: Stamps;
  /** Deleted: kept this way until TOMBSTONE_MS so it is not brought back. */
  deleted?: true;
};

export type DirectoryDoc = {
  v: 1;
  /** The revision the device meant it to be stored as: the server's rev must match (ADR 0032). */
  rev: number;
  workspaces: WorkspaceEntry[];
};

/** How long a deleted workspace is remembered, so a device away for less does not revive it. */
export const TOMBSTONE_MS = 30 * 24 * 3600 * 1000;

export const emptyDirectory = (): DirectoryDoc => ({ v: 1, rev: 0, workspaces: [] });

const stampsOf = (w: WorkspaceEntry): Stamps =>
  w.stamps ?? { name: w.updatedAt, roots: w.updatedAt, layout: w.updatedAt };

const lastChange = (w: WorkspaceEntry) => Math.max(w.updatedAt, ...FIELDS.map((f) => stampsOf(w)[f]));

/**
 * What of a layout is shared: groups, their split and their kept tabs. A
 * preview tab, the tab in front and the focused group are this device's
 * view of it; a terminal's title follows whatever runs in it.
 */
function layoutShape(layout: Layout | null): unknown {
  if (!layout) return null;
  const groups = Object.values(layout.groups)
    .map((g) => ({
      id: g.id,
      tabs: g.tabs
        .filter((t) => !t.preview)
        .map(({ id, kind, machineId, path, dir, pinned }) => ({ id, kind, machineId, path, dir, pinned })),
    }))
    .sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return { tree: layout.tree, groups };
}

/** A field's value as it is compared across devices. */
function keyOf(w: WorkspaceEntry, f: Field): string {
  if (f === 'layout') return JSON.stringify(layoutShape(w.layout));
  return JSON.stringify(w[f]);
}

/**
 * The winning layout, seen the way this device saw it: its focused group
 * and the tab in front of each group are kept where they still exist.
 */
function withView(winner: Layout | null, mine: Layout | null): Layout | null {
  if (!winner || !mine || winner === mine) return winner;
  const groups = Object.fromEntries(
    Object.entries(winner.groups).map(([id, g]) => {
      const active = mine.groups[id]?.active;
      return [id, active && g.tabs.some((t) => t.id === active) ? { ...g, active } : g];
    }),
  );
  return { ...winner, groups, focus: winner.groups[mine.focus] ? mine.focus : winner.focus };
}

/**
 * One workspace from two versions of it, `a` this device's. A deletion
 * wins over changes made before it and loses to changes made after it (the
 * workspace is revived); otherwise each field comes from whichever side
 * changed it later, a tie going the same way on every device.
 */
function mergeEntry(a: WorkspaceEntry, b: WorkspaceEntry): WorkspaceEntry {
  if (a.deleted && b.deleted) return a.updatedAt >= b.updatedAt ? a : b;
  if (a.deleted || b.deleted) {
    const [gone, alive] = a.deleted ? [a, b] : [b, a];
    return gone.updatedAt >= lastChange(alive) ? gone : alive;
  }
  const sa = stampsOf(a);
  const sb = stampsOf(b);
  const pick = (f: Field): WorkspaceEntry => {
    if (sa[f] !== sb[f]) return sa[f] > sb[f] ? a : b;
    const ka = keyOf(a, f);
    const kb = keyOf(b, f);
    return ka === kb || ka > kb ? a : b;
  };
  const name = pick('name');
  const roots = pick('roots');
  const layout = pick('layout');
  const stamps: Stamps = { name: stampsOf(name).name, roots: stampsOf(roots).roots, layout: stampsOf(layout).layout };
  return {
    id: a.id,
    name: name.name,
    roots: roots.roots,
    layout: layout === a ? a.layout : withView(layout.layout, a.layout),
    updatedAt: Math.max(...FIELDS.map((f) => stamps[f])),
    stamps,
  };
}

/**
 * Two versions of the directory as one, `a` this device's: each workspace
 * merged field by field, tombstones older than TOMBSTONE_MS dropped. What is
 * shared (sharedForm) comes out the same on every device whatever the order,
 * so devices converge; each keeps its own view of the layouts.
 */
export function mergeDirectories(a: DirectoryDoc, b: DirectoryDoc, now: number): DirectoryDoc {
  const byId = new Map<string, WorkspaceEntry>();
  for (const w of a.workspaces) byId.set(w.id, w);
  for (const w of b.workspaces) {
    const mine = byId.get(w.id);
    byId.set(w.id, mine ? mergeEntry(mine, w) : w);
  }
  const workspaces = [...byId.values()]
    .filter((w) => !w.deleted || now - w.updatedAt < TOMBSTONE_MS)
    .sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return { v: 1, rev: Math.max(a.rev, b.rev), workspaces };
}

/** The part of a directory every device must agree on: what a write stores for the others. */
export function sharedForm(doc: DirectoryDoc): string {
  return JSON.stringify(
    doc.workspaces.map((w) => ({
      id: w.id,
      deleted: w.deleted === true,
      updatedAt: w.updatedAt,
      ...(w.deleted ? {} : { stamps: stampsOf(w), ...Object.fromEntries(FIELDS.map((f) => [f, keyOf(w, f)])) }),
    })),
  );
}

/**
 * Stamps what a local edit changed, from `before` to `after`. A field's new
 * stamp is now, or one past the stamp it replaces if this device's clock is
 * behind: an edit always wins over the version it was made on, however the
 * devices' clocks disagree (the part of Firefox's merge by age that needs no
 * server time). `changed` is false when only this device's view moved, so
 * nothing needs storing.
 */
export function stampChanges(
  before: DirectoryDoc,
  after: DirectoryDoc,
  now: number,
): { doc: DirectoryDoc; changed: boolean } {
  const prior = new Map(before.workspaces.map((w) => [w.id, w]));
  let changed = after.workspaces.length !== before.workspaces.length;
  const workspaces = after.workspaces.map((w): WorkspaceEntry => {
    const prev = prior.get(w.id);
    if (w.deleted) {
      if (prev?.deleted) return prev;
      changed = true;
      const at = prev ? Math.max(now, lastChange(prev) + 1) : now;
      return { ...w, ...(prev ? { stamps: stampsOf(prev) } : {}), updatedAt: at };
    }
    if (!prev || prev.deleted) {
      changed = true;
      const at = prev ? Math.max(now, prev.updatedAt + 1) : now;
      return { ...w, stamps: { name: at, roots: at, layout: at }, updatedAt: at };
    }
    const stamps = { ...stampsOf(prev) };
    for (const f of FIELDS) {
      if (keyOf(w, f) !== keyOf(prev, f)) {
        stamps[f] = Math.max(now, stamps[f] + 1);
        changed = true;
      }
    }
    return { ...w, stamps, updatedAt: Math.max(...FIELDS.map((f) => stamps[f])) };
  });
  return { doc: { ...after, workspaces }, changed };
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isPath = (p: unknown): p is string => typeof p === 'string' && /^[A-Za-z0-9_-]*$/.test(p);
const isTime = (t: unknown): t is number => typeof t === 'number' && Number.isFinite(t);

function parseStamps(v: unknown): Stamps | undefined {
  if (!isRecord(v) || !FIELDS.every((f) => isTime(v[f]))) return undefined;
  return { name: v.name as number, roots: v.roots as number, layout: v.layout as number };
}

function parseEntry(v: unknown): WorkspaceEntry | null {
  if (!isRecord(v) || typeof v.id !== 'string' || v.id === '' || typeof v.name !== 'string') return null;
  if (!isTime(v.updatedAt) || !Array.isArray(v.roots)) return null;
  const roots = v.roots.filter(
    (r): r is DirectoryRoot => isRecord(r) && typeof r.machineId === 'string' && isPath(r.path),
  );
  const layout = v.layout === null ? null : parseLayout(v.layout);
  const stamps = parseStamps(v.stamps);
  return {
    id: v.id,
    name: v.name,
    roots: roots.map(({ machineId, path }) => ({ machineId, path })),
    layout,
    updatedAt: v.updatedAt,
    ...(stamps ? { stamps } : {}),
    ...(v.deleted === true ? { deleted: true as const } : {}),
  };
}

/**
 * A directory from its JSON, or null. Opened under the owner's key it came
 * from one of their devices, but it is read as carefully as anything else:
 * a device of an older or newer build may have written it.
 */
export function parseDirectory(json: string): DirectoryDoc | null {
  let v: unknown;
  try {
    v = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(v) || v.v !== 1 || typeof v.rev !== 'number' || !Array.isArray(v.workspaces)) return null;
  const workspaces = v.workspaces.map(parseEntry).filter((w): w is WorkspaceEntry => w !== null);
  return { v: 1, rev: v.rev, workspaces };
}
