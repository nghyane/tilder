import { fromBase64Url, toBase64Url } from './base64';
import { parentOf } from './folder-query';

/**
 * Tabs and tab groups of one workspace (FRONTEND §6). Every tab is equal — a
 * terminal, a file, settings — and lives in a group; groups tile
 * the work area as a tree of row/column splits, as VS Code's editor groups
 * and Zed's panes do. Pure: each operation returns a new layout, so the same
 * state can be saved per workspace and replayed in tests.
 *
 * Invariants: a tab id appears once; pinned tabs lead their group; there is
 * always at least one group, and every group but the last has a tab.
 */
type TabKind = 'terminal' | 'settings' | 'file';

export type Tab = {
  id: string;
  kind: TabKind;
  title: string;
  machineId?: string;
  /** A file tab's path on its machine: the name bytes as base64url (ADR 0022). */
  path?: string;
  /** A terminal tab's folder, where its shell started (ADR 0024), as base64url; absent is the home. */
  dir?: string;
  pinned: boolean;
  /** Replaced by the next preview open; an edit or a double click keeps it. */
  preview: boolean;
};

export type NewTab = Omit<Tab, 'pinned' | 'preview'> & { preview?: boolean };

export type Group = { id: string; tabs: Tab[]; active: string | null };

export type Tree = { group: string } | { split: 'row' | 'column'; children: Tree[] };

export type Layout = { groups: Record<string, Group>; tree: Tree; focus: string };

type Edge = 'left' | 'right' | 'top' | 'bottom';

export function emptyLayout(groupId: string): Layout {
  return { groups: { [groupId]: { id: groupId, tabs: [], active: null } }, tree: { group: groupId }, focus: groupId };
}

/** Groups in reading order: left to right, top to bottom. */
export function groupOrder(layout: Layout): string[] {
  const walk = (tree: Tree): string[] => ('group' in tree ? [tree.group] : tree.children.flatMap(walk));
  return walk(layout.tree);
}

export function groupOf(layout: Layout, tabId: string): Group | undefined {
  return Object.values(layout.groups).find((g) => g.tabs.some((t) => t.id === tabId));
}

function findTab(layout: Layout, tabId: string): Tab | undefined {
  return groupOf(layout, tabId)?.tabs.find((t) => t.id === tabId);
}

/**
 * Opens a tab in `groupId` (the focused group by default). A tab already open
 * anywhere is shown where it is. A preview replaces the group's current
 * preview in place.
 */
export function openTab(layout: Layout, tab: NewTab, groupId = layout.focus): Layout {
  if (groupOf(layout, tab.id)) return activate(layout, tab.id);
  const group = layout.groups[groupId];
  if (!group) return layout;
  const next: Tab = { ...tab, pinned: false, preview: tab.preview ?? false };
  const previewAt = next.preview ? group.tabs.findIndex((t) => t.preview) : -1;
  const tabs = previewAt >= 0 ? group.tabs.with(previewAt, next) : [...group.tabs, next];
  return withGroup({ ...layout, focus: groupId }, { ...group, tabs, active: next.id });
}

export function activate(layout: Layout, tabId: string): Layout {
  const group = groupOf(layout, tabId);
  if (!group) return layout;
  return withGroup({ ...layout, focus: group.id }, { ...group, active: tabId });
}

export function focusGroup(layout: Layout, groupId: string): Layout {
  return layout.groups[groupId] ? { ...layout, focus: groupId } : layout;
}

/** Closes one tab. The tab to its right takes over, else the one to its left. */
export function closeTab(layout: Layout, tabId: string): Layout {
  const group = groupOf(layout, tabId);
  if (!group) return layout;
  const at = group.tabs.findIndex((t) => t.id === tabId);
  const tabs = group.tabs.filter((t) => t.id !== tabId);
  const active = group.active === tabId ? ((tabs[at] ?? tabs[at - 1])?.id ?? null) : group.active;
  return pruned(withGroup(layout, { ...group, tabs, active }));
}

/**
 * Closes others, those to the right of `anchor`, or all. Pinned tabs stay:
 * pinning is how a tab says "not in a bulk close".
 */
export function closeTabs(layout: Layout, anchor: string, which: 'others' | 'right' | 'all'): Layout {
  const group = groupOf(layout, anchor);
  if (!group) return layout;
  const at = group.tabs.findIndex((t) => t.id === anchor);
  const keep = (t: Tab, i: number) =>
    t.pinned || (which === 'others' && t.id === anchor) || (which === 'right' && i <= at);
  const tabs = group.tabs.filter(keep);
  const active = tabs.some((t) => t.id === group.active) ? group.active : (tabs.at(-1)?.id ?? null);
  return pruned(withGroup(layout, { ...group, tabs, active }));
}

/** Pins (moves to the end of the pinned run) or unpins (to the start of the rest). */
export function setPinned(layout: Layout, tabId: string, pinned: boolean): Layout {
  const group = groupOf(layout, tabId);
  const tab = group?.tabs.find((t) => t.id === tabId);
  if (!group || !tab || tab.pinned === pinned) return layout;
  const rest = group.tabs.filter((t) => t.id !== tabId);
  const pinnedCount = rest.filter((t) => t.pinned).length;
  const tabs = rest.toSpliced(pinnedCount, 0, { ...tab, pinned, preview: false });
  return withGroup(layout, { ...group, tabs });
}

/** A preview becomes a kept tab. */
export function keep(layout: Layout, tabId: string): Layout {
  const group = groupOf(layout, tabId);
  if (!group) return layout;
  return withGroup(layout, { ...group, tabs: group.tabs.map((t) => (t.id === tabId ? { ...t, preview: false } : t)) });
}

/**
 * Moves a tab to `index` in `toGroup` (drag and drop). The index is clamped
 * to the tab's run, so a pinned tab stays among pinned ones and vice versa.
 */
export function moveTab(layout: Layout, tabId: string, toGroup: string, index: number): Layout {
  const from = groupOf(layout, tabId);
  const tab = from?.tabs.find((t) => t.id === tabId);
  if (!from || !tab || !layout.groups[toGroup]) return layout;
  let next = layout;
  if (from.id !== toGroup) next = detach(next, from, tabId);
  const target = next.groups[toGroup];
  if (!target) return layout;
  const rest = target.tabs.filter((t) => t.id !== tabId);
  // index counts the tabs as shown, the moved one among them: moved right in
  // its own group, one of the tabs before the drop point is itself (VS Code's
  // multiEditorTabsControl does the same).
  const at = from.id === toGroup && from.tabs.findIndex((t) => t.id === tabId) < index ? index - 1 : index;
  const pinnedCount = rest.filter((t) => t.pinned).length;
  const [low, high] = tab.pinned ? [0, pinnedCount] : [pinnedCount, rest.length];
  const tabs = rest.toSpliced(Math.min(Math.max(at, low), high), 0, tab);
  return pruned(withGroup({ ...next, focus: toGroup }, { ...target, tabs, active: tabId }));
}

/**
 * Opens a new group at `edge` of `beside` holding `tab`: a tab already in the
 * layout moves there (drag to an edge, "Move to Other Group"); a new one opens
 * there (⌘\ on a terminal splits with a fresh shell).
 */
export function splitWith(layout: Layout, beside: string, edge: Edge, tab: NewTab, newGroupId: string): Layout {
  if (!layout.groups[beside] || layout.groups[newGroupId]) return layout;
  const existing = findTab(layout, tab.id);
  const source = groupOf(layout, tab.id);
  // Splitting a group's only tab off itself would leave an empty twin.
  if (source?.id === beside && source.tabs.length === 1) return layout;
  let next = source ? detach(layout, source, tab.id) : layout;
  const moved: Tab = existing ?? { ...tab, pinned: false, preview: tab.preview ?? false };
  next = {
    ...next,
    groups: { ...next.groups, [newGroupId]: { id: newGroupId, tabs: [moved], active: moved.id } },
    tree: insertBeside(next.tree, beside, newGroupId, edge),
    focus: newGroupId,
  };
  return pruned(next);
}

/** The group after this one in reading order, wrapping; `undefined` when alone. */
export function neighbourGroup(layout: Layout, groupId: string): string | undefined {
  const order = groupOrder(layout);
  if (order.length < 2) return undefined;
  return order[(order.indexOf(groupId) + 1) % order.length];
}

// --- internals ---

function withGroup(layout: Layout, group: Group): Layout {
  return { ...layout, groups: { ...layout.groups, [group.id]: group } };
}

function detach(layout: Layout, group: Group, tabId: string): Layout {
  const tabs = group.tabs.filter((t) => t.id !== tabId);
  const at = group.tabs.findIndex((t) => t.id === tabId);
  const active = group.active === tabId ? ((tabs[at] ?? tabs[at - 1])?.id ?? null) : group.active;
  return withGroup(layout, { ...group, tabs, active });
}

/** Drops empty groups (never the last one) and collapses the tree around them. */
function pruned(layout: Layout): Layout {
  const order = groupOrder(layout);
  const empty = order.filter((id) => layout.groups[id]?.tabs.length === 0);
  const doomed = empty.length === order.length ? empty.slice(1) : empty;
  if (doomed.length === 0) return layout;
  const groups = { ...layout.groups };
  let tree: Tree = layout.tree;
  for (const id of doomed) {
    delete groups[id];
    tree = removeLeaf(tree, id) ?? tree;
  }
  const focus = groups[layout.focus] ? layout.focus : (groupOrder({ ...layout, tree })[0] ?? layout.focus);
  return { groups, tree, focus };
}

function removeLeaf(tree: Tree, id: string): Tree | null {
  if ('group' in tree) return tree.group === id ? null : tree;
  const children = tree.children.map((c) => removeLeaf(c, id)).filter((c): c is Tree => c !== null);
  if (children.length === 0) return null;
  if (children.length === 1) return children[0] ?? null;
  return { split: tree.split, children: flatten(tree.split, children) };
}

function insertBeside(tree: Tree, target: string, id: string, edge: Edge): Tree {
  const split = edge === 'left' || edge === 'right' ? 'row' : 'column';
  const before = edge === 'left' || edge === 'top';
  const leaf: Tree = { group: id };
  if ('group' in tree) {
    if (tree.group !== target) return tree;
    return { split, children: before ? [leaf, tree] : [tree, leaf] };
  }
  // Same direction as the parent: become a sibling, not a nested split.
  const at = tree.children.findIndex((c) => 'group' in c && c.group === target);
  if (at >= 0 && tree.split === split) {
    return { split, children: tree.children.toSpliced(before ? at : at + 1, 0, leaf) };
  }
  return {
    split: tree.split,
    children: flatten(
      tree.split,
      tree.children.map((c) => insertBeside(c, target, id, edge)),
    ),
  };
}

function flatten(split: 'row' | 'column', children: Tree[]): Tree[] {
  return children.flatMap((c) => ('split' in c && c.split === split ? c.children : [c]));
}

/**
 * A saved layout read back from storage: disk data is untrusted, so anything
 * that breaks an invariant — unknown kind, duplicate tab, a tree that does not
 * match the groups, a focus that does not exist — discards the whole layout
 * and the workspace starts empty. Previews come back kept.
 */
export function parseLayout(value: unknown): Layout | null {
  if (!isRecord(value) || !isRecord(value.groups) || typeof value.focus !== 'string') return null;
  const groups: Record<string, Group> = {};
  const seen = new Set<string>();
  for (const [id, raw] of Object.entries(value.groups)) {
    if (!isRecord(raw) || raw.id !== id || !Array.isArray(raw.tabs)) return null;
    const tabs: Tab[] = [];
    for (const t of raw.tabs) {
      // The machines table was a tab before it had a place of its own.
      if (isRecord(t) && t.kind === 'machines') continue;
      const tab = parseTab(t);
      if (!tab || seen.has(tab.id)) return null;
      seen.add(tab.id);
      tabs.push(tab);
    }
    const pinnedFirst = tabs.every((t, i) => !t.pinned || tabs.slice(0, i).every((p) => p.pinned));
    if (!pinnedFirst) return null;
    const active = typeof raw.active === 'string' && tabs.some((t) => t.id === raw.active) ? raw.active : null;
    groups[id] = { id, tabs, active: active ?? tabs[0]?.id ?? null };
  }
  const tree = parseTree(value.tree);
  if (!tree) return null;
  const layout: Layout = { groups, tree, focus: value.focus };
  const order = groupOrder(layout);
  const sameGroups = order.length === Object.keys(groups).length && order.every((id) => groups[id]);
  if (!sameGroups || new Set(order).size !== order.length || !groups[layout.focus]) return null;
  return layout;
}

const KINDS: readonly Tab['kind'][] = ['terminal', 'settings', 'file'];

function parseTab(value: unknown): Tab | null {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.title !== 'string') return null;
  if (!KINDS.includes(value.kind as Tab['kind'])) return null;
  if (value.machineId !== undefined && typeof value.machineId !== 'string') return null;
  if (value.path !== undefined && (typeof value.path !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value.path))) return null;
  if (value.dir !== undefined && (typeof value.dir !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value.dir))) return null;
  if (value.kind === 'file' && (typeof value.machineId !== 'string' || typeof value.path !== 'string')) return null;
  return {
    id: value.id,
    kind: value.kind as Tab['kind'],
    title: value.title,
    ...(typeof value.machineId === 'string' ? { machineId: value.machineId } : {}),
    ...(typeof value.path === 'string' ? { path: value.path } : {}),
    ...(typeof value.dir === 'string' ? { dir: value.dir } : {}),
    pinned: value.pinned === true,
    preview: false,
  };
}

function parseTree(value: unknown, depth = 0): Tree | null {
  if (!isRecord(value) || depth > 32) return null;
  if (typeof value.group === 'string') return { group: value.group };
  if ((value.split !== 'row' && value.split !== 'column') || !Array.isArray(value.children)) return null;
  if (value.children.length < 2) return null;
  const children = value.children.map((c) => parseTree(c, depth + 1));
  return children.every((c): c is Tree => c !== null) ? { split: value.split, children } : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * A terminal tab follows its shell (ADR 0024): the folder it is in now, when
 * under the home, and the name it shows. Unchanged, the same layout returns.
 */
export function followShell(layout: Layout, id: string, title: string, dir?: string): Layout {
  const group = groupOf(layout, id);
  const tab = group?.tabs.find((t) => t.id === id);
  if (!group || !tab || (tab.title === title && (dir === undefined || tab.dir === dir))) return layout;
  const next: Tab = { ...tab, title, ...(dir !== undefined ? { dir } : {}) };
  return {
    ...layout,
    groups: { ...layout.groups, [group.id]: { ...group, tabs: group.tabs.map((t) => (t.id === id ? next : t)) } },
  };
}

/** Where a terminal opens (ADR 0024): its folder as base64url ("" the home), and beside the focused group. */
export type TerminalPlace = { dir?: string; side?: boolean };

/**
 * The folder a tab is "in", for a terminal opened from it (ADR 0024): a
 * terminal's own, a file's parent; base64url, "" the home, undefined none.
 */
export function folderOf(tab: Tab | undefined): string | undefined {
  if (tab?.kind === 'terminal') return tab.dir ?? '';
  if (tab?.kind === 'file' && tab.path !== undefined) return toBase64Url(parentOf(fromBase64Url(tab.path)));
  return undefined;
}
