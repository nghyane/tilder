import { HOME, joinPath, shownName } from './fs-path';

/**
 * The folder box (wireframe 18, VS Code's and Zed's remote Open Folder):
 * what is typed is a folder to list and a start of a name to narrow it by.
 * "~/src/a" lists ~/src and keeps names starting "a". Only the home and
 * below can be opened (ADR 0022), so an absolute path, "." or ".." is said
 * to be out of reach rather than sent.
 */
type TypedFolder = { dir: Uint8Array; prefix: string } | { outside: true };

const encoder = new TextEncoder();

export function parseTyped(text: string): TypedFolder {
  const trimmed = text.trim();
  if (trimmed.startsWith('/')) return { outside: true };
  const rest = trimmed.replace(/^~(\/|$)/, '');
  if (rest.startsWith('~')) return { outside: true };
  const parts = rest.split('/');
  const prefix = parts.pop() ?? '';
  const names = parts.filter((p) => p !== '');
  if (names.some((n) => n === '.' || n === '..') || prefix === '..') return { outside: true };
  return { dir: names.reduce<Uint8Array>((path, n) => joinPath(path, encoder.encode(n)), HOME), prefix };
}

/** The folder above; the home stays the home. */
export function parentOf(path: Uint8Array): Uint8Array {
  const at = path.lastIndexOf(0x2f);
  return at < 0 ? HOME : path.subarray(0, at);
}

/** "~" for the home, "~/src/api" below it. */
export function folderLabel(path: Uint8Array): string {
  return path.length === 0 ? '~' : `~/${shownName(path)}`;
}

/** Names that start with the prefix first, then names that contain it; case does not matter. */
export function narrow<T extends { name: Uint8Array }>(entries: readonly T[], prefix: string): T[] {
  if (prefix === '') return [...entries];
  const p = prefix.toLowerCase();
  const name = (e: T) => shownName(e.name).toLowerCase();
  return [
    ...entries.filter((e) => name(e).startsWith(p)),
    ...entries.filter((e) => !name(e).startsWith(p) && name(e).includes(p)),
  ];
}
