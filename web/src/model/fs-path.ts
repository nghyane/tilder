import { toBase64Url } from './base64';

/**
 * Paths on a machine as the agent takes them (ADR 0022): the exact name
 * bytes, joined by "/", relative to the home. Never normalised; decoded only
 * to be shown, so a name that is not UTF-8 still opens.
 */
const SLASH = 0x2f;
const decoder = new TextDecoder('utf-8', { fatal: false });

export const HOME = new Uint8Array();

export function joinPath(parent: Uint8Array, name: Uint8Array): Uint8Array {
  if (parent.length === 0) return name;
  const out = new Uint8Array(parent.length + 1 + name.length);
  out.set(parent);
  out[parent.length] = SLASH;
  out.set(name, parent.length + 1);
  return out;
}

/** A stable key for a path, for ids and storage. */
export const pathKey = (path: Uint8Array) => toBase64Url(path);

/** What to show for a name: bytes that are not UTF-8 show as U+FFFD. */
export const shownName = (name: Uint8Array) => decoder.decode(name);

/** The last name in a path. */
export function baseName(path: Uint8Array): Uint8Array {
  const at = path.lastIndexOf(SLASH);
  return at < 0 ? path : path.subarray(at + 1);
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** VS Code's explorer order: folders first, then names as people read them ("f2" before "f10"). */
export function compareEntries(
  a: { name: Uint8Array; folder: boolean },
  b: { name: Uint8Array; folder: boolean },
): number {
  if (a.folder !== b.folder) return a.folder ? -1 : 1;
  return collator.compare(shownName(a.name), shownName(b.name));
}

/**
 * Why a name typed for a new file, folder or rename cannot be one, or null.
 * The agent takes one component at a time (ADR 0022): not empty, not "." or
 * "..", no "/" or NUL, at most 255 bytes.
 */
export function nameProblem(name: string): string | null {
  if (name.trim() === '') return 'Type a name.';
  if (name === '.' || name === '..') return 'That name is taken by the folder itself.';
  if (name.includes('/')) return 'A name cannot hold "/".';
  if (name.includes('\0')) return 'A name cannot hold a NUL character.';
  if (new TextEncoder().encode(name).length > 255) return 'That name is too long (255 bytes at most).';
  return null;
}
