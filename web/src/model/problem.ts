/**
 * An error whose message was written for the owner to read. Anything else
 * (a browser's DOMException, a library's TypeError, a code like "fs: busy")
 * is never shown as is: its text was not written for them and may name a
 * file or carry what was on screen.
 */
export class ShownError extends Error {}

/** The message of an error written for the owner, else null; the details of any other go to this browser's console. */
export function shownMessage(error: unknown): string | null {
  if (error instanceof ShownError && error.message) return error.message;
  console.error('[tilder] an error the owner sees as a fixed sentence', error);
  return null;
}

/** What the owner reads for `error`: its own message if written for them, else `fallback`. */
export const problemText = (error: unknown, fallback: string): string => shownMessage(error) ?? fallback;
