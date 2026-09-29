import { CROCKFORD } from './recovery-code';

/**
 * The code that adds a device (ADR 0004): the mailbox's nameplate, which is
 * not secret, and six Crockford characters (30 bits), which never leave the
 * two browsers. It is short because it is only ever tried once: a wrong
 * guess fails CPace's confirmation and the mailbox is gone (magic-wormhole
 * uses 16 bits the same way). The QR carries the same code.
 */
export type LinkCode = { nameplate: string; secret: string };

const SECRET_CHARS = 6;

/** A fresh code for `nameplate`; `random` gives six bytes, each picks one character. */
export function newLinkCode(nameplate: string, random: Uint8Array): LinkCode {
  if (random.length !== SECRET_CHARS) throw new Error('link code: six random bytes');
  // 256 is a multiple of 32, so each character is uniform.
  return { nameplate, secret: Array.from(random, (b) => CROCKFORD[b & 31]).join('') };
}

export const formatLinkCode = (code: LinkCode) => `${code.nameplate}-${code.secret}`;

/**
 * Reads a typed or scanned code: case, spaces and dashes do not matter, and
 * I and L read as 1, O as 0.
 */
export function parseLinkCode(typed: string): LinkCode | null {
  const clean = typed.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
  const nameplate = clean.slice(0, 4);
  const secret = clean.slice(4);
  if (!/^[0-9]{4}$/.test(nameplate) || secret.length !== SECRET_CHARS) return null;
  if ([...secret].some((c) => !CROCKFORD.includes(c))) return null;
  return { nameplate, secret };
}

/** The console link a QR carries: the code rides in the fragment, which browsers never send. */
export const linkUrl = (origin: string, code: LinkCode) => `${origin}/#link=${formatLinkCode(code)}`;

/** The code in a console link's fragment, if any. */
export function codeFromHash(hash: string): LinkCode | null {
  const match = /^#link=([0-9A-Za-z-]+)$/.exec(hash);
  return match?.[1] ? parseLinkCode(match[1]) : null;
}
