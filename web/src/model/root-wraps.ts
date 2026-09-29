import { toBase64Url } from './base64';

/**
 * The root's list of its wrapped copies the server keeps (ADR 0021), byte
 * for byte as go/internal/identity writes it: each blob by lookup key and
 * SHA-256, sorted by lookup key.
 */
type RootWrapEntry = { lookup: Uint8Array; digest: Uint8Array };

const compare = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
};

export const rootWrapsStatement = (user: string, seq: number, wraps: RootWrapEntry[], atSeconds: number) =>
  `tilder/root-wraps/v2\nuser=${user}\nseq=${seq}\nwraps=${[...wraps]
    .sort((a, b) => compare(a.lookup, b.lookup))
    .map((w) => `${toBase64Url(w.lookup)}:${toBase64Url(w.digest)}`)
    .join(',')}\nat=${atSeconds}\n`;

const encoder = new TextEncoder();

/** What a recovery code's blob is found by: derived from its secret, never the secret. */
export const recoveryLookupPreimage = (secret: Uint8Array) =>
  Uint8Array.from([...encoder.encode('tilder/recovery-lookup\n'), ...secret]);

/** What a passkey's blob is found by, from its credential id. */
export const prfLookupPreimage = (credentialId: string) => encoder.encode(`tilder/prf-lookup\n${credentialId}`);

/** A wrapped root as the server keeps it: found by lookup, sealed. */
export type WrapBlob = { lookup: Uint8Array; blob: Uint8Array };

/** What the server keeps of the root's wraps (ADR 0037): the list's seq (0: none) and its blobs. */
export type HeldWraps = { seq: number; blobs: WrapBlob[] };

/** At most this many wraps in a list, as go/internal/identity takes it. */
export const MAX_ROOT_WRAPS = 16;

type Kind = 'recovery' | 'prf';

/** A blob's kind, from its JSON (`wrap.kind` is not sealed); null for one this build does not read. */
function blobKind(blob: Uint8Array): Kind | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(blob)) as { v?: number; wrap?: { kind?: string } };
    const kind = parsed.v === 1 ? parsed.wrap?.kind : undefined;
    return kind === 'recovery' || kind === 'prf' ? kind : null;
  } catch {
    return null;
  }
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * The list a device signs (ADR 0037): its own wraps, and the server's
 * passkeys it does not have (another device added them: a list replacing the
 * server's dropped them). One recovery code: the one made here when
 * `newCode`; else the server's if it keeps one (another device may have made
 * a newer code); else this device's. At most MAX_ROOT_WRAPS, its own first.
 */
export function mergeWraps(own: (WrapBlob & { kind: Kind })[], held: HeldWraps | null, newCode: boolean): WrapBlob[] {
  const theirs = (held?.blobs ?? []).filter((h) => !own.some((o) => same(o.lookup, h.lookup)));
  const serverCode = newCode ? undefined : theirs.find((h) => blobKind(h.blob) === 'recovery');
  const mine = own.filter((o) => !(serverCode && o.kind === 'recovery'));
  const carried = theirs.filter((h) => blobKind(h.blob) === 'prf');
  const list = [...mine, ...(serverCode ? [serverCode] : []), ...carried];
  return list.slice(0, MAX_ROOT_WRAPS).map(({ lookup, blob }) => ({ lookup, blob }));
}

/**
 * Whether a new device can sign in with what this browser holds (ADR 0037):
 * one of its passkeys, or the recovery code, kept on the server. `finish`:
 * something of this browser's is missing there, and one unlock here puts it.
 */
export function newDeviceReadiness(
  own: { passkeyLookups: Uint8Array[]; recoveryLookup: Uint8Array | null; hasRecovery: boolean },
  held: HeldWraps,
): { passkey: boolean; recovery: boolean; finish: boolean } {
  const kept = (lookup: Uint8Array) => held.blobs.some((b) => same(b.lookup, lookup));
  const passkey = own.passkeyLookups.some(kept);
  const serverCode = held.blobs.some((b) => blobKind(b.blob) === 'recovery');
  // A code whose lookup this browser never learned (made before ADR 0021)
  // counts as kept when the server has a code at all.
  const recovery = own.recoveryLookup ? kept(own.recoveryLookup) || serverCode : serverCode;
  const passkeyMissing = own.passkeyLookups.length > 0 && !passkey;
  const recoveryMissing = own.hasRecovery && !serverCode;
  return { passkey, recovery, finish: passkeyMissing || recoveryMissing };
}
