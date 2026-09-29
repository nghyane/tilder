import { fromBase64Url, toBase64Url } from './base64';

/**
 * The root's list of removed devices (ADR 0004), byte for byte as
 * go/internal/identity writes it: keys sorted by their bytes, no duplicates.
 * The set only grows; seq orders lists for syncing.
 */
export type RevocationList = { seq: number; devices: Uint8Array[] };

const compare = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
};

/** Sorted by bytes (identity.SortDevices), duplicates dropped. */
function sortDevices(devices: Uint8Array[]): Uint8Array[] {
  const sorted = [...devices].sort(compare);
  return sorted.filter((d, i) => i === 0 || compare(d, sorted[i - 1] as Uint8Array) !== 0);
}

export const revocationsStatement = (user: string, list: RevocationList, atSeconds: number) =>
  `tilder/revocations/v2\nuser=${user}\nseq=${list.seq}\ndevices=${sortDevices(list.devices)
    .map((d) => toBase64Url(d))
    .join(',')}\nat=${atSeconds}\n`;

/** The list in a statement that is exactly its canonical text for this user, or null. */
export function parseRevocations(text: string, user: string): RevocationList | null {
  const m =
    /^tilder\/revocations\/v2\nuser=([^\n]*)\nseq=(0|[1-9][0-9]{0,15})\ndevices=([^\n]*)\nat=(0|[1-9][0-9]{0,15})\n$/.exec(
      text,
    );
  if (!m || m[1] !== user) return null;
  try {
    const devices = m[3] ? (m[3].split(',').map((d) => fromBase64Url(d)) as Uint8Array[]) : [];
    if (devices.some((d) => d.length !== 32)) return null;
    const list = { seq: Number(m[2]), devices };
    return revocationsStatement(user, list, Number(m[4])) === text ? list : null;
  } catch {
    return null;
  }
}

export const hasDevice = (list: RevocationList, device: Uint8Array) =>
  list.devices.some((d) => compare(d, device) === 0);
