import { fromBase64Url, toBase64Url } from './base64';

/**
 * A device-cert (ADR 0004), byte for byte as go/internal/identity builds it.
 * The root signs it; the validity is inside the signature. This file only
 * builds and reads the text: signing and verifying are WebCrypto's.
 */
type DeviceCert = {
  user: string;
  root: Uint8Array;
  device: Uint8Array;
  nameHash: Uint8Array;
  revSeq: number;
  /** Unix seconds. */
  notBefore: number;
  notAfter: number;
};

const MAX_CERT_LIFETIME_S = 90 * 24 * 3600;
export const CLOCK_SKEW_S = 5 * 60;
const KEYS = ['user', 'root', 'device', 'name_hash', 'rev_seq', 'not_before', 'not_after'] as const;

export function deviceCertStatement(c: DeviceCert): string {
  const values = [
    c.user,
    toBase64Url(c.root),
    toBase64Url(c.device),
    toBase64Url(c.nameHash),
    String(c.revSeq),
    String(c.notBefore),
    String(c.notAfter),
  ];
  return `tilder/device-cert/v2\n${KEYS.map((key, i) => `${key}=${values[i]}\n`).join('')}`;
}

/** What a cert's name_hash hashes (identity.NameHash). */
export const deviceNamePreimage = (name: string) => new TextEncoder().encode(`tilder/device-name/v2\n${name}`);

const digits = /^(0|[1-9][0-9]{0,15})$/;

/**
 * Reads the exact canonical form or returns null: the kind line, the seven
 * fields in order, nothing else, and the text must rebuild to itself. The
 * user is checked against the root by the caller (it needs a hash).
 */
export function parseDeviceCert(text: string): DeviceCert | null {
  if (text.length > 1024 || !text.endsWith('\n')) return null;
  const lines = text.slice(0, -1).split('\n');
  if (lines.length !== KEYS.length + 1 || lines[0] !== 'tilder/device-cert/v2') return null;
  const v: Record<string, string> = {};
  for (const [i, key] of KEYS.entries()) {
    const line = lines[i + 1] ?? '';
    const eq = line.indexOf('=');
    if (eq < 0 || line.slice(0, eq) !== key) return null;
    v[key] = line.slice(eq + 1);
  }
  try {
    const numbers = [v.rev_seq, v.not_before, v.not_after];
    if (!numbers.every((n) => n !== undefined && digits.test(n))) return null;
    const cert: DeviceCert = {
      user: v.user ?? '',
      root: fromBase64Url(v.root ?? ''),
      device: fromBase64Url(v.device ?? ''),
      nameHash: fromBase64Url(v.name_hash ?? ''),
      revSeq: Number(v.rev_seq),
      notBefore: Number(v.not_before),
      notAfter: Number(v.not_after),
    };
    if (cert.root.length !== 32 || cert.device.length !== 32 || cert.nameHash.length !== 32) return null;
    return deviceCertStatement(cert) === text ? cert : null;
  } catch {
    return null;
  }
}

/** The time rules a verifier applies after the signature (identity.VerifyDeviceCert). */
export function certTimeProblem(c: DeviceCert, nowSeconds: number): 'lifetime' | 'not-yet' | 'expired' | null {
  const life = c.notAfter - c.notBefore;
  if (life <= 0 || life > MAX_CERT_LIFETIME_S) return 'lifetime';
  if (nowSeconds + CLOCK_SKEW_S < c.notBefore) return 'not-yet';
  if (nowSeconds - CLOCK_SKEW_S > c.notAfter) return 'expired';
  return null;
}
