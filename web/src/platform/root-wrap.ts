import { fromBase64Url, toBase64Url } from '@/model/base64';
import { formatRecoveryCode, parseRecoveryCode, SECRET_BYTES } from '@/model/recovery-code';
import { sha256, sign, verify } from './crypto';

/**
 * The root, wrapped (ADR 0004): only this blob is ever stored, here or on the
 * server. HKDF-SHA256 over a secret (the recovery code's bytes, later a
 * passkey's PRF output) gives a non-extractable AES-GCM key that wraps the
 * root as PKCS8; the root's public key and user are the associated data, so
 * a blob moved to another account does not open. Unwrapping goes straight to
 * a non-extractable signing key: the root's bytes never sit in JavaScript.
 */
export type RootWrap = {
  v: 1;
  kind: 'recovery' | 'prf';
  /** The passkey whose PRF output opens it (kind 'prf'). */
  credentialId?: string;
  salt: string;
  iv: string;
  ct: string;
};

const INFO = { recovery: 'tilder/root-wrap/v1/recovery', prf: 'tilder/root-wrap/v1/prf' } as const;
const bytes = (text: string) => new TextEncoder().encode(text);

// A recovery wrap's associated data is exactly what the first version wrote
// (no credential line): wraps already stored must keep opening. Only a
// passkey wrap adds its credential id.
const associated = (kind: RootWrap['kind'], user: string, rootPublic: Uint8Array, credentialId?: string) =>
  bytes(
    `tilder/root-wrap/v1\n${kind}\n${user}\n${toBase64Url(rootPublic)}\n${credentialId ? `${credentialId}\n` : ''}`,
  );

async function wrappingKey(secret: Uint8Array, salt: Uint8Array, kind: RootWrap['kind']): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: bytes(INFO[kind]) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
}

/** A new recovery code: the words to show once, and the secret they carry. */
export async function newRecoveryCode(): Promise<{ code: string; secret: Uint8Array }> {
  const secret = crypto.getRandomValues(new Uint8Array(SECRET_BYTES));
  return { code: formatRecoveryCode(secret, await sha256(secret)), secret };
}

/** The secret in a typed code, or null when it is malformed or mistyped (the checksum). */
export async function recoverySecret(typed: string): Promise<Uint8Array | null> {
  const parsed = parseRecoveryCode(typed);
  if (!parsed) return null;
  const sum = await sha256(parsed.secret);
  return sum[0] === parsed.checksum[0] && sum[1] === parsed.checksum[1] ? parsed.secret : null;
}

/**
 * Wraps an extractable root under secret: a recovery code's bytes, or a
 * passkey's PRF output (with its credential id). The caller drops the root
 * right after.
 */
export async function wrapRoot(
  root: CryptoKey,
  secret: Uint8Array,
  user: string,
  rootPublic: Uint8Array,
  passkey?: string,
): Promise<RootWrap> {
  const kind = passkey ? 'prf' : 'recovery';
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await wrappingKey(secret, salt, kind);
  const ct = await crypto.subtle.wrapKey('pkcs8', root, key, {
    name: 'AES-GCM',
    iv,
    additionalData: associated(kind, user, rootPublic, passkey),
  });
  return {
    v: 1,
    kind,
    ...(passkey ? { credentialId: passkey } : {}),
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ct: toBase64Url(new Uint8Array(ct)),
  };
}

/**
 * Opens a wrap as a non-extractable signing key, or null: a wrong secret, a
 * blob for another root or account, or one that was tampered with. The key
 * signs a test text that must verify against the root's known public key,
 * since WebCrypto cannot say which public key a non-extractable key has.
 */
export async function unwrapRoot(
  wrap: RootWrap,
  secret: Uint8Array,
  user: string,
  rootPublic: Uint8Array,
  // Only to wrap the root again under a new passkey or code, right away.
  extractable = false,
): Promise<CryptoKey | null> {
  try {
    const key = await wrappingKey(secret, fromBase64Url(wrap.salt), wrap.kind);
    const root = await crypto.subtle.unwrapKey(
      'pkcs8',
      fromBase64Url(wrap.ct) as BufferSource,
      key,
      {
        name: 'AES-GCM',
        iv: fromBase64Url(wrap.iv) as BufferSource,
        additionalData: associated(wrap.kind, user, rootPublic, wrap.credentialId),
      },
      'Ed25519',
      extractable,
      ['sign'],
    );
    const probe = `tilder/root-probe/v1\n${user}\n`;
    return (await verify(rootPublic, probe, await sign(root, probe))) ? root : null;
  } catch {
    return null;
  }
}
