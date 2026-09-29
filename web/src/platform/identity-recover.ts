import { fromBase64Url, toBase64Url } from '@/model/base64';
import type { Identity } from '@/model/owner';
import { prfLookupPreimage, recoveryLookupPreimage } from '@/model/root-wraps';
import { userIdPreimage } from '@/model/statements';
import { generateSigningKey, idOf, sha256 } from './crypto';
import { directoryKeyFrom } from './directory-key';
import { identityOf, KEY, type Stored, signCert, type Unlock, UnlockFailed } from './identity-store';
import type { KeyValue } from './kv';
import { unlockWithPasskey } from './passkey';
import { type RootWrap, recoverySecret, unwrapRoot } from './root-wrap';

/**
 * A new browser recovering the owner (ADR 0021) with the recovery code or a
 * synced passkey: the secret gives the lookup key, `fetchBlob` asks the
 * server for the wrapped root kept under it, the secret opens it, and the
 * root certifies a new device key for this browser. The blob's user and root
 * key are checked, not trusted: the user must be the root's, and they are
 * the wrap's associated data, so a blob changed on the way does not open.
 */
export async function recoverIdentity(
  kv: KeyValue,
  how: Unlock,
  fetchBlob: (lookup: Uint8Array) => Promise<Uint8Array | null>,
  deviceName: string,
  nowSeconds: number,
): Promise<Identity> {
  let secret: Uint8Array;
  let lookup: Uint8Array;
  if ('passkey' in how) {
    const got = await unlockWithPasskey();
    secret = got.secret;
    lookup = await sha256(prfLookupPreimage(got.credentialId));
  } else {
    const typed = await recoverySecret(how.recoveryCode);
    if (!typed) throw new UnlockFailed('That is not a recovery code: check it for typos.');
    secret = typed;
    lookup = await sha256(recoveryLookupPreimage(secret));
  }
  const raw = await fetchBlob(lookup);
  if (!raw) {
    secret.fill(0);
    // Said as it is (ADR 0037): the server has nothing under it, and what
    // fixes that is one step on a device already signed in.
    throw new UnlockFailed(
      'passkey' in how
        ? 'This passkey is not set up for new devices yet. On a device where you use Tilder, open Settings, then Security, and choose Finish.'
        : 'Tilder keeps nothing for that recovery code. If you made a new code since, use that one; or, on a device where you use Tilder, open Settings, then Security, and choose Finish.',
    );
  }
  const blob = parseBlob(raw);
  const user = blob && (await idOf(userIdPreimage(blob.rootPublic)));
  // Extractable only for this call: the directory key is derived from it,
  // then it signs this browser's certificate and is dropped.
  const root =
    blob && user === blob.user ? await unwrapRoot(blob.wrap, secret, blob.user, blob.rootPublic, true) : null;
  secret.fill(0);
  if (!blob || !root) throw new UnlockFailed('That does not open the account kept here.');
  const device = await generateSigningKey();
  const stored: Stored = {
    v: 1,
    rootPublic: blob.rootPublic,
    user: blob.user,
    name: deviceName,
    device,
    cert: { statement: '', signature: new Uint8Array() },
    wraps: [blob.wrap],
    ...(blob.wrap.kind === 'recovery' ? { recoveryLookup: toBase64Url(lookup) } : {}),
    directoryKey: await directoryKeyFrom(root),
  };
  stored.cert = await signCert(root, stored, nowSeconds, deviceName);
  await kv.set(KEY, stored);
  return identityOf(stored);
}

/** A kept blob, or null when it is not what queueWraps writes. */
function parseBlob(raw: Uint8Array): { user: string; rootPublic: Uint8Array; wrap: RootWrap } | null {
  try {
    const v = JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
    const wrap = v.wrap as RootWrap | undefined;
    if (v.v !== 1 || typeof v.user !== 'string' || typeof v.rootPublic !== 'string' || !wrap) return null;
    if (wrap.v !== 1 || (wrap.kind !== 'recovery' && wrap.kind !== 'prf')) return null;
    if (typeof wrap.salt !== 'string' || typeof wrap.iv !== 'string' || typeof wrap.ct !== 'string') return null;
    const rootPublic = fromBase64Url(v.rootPublic);
    return rootPublic.length === 32 ? { user: v.user, rootPublic, wrap } : null;
  } catch {
    return null;
  }
}
