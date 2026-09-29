import { type DirectoryDoc, parseDirectory } from '@/model/directory';

/**
 * The directory on the wire and on the server (ADR 0032): a format byte,
 * nonce(12), then AES-256-GCM of its JSON under the owner's directory key,
 * bound to the owner and the format by the associated data, so the server
 * can neither read it nor pass one owner's off as another's. The format byte
 * leaves room for a rotated key or another cipher without guessing (FxA's
 * scoped keys carry a key id for the same reason).
 */

const FORMAT = 1;
const NONCE = 12;
const TAG = 16;
const encoder = new TextEncoder();
const aad = (user: string) => encoder.encode(`tilder/directory/v1\n${FORMAT}\n${user}`);

export async function sealDirectory(key: CryptoKey, user: string, doc: DirectoryDoc): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad(user) },
      key,
      encoder.encode(JSON.stringify(doc)),
    ),
  );
  const out = new Uint8Array(1 + NONCE + ct.length);
  out[0] = FORMAT;
  out.set(nonce, 1);
  out.set(ct, 1 + NONCE);
  return out;
}

/**
 * Why a directory from the server is not taken: 'not-ours' (it does not
 * open under this owner's key and name, or says another revision than the
 * server does), 'stale' (older than one this device has seen: the server
 * replaying an old copy).
 */
type Refusal = 'not-ours' | 'stale';

/**
 * Opens a directory the server sent as revision `rev`, refusing one older
 * than `seen`, the newest revision this device has taken.
 */
export async function openDirectory(
  key: CryptoKey,
  user: string,
  blob: Uint8Array,
  rev: number,
  seen: number,
): Promise<DirectoryDoc | Refusal> {
  if (rev < seen) return 'stale';
  if (blob.length < 1 + NONCE + TAG || blob[0] !== FORMAT) return 'not-ours';
  let json: string;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: blob.subarray(1, 1 + NONCE) as BufferSource, additionalData: aad(user) },
      key,
      blob.subarray(1 + NONCE) as BufferSource,
    );
    json = new TextDecoder().decode(pt);
  } catch {
    return 'not-ours';
  }
  const doc = parseDirectory(json);
  // The device that wrote it said which revision it meant; a server that
  // stores it under another is not telling the truth about it.
  if (!doc || doc.rev !== rev) return 'not-ours';
  return doc;
}
