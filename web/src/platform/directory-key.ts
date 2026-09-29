/**
 * The directory key (ADR 0032): HKDF-SHA256 of the root, so every device of
 * the owner can derive the same key and the server, which never has the
 * root, cannot. It seals the owner's workspaces with AES-256-GCM. A device
 * keeps it as a key WebCrypto will not export; its raw bytes exist only
 * while the root is open, to be handed to a device being added.
 */

const INFO = new TextEncoder().encode('tilder/directory/v1');
/** An Ed25519 PKCS#8 key ends with its 32-byte seed. */
const SEED = 32;

/** The key's raw bytes, from a root opened extractable for this. The caller zeroes them once used. */
export async function directoryKeyBytes(root: CryptoKey): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', root));
  const seed = pkcs8.slice(pkcs8.length - SEED);
  pkcs8.fill(0);
  try {
    const ikm = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: INFO }, ikm, 256),
    );
  } finally {
    seed.fill(0);
  }
}

/** The key as this device keeps it: AES-GCM, never exportable. Zeroes `bytes`. */
export async function importDirectoryKey(bytes: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('raw', bytes as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  } finally {
    bytes.fill(0);
  }
}

/** The key straight from an extractable root, for this device. */
export async function directoryKeyFrom(root: CryptoKey): Promise<CryptoKey> {
  return importDirectoryKey(await directoryKeyBytes(root));
}
