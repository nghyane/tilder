import { toBase64Url } from '@/model/base64';

const encoder = new TextEncoder();

export async function sha256(bytes: Uint8Array | string): Promise<Uint8Array> {
  const data = typeof bytes === 'string' ? encoder.encode(bytes) : bytes;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

/** A 16-byte SHA-256 prefix in base64url: the form machine and user ids take. */
export async function idOf(preimage: Uint8Array): Promise<string> {
  return toBase64Url((await sha256(preimage)).subarray(0, 16));
}

type SigningKey = { publicKey: Uint8Array; privateKey: CryptoKey };

/**
 * A new Ed25519 key whose private half can never leave WebCrypto: script on
 * the page (XSS included) can use it while the page is open, never copy it
 * out (ADR 0004).
 */
export async function generateSigningKey(): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { publicKey, privateKey: pair.privateKey };
}

export async function sign(key: CryptoKey, text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('Ed25519', key, encoder.encode(text)));
}

export async function verify(publicKey: Uint8Array, text: string, signature: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', publicKey as BufferSource, { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, signature as BufferSource, encoder.encode(text));
}
