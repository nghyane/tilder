import { fromBase64Url, toBase64Url } from '@/model/base64';
import { sha256 } from './crypto';

/**
 * Passkeys that wrap the root (ADR 0004), after Bitwarden's PRF unlock: one
 * fixed salt, so a discoverable passkey works with no credential list; user
 * verification always required, because a security key's PRF output differs
 * with and without it; and the PRF result never leaves this function's
 * caller for the network (Bitwarden throws if it would). Nothing here talks
 * to a server: no one verifies these assertions but the wrap itself.
 */
export type PasskeyUnlock = { credentialId: string; secret: Uint8Array };

export class PasskeyUnsupported extends Error {}

/**
 * The name a passkey carries in the password manager (ADR 0038): the account,
 * never the device, so two accounts' passkeys can be told apart and one
 * account's passkeys look alike wherever they were made. The user id is a
 * hash of the root public key, so its start names the account and is no secret.
 */
export const passkeyName = (user: string) => `Tilder ${user.slice(0, 8)}`;

const SALT_TEXT = 'tilder/root-wrap/v1/prf';
const salt = () => sha256(SALT_TEXT);
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer } };
const prfOf = (credential: PublicKeyCredential): PrfResults =>
  (credential.getClientExtensionResults() as { prf?: PrfResults }).prf ?? {};

/**
 * The authenticators to offer first (WebAuthn hints): the one on this device
 * (Touch ID with iCloud Keychain, Windows Hello, a Chrome profile), then a
 * phone by QR. Without them a browser may lead with the QR even on a Mac.
 */
const HINTS = ['client-device', 'hybrid'];

/**
 * Whether this device has a passkey store the browser can use (Touch ID or
 * the like). False means the browser can only offer a phone or a security
 * key: on a Mac, iCloud Keychain is off, or the browser cannot reach it.
 */
export async function passkeyOnThisDevice(): Promise<boolean> {
  try {
    return (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.()) ?? false;
  } catch {
    return false;
  }
}

/** Whether this browser can make passkeys at all (PRF is known only after asking). */
export function passkeysAvailable(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create;
}

/**
 * Makes a passkey for this user and returns its PRF output. Some
 * authenticators give PRF only on assertion: then it asks for one more touch
 * (Bitwarden's second get). Throws PasskeyUnsupported when the passkey has
 * no PRF: the recovery code stays the only way back in.
 *
 * `existing` are the account's passkeys already wrapping the root. A password
 * manager keeps one passkey per site and user id, so a second one made in the
 * same manager would replace the first and leave its wrap opening nothing:
 * the manager is told to refuse instead (excludeCredentials).
 */
export async function createPasskey(user: string, existing: string[] = []): Promise<PasskeyUnlock> {
  const name = passkeyName(user);
  const credential = (await navigator.credentials
    .create({
      publicKey: {
        rp: { name: 'Tilder', id: location.hostname },
        user: { id: new TextEncoder().encode(user), name, displayName: name },
        excludeCredentials: existing.map((id) => ({
          type: 'public-key' as const,
          id: fromBase64Url(id) as BufferSource,
        })),
        challenge: random(32),
        // ES256 first: what iCloud Keychain and Google Password Manager make.
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -8 }, // Ed25519
          { type: 'public-key', alg: -257 }, // RS256, for Windows Hello
        ],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
        extensions: { prf: { eval: { first: await salt() } } } as AuthenticationExtensionsClientInputs,
        hints: HINTS,
      } as PublicKeyCredentialCreationOptions,
    })
    .catch((error: unknown) => {
      if (error instanceof DOMException && error.name === 'InvalidStateError') {
        throw new Error('This device already keeps a passkey for your account.');
      }
      throw error;
    })) as PublicKeyCredential | null;
  if (!credential) throw new PasskeyUnsupported('no passkey was made');
  const prf = prfOf(credential);
  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  if (prf.results?.first) return { credentialId, secret: new Uint8Array(prf.results.first) };
  if (prf.enabled === false) throw new PasskeyUnsupported('this passkey cannot protect a key');
  return unlockWithPasskey([credentialId]);
}

/**
 * Asks for a passkey (any of this site's, or one of `only`) and returns its
 * PRF output. Throws PasskeyUnsupported when the chosen passkey has no PRF.
 */
export async function unlockWithPasskey(only: string[] = []): Promise<PasskeyUnlock> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      rpId: location.hostname,
      challenge: random(32),
      userVerification: 'required',
      allowCredentials: only.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id) as BufferSource,
      })),
      extensions: { prf: { eval: { first: await salt() } } } as AuthenticationExtensionsClientInputs,
      hints: HINTS,
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  if (!credential) throw new PasskeyUnsupported('no passkey was chosen');
  const first = prfOf(credential).results?.first;
  if (!first) throw new PasskeyUnsupported('this passkey cannot protect a key');
  return { credentialId: toBase64Url(new Uint8Array(credential.rawId)), secret: new Uint8Array(first) };
}
