import { ShownError } from '@/model/problem';
import { deviceHelloStatement, offerStatement, transferStatement } from '@/model/statements';
import { generateSigningKey, sign } from './crypto';
import type { KeyValue } from './kv';

/** A copy's grant as the device signs it (ADR 0035); the device is the key's own. */
export type TransferIntent = Omit<Parameters<typeof transferStatement>[0], 'device'>;

/**
 * This browser's device key (ADR 0004), by what it signs and never by bytes
 * (ADR 0048): the console asks for a hello, an offer or a grant, and the
 * holder builds the statement itself. In production the holder is the key
 * signer on its own origin (platform/signer.ts); `localDeviceKeys` keeps it
 * here, for the in-page demo and tests.
 */
export type DeviceKeys = {
  /** A new key for this browser, in place of any; its public half. */
  create(): Promise<Uint8Array>;
  /** The key's public half, or null before one is made. */
  publicKey(): Promise<Uint8Array | null>;
  signHello(nonce: Uint8Array): Promise<Uint8Array>;
  signOffer(machineId: string, sessionId: Uint8Array, offerDigest: Uint8Array): Promise<Uint8Array>;
  /** The grant's statement and its signature: built by the holder, around its own key. */
  signTransfer(t: TransferIntent): Promise<{ statement: string; signature: Uint8Array }>;
  /** Forgets the key (starting over). */
  forget(): Promise<void>;
};

const KEY = 'device-key';

type Held = { publicKey: Uint8Array; privateKey: CryptoKey };

/**
 * Keeps a key made before the signer held keys (ADR 0048), handed over by
 * the console once: it becomes this holder's key, in place of any.
 */
export async function adoptDeviceKey(kv: KeyValue, held: Held): Promise<void> {
  await kv.set(KEY, held);
}

/** The key signs with `held`, or refuses: no key, no signature. */
async function keysSign(held: Held | null | undefined, text: string): Promise<Uint8Array> {
  if (!held) throw new ShownError('This browser has no device key.');
  return sign(held.privateKey, text);
}

/** A device key kept in `kv` of this origin: non-extractable, as the signer keeps it. */
export function localDeviceKeys(kv: KeyValue): DeviceKeys {
  const held = () => kv.get<Held | null>(KEY);
  return {
    async create() {
      const key = await generateSigningKey();
      await kv.set(KEY, key);
      return key.publicKey;
    },
    publicKey: async () => (await held())?.publicKey ?? null,
    async signHello(nonce) {
      const h = await held();
      if (!h) throw new ShownError('This browser has no device key.');
      return keysSign(h, deviceHelloStatement(nonce, h.publicKey));
    },
    signOffer: async (machineId, sessionId, offerDigest) =>
      keysSign(await held(), offerStatement(machineId, sessionId, offerDigest)),
    async signTransfer(t) {
      const h = await held();
      if (!h) throw new ShownError('This browser has no device key.');
      const statement = transferStatement({ ...t, device: h.publicKey });
      return { statement, signature: await keysSign(h, statement) };
    },
    async forget() {
      await kv.set(KEY, null);
    },
  };
}
