import type { PasskeyUnlock } from '@/platform/passkey';

/** The channel the signer's passkey button tells the signer on: same origin, same storage partition only. */
export const MADE_CHANNEL = 'tilder-signer-passkeys';

/** What the button says once the owner has made a passkey, or failed to. */
export type Made = { nonce: string } & ({ made: PasskeyUnlock } | { error: 'unsupported' | 'failed'; message: string });

/** How long a made passkey waits to be used, and how long a use waits for it to arrive. */
const KEEP_MS = 10 * 60_000;
const WAIT_MS = 10_000;

const NONCE = /^[A-Za-z0-9_-]{16,64}$/;

function parseMade(v: unknown): Made | null {
  const m = v as Partial<Record<string, unknown>> | null;
  if (typeof m?.nonce !== 'string' || !NONCE.test(m.nonce)) return null;
  if (m.error === 'unsupported' || m.error === 'failed')
    return { nonce: m.nonce, error: m.error, message: typeof m.message === 'string' ? m.message.slice(0, 300) : '' };
  const p = m.made as Partial<PasskeyUnlock> | undefined;
  if (typeof p?.credentialId !== 'string' || !/^[A-Za-z0-9_-]{1,512}$/.test(p.credentialId)) return null;
  if (Object.prototype.toString.call(p.secret) !== '[object Uint8Array]' || (p.secret as Uint8Array).length !== 32)
    return null;
  return { nonce: m.nonce, made: { credentialId: p.credentialId, secret: p.secret as Uint8Array } };
}

/**
 * The passkeys the signer's own button made (ADR 0048): WebAuthn makes one
 * in a cross-origin frame only on a click in that very frame, so the button
 * is a frame of this origin in the console's dialog, and hands the passkey
 * to this frame over a BroadcastChannel. The console only ever holds the
 * nonce that names it. Each is taken once.
 */
export function madePasskeys(channel: { onmessage: ((e: MessageEvent) => void) | null }, now = () => Date.now()) {
  const kept = new Map<string, { made: Made; at: number }>();
  const waiting = new Map<string, (m: Made) => void>();
  channel.onmessage = (e) => {
    const made = parseMade(e.data);
    if (!made) return;
    const waiter = waiting.get(made.nonce);
    if (waiter) {
      waiting.delete(made.nonce);
      waiter(made);
      return;
    }
    for (const [nonce, k] of kept) if (now() - k.at > KEEP_MS) kept.delete(nonce);
    kept.set(made.nonce, { made, at: now() });
  };

  /** The passkey made under `nonce`: waits a little for it to arrive; used once. */
  return function take(nonce: string): Promise<Made> {
    const k = kept.get(nonce);
    kept.delete(nonce);
    if (k && now() - k.at <= KEEP_MS) return Promise.resolve(k.made);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        waiting.delete(nonce);
        resolve({ nonce, error: 'failed', message: 'No passkey was made. Try again.' });
      }, WAIT_MS);
      waiting.set(nonce, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
    });
  };
}
