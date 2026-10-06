/**
 * The recovery codes typed into this origin's code fields (ADR 0054), by
 * field: the field's page (/code, framed by the console) sends what is
 * typed over a channel only keys.tilder.run reads; the signer takes it
 * when the console names the field in place of a code. The console never
 * holds the code. Each is kept while its field may be tried again (a typo,
 * then Continue once more), forgotten as soon as it has opened what it was
 * typed for, and after a few minutes anyway; only the newest few are kept.
 */
export const CODE_CHANNEL = 'tilder-code-field';
/** Where the code page asks for a new code by its token, to show it (ADR 0054). */
export const SHOW_CHANNEL = 'tilder-code-show';
/** A token of the identity service (newToken): 16 random bytes. */
export const TOKEN = /^[A-Za-z0-9_-]{22}$/;
export const FIELD_ID = /^[A-Za-z0-9_-]{16,64}$/;
const KEEP_MS = 10 * 60_000;
/** Typing and asking race: the last keystroke may land a moment after the console's call. */
const WAIT_MS = 1_000;
const MAX_CODE = 200;
const MAX_FIELDS = 16;

export type CodeFields = {
  take(field: string): Promise<string | null>;
  /** The code opened what it was typed for: forgotten here and in every other signer frame of this browser. */
  used(field: string): void;
  stop(): void;
};

export function codeFields(now: () => number = Date.now): CodeFields {
  const typed = new Map<string, { code: string; at: number }>();
  const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel(CODE_CHANNEL) : null;
  if (channel)
    channel.onmessage = (event: MessageEvent) => {
      const m = event.data as { field?: unknown; code?: unknown; used?: unknown } | null;
      if (typeof m?.field !== 'string' || !FIELD_ID.test(m.field)) return;
      if (m.used === true) {
        typed.delete(m.field);
        return;
      }
      if (typeof m.code !== 'string' || m.code.length > MAX_CODE) return;
      typed.delete(m.field); // newest last, so the oldest goes first
      typed.set(m.field, { code: m.code, at: now() });
      while (typed.size > MAX_FIELDS) typed.delete(typed.keys().next().value as string);
    };
  const fresh = (field: string) => {
    const t = typed.get(field);
    return t && now() - t.at < KEEP_MS && t.code.trim() !== '' ? t.code : null;
  };
  return {
    async take(field) {
      let code = fresh(field);
      for (let waited = 0; code === null && waited < WAIT_MS; waited += 50) {
        await new Promise((r) => setTimeout(r, 50));
        code = fresh(field);
      }
      return code;
    },
    used(field) {
      typed.delete(field);
      channel?.postMessage({ field, used: true });
    },
    stop() {
      channel?.close();
    },
  };
}

/**
 * Answers the code page asking for a new code by its token (a new account's,
 * or a new code's): only pages of this origin hear the channel, and only the
 * signer that made the token knows it.
 */
export function showCodes(codeFor: (token: string) => string | null): () => void {
  if (typeof BroadcastChannel !== 'function') return () => undefined;
  const channel = new BroadcastChannel(SHOW_CHANNEL);
  channel.onmessage = (event: MessageEvent) => {
    const m = event.data as { want?: unknown; nonce?: unknown } | null;
    if (typeof m?.want !== 'string' || !TOKEN.test(m.want) || typeof m.nonce !== 'string' || m.nonce.length > 64)
      return;
    const code = codeFor(m.want);
    if (code) channel.postMessage({ nonce: m.nonce, code });
  };
  return () => channel.close();
}
