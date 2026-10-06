import type { RegistrationIntent } from '@/model/owner';
import { ShownError } from '@/model/problem';
import {
  type ConsoleAnswer,
  SIGNER_CONNECT,
  SIGNER_PROTOCOL,
  SIGNER_READY,
  type SignerCallback,
  type SignerReply,
} from '@/model/signer-protocol';
import type { DeviceKeys, TransferIntent } from './device-keys';
import { UnlockFailed } from './identity-store';
import { PasskeyUnsupported } from './passkey';
import { onResume } from './resume';

/**
 * The console's side of the key signer (ADR 0048): a hidden iframe on the
 * signer's origin, a MessageChannel handed only to that origin, and the
 * device key's work asked for over it. The console never holds the key.
 *
 * The frame can die under the page: a browser left alone a long while ends
 * a background frame's process, and its port then answers nothing. Every
 * shell and copy needs a signature, so a dead signer left every terminal on
 * "reconnecting" until a reload. A call that gets no answer now replaces the
 * frame and is asked once more, and the page coming back checks the signer
 * first.
 */
export class SignerUnavailable extends Error {}

const READY_MS = 10_000;
const CALL_MS = 30_000;
/** A signature takes milliseconds; one this late means the frame is gone. */
const SIGN_MS = 5_000;
/** An identity step may wait on the owner at a passkey sheet. */
const IDENTITY_MS = 10 * 60_000;

/** The device key's holder on the signer's origin, and what only the signer can say. */
export type SignerKeys = DeviceKeys & {
  /** Identity work by name (identity-remote.ts); the root never leaves the signer. */
  identity(op: string, args?: Record<string, unknown>): Promise<unknown>;
  /** Whether shells and copies wait for the owner's OK (off unless turned on in the signer's window). */
  asking(): Promise<boolean>;
  close(): void;
};

/** Asks the owner to allow shells and copies on `machines` (ADR 0048); true once they may have. */
type AskApproval = (machines: string[]) => Promise<boolean>;

/** The server's wrapped root under a lookup key (a recovery): the signer asks, the console fetches. */
type FetchBlob = (lookup: Uint8Array) => Promise<Uint8Array | null>;

/** One frame of the signer and its port. */
export type Link = {
  call(op: string, args: Record<string, unknown>, ms: number): Promise<unknown>;
  close(): void;
};

export async function connectSigner(
  origin: string,
  askApproval: AskApproval,
  fetchBlob: FetchBlob,
  doc: Document = document,
  wake: (check: () => void) => () => void = onResume,
  open: (origin: string, fetchBlob: FetchBlob, doc: Document) => Promise<Link> = openSigner,
): Promise<SignerKeys> {
  // The first frame must come up: without a signer there is no key.
  let current: Promise<Link> = open(origin, fetchBlob, doc);
  await current;
  let replacing: Promise<Link> | null = null;
  let closed = false;
  /** A new frame in place of `dead`, one at a time however many calls found it dead. */
  const replace = (dead: Promise<Link>): Promise<Link> => {
    if (current !== dead) return current;
    replacing ??= (async () => {
      void dead.then(
        (l) => l.close(),
        () => undefined,
      );
      const next = open(origin, fetchBlob, doc);
      current = next;
      try {
        return await next;
      } finally {
        replacing = null;
      }
    })();
    return replacing;
  };
  /** A call that gets no answer replaces the frame; `retry` asks the new one once more. */
  const call = async (op: string, args: Record<string, unknown> = {}, ms = CALL_MS, retry = true) => {
    if (closed) throw new SignerUnavailable('closed');
    const used = current;
    try {
      return await (await used).call(op, args, ms);
    } catch (error) {
      if (!(error instanceof SignerUnavailable) || closed) throw error;
      const fresh = await replace(used);
      if (!retry) throw error;
      return fresh.call(op, args, ms);
    }
  };
  // Back from the background: the signer answers now, or is replaced before
  // a shell needs it.
  const stopWaking = wake(() => {
    void call('version', {}, SIGN_MS, false).catch(() => undefined);
  });

  // A shell or a copy the signer will not sign yet: the owner is asked, and
  // it is tried once more; refused again, it fails with the owner's answer.
  const approved = async (op: string, args: Record<string, unknown>) => {
    try {
      return await call(op, args, SIGN_MS);
    } catch (error) {
      if (!(error instanceof NeedsApproval)) throw error;
      if (!(await askApproval(error.machines))) throw new ShownError('Not allowed on this machine from this browser.');
      return call(op, args, SIGN_MS);
    }
  };
  const key = (v: unknown): Uint8Array => {
    if (Object.prototype.toString.call(v) !== '[object Uint8Array]' || (v as Uint8Array).length !== 32)
      throw new ShownError('The key signer answered nonsense.');
    return v as Uint8Array;
  };
  const signature = (v: unknown): Uint8Array => {
    if (Object.prototype.toString.call(v) !== '[object Uint8Array]' || (v as Uint8Array).length !== 64)
      throw new ShownError('The key signer answered nonsense.');
    return v as Uint8Array;
  };
  return {
    // Not asked again on a new frame: a passkey sheet the owner already saw
    // must not come back by itself.
    identity: (op: string, args: Record<string, unknown> = {}) => call(op, args, IDENTITY_MS, false),
    create: async () => key(await call('create')),
    async publicKey() {
      const v = await call('public-key');
      return v === null ? null : key(v);
    },
    signHello: async (nonce: Uint8Array) => signature(await call('sign-hello', { nonce }, SIGN_MS)),
    signOffer: async (machineId: string, sessionId: Uint8Array, offerDigest: Uint8Array) =>
      signature(await approved('sign-offer', { machineId, sessionId, offerDigest })),
    async signTransfer(t: TransferIntent) {
      const v = (await approved('sign-transfer', { t })) as { statement?: unknown; signature?: unknown } | null;
      if (typeof v?.statement !== 'string') throw new ShownError('The key signer answered nonsense.');
      return { statement: v.statement, signature: signature(v.signature) };
    },
    // Behind approvals, as a shell is: the secret its proof is checked
    // under is the console's own (ADR 0053).
    async signRegistration(r: RegistrationIntent) {
      const v = (await approved('sign-registration', { r })) as {
        statement?: unknown;
        signature?: unknown;
      } | null;
      if (typeof v?.statement !== 'string') throw new ShownError('The key signer answered nonsense.');
      return { statement: v.statement, signature: signature(v.signature) };
    },
    async forget() {
      await call('forget');
    },
    async asking() {
      const v = (await call('policy')) as { ask?: unknown } | null;
      return v?.ask === true;
    },
    close() {
      closed = true;
      stopWaking();
      void current.then(
        (l) => l.close(),
        () => undefined,
      );
    },
  };
}

/** A frame of the signer, ready and speaking this protocol; it fails if not within READY_MS. */
function openSigner(origin: string, fetchBlob: FetchBlob, doc: Document): Promise<Link> {
  const win = doc.defaultView;
  if (!win) return Promise.reject(new SignerUnavailable('no window'));
  const frame = doc.createElement('iframe');
  frame.src = `${origin}/`;
  frame.hidden = true;
  // The passkey sheet is the signer's: its origin holds the wraps (ADR 0048).
  frame.allow = 'publickey-credentials-get; publickey-credentials-create';
  frame.setAttribute('aria-hidden', 'true');

  return new Promise((resolve, reject) => {
    const fail = (why: string) => {
      win.clearTimeout(timer);
      win.removeEventListener('message', onReady);
      frame.remove();
      reject(new SignerUnavailable(why));
    };
    const timer = win.setTimeout(() => fail(`Can't reach tilder's key signer (${origin}).`), READY_MS);
    const onReady = (event: MessageEvent) => {
      if (event.origin !== origin || event.source !== frame.contentWindow) return;
      if ((event.data as { type?: unknown })?.type !== SIGNER_READY) return;
      win.clearTimeout(timer);
      win.removeEventListener('message', onReady);
      const channel = new MessageChannel();
      frame.contentWindow?.postMessage({ type: SIGNER_CONNECT }, origin, [channel.port2]);
      const link = linkOver(channel.port1, frame, win, fetchBlob);
      // A signer that speaks another protocol is not used.
      void link
        .call('version', {}, SIGN_MS)
        .then((v) => {
          if (v === SIGNER_PROTOCOL) resolve(link);
          else {
            link.close();
            reject(new SignerUnavailable('The key signer is a different version.'));
          }
        })
        .catch((e: Error) => {
          link.close();
          reject(e instanceof SignerUnavailable ? e : new SignerUnavailable(e.message));
        });
    };
    win.addEventListener('message', onReady);
    doc.body.append(frame);
  });
}

class NeedsApproval extends Error {
  constructor(readonly machines: string[]) {
    super('The owner has not allowed this machine here.');
  }
}

function linkOver(port: MessagePort, frame: HTMLIFrameElement, win: Window, fetchBlob: FetchBlob): Link {
  let next = 0;
  const waiting = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: number }>();
  port.onmessage = (event) => {
    const asked = event.data as SignerCallback | null;
    if (typeof asked?.cb === 'number') {
      if (asked.op !== 'fetch-blob') return;
      void fetchBlob(asked.lookup)
        .catch(() => null)
        .then((blob) => port.postMessage({ cb: asked.cb, blob } satisfies ConsoleAnswer));
      return;
    }
    const reply = event.data as SignerReply | null;
    const wait = typeof reply?.id === 'number' ? waiting.get(reply.id) : undefined;
    if (!reply || !wait) return;
    waiting.delete(reply.id);
    win.clearTimeout(wait.timer);
    if (reply.ok) wait.resolve(reply.value);
    else if (reply.error === 'needs-approval' && Array.isArray(reply.machines))
      wait.reject(new NeedsApproval(reply.machines.filter((m): m is string => typeof m === 'string')));
    else wait.reject(errorOf(reply));
  };
  return {
    call: (op, args, ms) =>
      new Promise<unknown>((resolve, reject) => {
        const id = next++;
        const timer = win.setTimeout(() => {
          waiting.delete(id);
          reject(new SignerUnavailable('The key signer did not answer.'));
        }, ms);
        waiting.set(id, { resolve, reject, timer });
        port.postMessage({ ...args, id, op });
      }),
    close() {
      for (const [, wait] of waiting) {
        win.clearTimeout(wait.timer);
        wait.reject(new SignerUnavailable('closed'));
      }
      waiting.clear();
      port.close();
      frame.remove();
    },
  };
}

/** A refusal from the signer as the console throws it: the identity code's own errors, as the console showed them before it moved. */
export function errorOf(reply: { error: string; message?: string; shown?: boolean }): Error {
  if (reply.error === 'unlock-failed') return new UnlockFailed(reply.message ?? 'That did not open it.');
  if (reply.error === 'passkey-unsupported') return new PasskeyUnsupported(reply.message ?? 'no passkey');
  if (reply.error === 'failed' && reply.message)
    return reply.shown === true ? new ShownError(reply.message) : new Error(reply.message);
  // A code, not words for the owner: they read a fixed sentence, the code goes to the log.
  return new Error(`the key signer refused: ${reply.error}`);
}
