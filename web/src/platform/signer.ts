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

/**
 * The console's side of the key signer (ADR 0048): a hidden iframe on the
 * signer's origin, a MessageChannel handed only to that origin, and the
 * device key's work asked for over it. The console never holds the key.
 */
class SignerUnavailable extends Error {}

const READY_MS = 10_000;
const CALL_MS = 30_000;
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

export function connectSigner(
  origin: string,
  askApproval: AskApproval,
  fetchBlob: FetchBlob,
  doc: Document = document,
): Promise<SignerKeys> {
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
      const keys = client(channel.port1, frame, win, askApproval, fetchBlob);
      // A signer that speaks another protocol is not used.
      void keys
        .call('version')
        .then((v) => (v === SIGNER_PROTOCOL ? resolve(keys) : fail('The key signer is a different version.')))
        .catch((e: Error) => fail(e.message));
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

function client(
  port: MessagePort,
  frame: HTMLIFrameElement,
  win: Window,
  askApproval: AskApproval,
  fetchBlob: FetchBlob,
) {
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
    // The identity code's own errors, as the console showed them before it moved.
    else if (reply.error === 'unlock-failed') wait.reject(new UnlockFailed(reply.message ?? 'That did not open it.'));
    else if (reply.error === 'passkey-unsupported') wait.reject(new PasskeyUnsupported(reply.message ?? 'no passkey'));
    else if (reply.error === 'failed' && reply.message) wait.reject(new Error(reply.message));
    else wait.reject(new Error(`The key signer refused: ${reply.error}.`));
  };
  const call = (op: string, args: Record<string, unknown> = {}, ms = CALL_MS) =>
    new Promise<unknown>((resolve, reject) => {
      const id = next++;
      const timer = win.setTimeout(() => {
        waiting.delete(id);
        reject(new SignerUnavailable('The key signer did not answer.'));
      }, ms);
      waiting.set(id, { resolve, reject, timer });
      port.postMessage({ ...args, id, op });
    });
  // A shell or a copy the signer will not sign yet: the owner is asked, and
  // it is tried once more; refused again, it fails with the owner's answer.
  const approved = async (op: string, args: Record<string, unknown>) => {
    try {
      return await call(op, args);
    } catch (error) {
      if (!(error instanceof NeedsApproval)) throw error;
      if (!(await askApproval(error.machines))) throw new Error('Not allowed on this machine from this browser.');
      return call(op, args);
    }
  };
  const key = (v: unknown): Uint8Array => {
    if (Object.prototype.toString.call(v) !== '[object Uint8Array]' || (v as Uint8Array).length !== 32)
      throw new SignerUnavailable('The key signer answered nonsense.');
    return v as Uint8Array;
  };
  const signature = (v: unknown): Uint8Array => {
    if (Object.prototype.toString.call(v) !== '[object Uint8Array]' || (v as Uint8Array).length !== 64)
      throw new SignerUnavailable('The key signer answered nonsense.');
    return v as Uint8Array;
  };
  return {
    call,
    identity: (op: string, args: Record<string, unknown> = {}) => call(op, args, IDENTITY_MS),
    create: async () => key(await call('create')),
    async publicKey() {
      const v = await call('public-key');
      return v === null ? null : key(v);
    },
    signHello: async (nonce: Uint8Array) => signature(await call('sign-hello', { nonce })),
    signOffer: async (machineId: string, sessionId: Uint8Array, offerDigest: Uint8Array) =>
      signature(await approved('sign-offer', { machineId, sessionId, offerDigest })),
    async signTransfer(t: TransferIntent) {
      const v = (await approved('sign-transfer', { t })) as { statement?: unknown; signature?: unknown } | null;
      if (typeof v?.statement !== 'string') throw new SignerUnavailable('The key signer answered nonsense.');
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
