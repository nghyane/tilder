import { ShownError } from '@/model/problem';
import type { IdentityRequest } from '@/model/signer-identity-ops';
import {
  parseRequest,
  SIGNER_CONNECT,
  SIGNER_PROTOCOL,
  SIGNER_READY,
  type SignerCallback,
  type SignerReply,
} from '@/model/signer-protocol';
import type { DeviceKeys } from '@/platform/device-keys';
import { UnlockFailed } from '@/platform/identity-store';
import type { KeyValue } from '@/platform/kv';
import { PasskeyUnsupported } from '@/platform/passkey';
import type { Approvals } from './approvals';
import { codeFields, showCodes } from './code-fields';
import { identityService } from './identity-service';

/**
 * The signer's side of the channel (ADR 0048): it tells the page that framed
 * it that it is ready, takes a port only from an allowed console origin, and
 * answers requests over that port with the device key it holds. The first
 * allowed port wins; later connects are ignored, so a second frame on the
 * page cannot take over.
 */
export function serveConsole(
  win: Window,
  allowed: readonly string[],
  keys: DeviceKeys,
  approvals: Approvals,
  kv: KeyValue,
): () => void {
  let port: MessagePort | null = null;
  // Asking the console for a wrapped root the server keeps (a recovery):
  // the signer reaches no network of its own.
  let nextCallback = 0;
  const callbacks = new Map<number, (blob: Uint8Array | null) => void>();
  const fetchBlob = (lookup: Uint8Array) =>
    new Promise<Uint8Array | null>((resolve) => {
      const cb = nextCallback++;
      callbacks.set(cb, resolve);
      port?.postMessage({ cb, op: 'fetch-blob', lookup } satisfies SignerCallback);
    });
  const fields = codeFields();
  const identity = identityService(kv, keys, fetchBlob, fields);
  const stopShowing = showCodes(identity.codeFor);

  const run = async (data: unknown): Promise<SignerReply> => {
    const request = parseRequest(data);
    const rid = typeof (data as { id?: unknown })?.id === 'number' ? (data as { id: number }).id : -1;
    if (!request) return { id: rid, ok: false, error: 'refused' };
    if (request.op.startsWith('id-')) {
      try {
        return { id: request.id, ok: true, value: await identity(request as IdentityRequest) };
      } catch (error) {
        return identityFailure(request.id, error);
      }
    }
    const ok = (value: unknown): SignerReply => ({ id: request.id, ok: true, value });
    const needs = (machines: string[]): SignerReply => ({
      id: request.id,
      ok: false,
      error: 'needs-approval',
      machines,
    });
    switch (request.op) {
      case 'version':
        return ok(SIGNER_PROTOCOL);
      case 'create':
        return ok(await keys.create());
      case 'public-key':
        return ok(await keys.publicKey());
      case 'forget':
        await keys.forget();
        return ok(null);
      case 'sign-hello':
        return ok(await keys.signHello(request.nonce));
      // With asking on, a shell or a copy on a machine the owner has not
      // allowed here in the last 12 hours is not signed: the console asks
      // the owner, in the signer's own window (ADR 0048).
      case 'policy':
        return ok({ ask: await approvals.asking() });
      case 'sign-offer':
        if ((await approvals.asking()) && !(await approvals.allowed(request.machineId)))
          return needs([request.machineId]);
        return ok(await keys.signOffer(request.machineId, request.sessionId, request.offerDigest));
      case 'sign-transfer': {
        const missing: string[] = [];
        if (await approvals.asking())
          for (const m of new Set([request.t.src, request.t.dst])) if (!(await approvals.allowed(m))) missing.push(m);
        if (missing.length > 0) return needs(missing);
        return ok(await keys.signTransfer(request.t));
      }
      // The join proof is checked, but the console holds the secret it is
      // checked under (it shows the command), so a page that runs script
      // there could make one. With asking on, a new machine is the owner's
      // to allow here, in the signer's window, as a shell is (ADR 0053).
      case 'sign-registration':
        if ((await approvals.asking()) && !(await approvals.allowed(request.r.machineId)))
          return needs([request.r.machineId]);
        return ok(await keys.signRegistration(request.r));
      default:
        return { id: rid, ok: false, error: 'refused' };
    }
  };

  const answer = (data: unknown) => {
    void run(data)
      .catch((): SignerReply => ({ id: (data as { id?: number })?.id ?? -1, ok: false, error: 'failed' }))
      .then((reply) => port?.postMessage(reply));
  };

  const onMessage = (event: MessageEvent) => {
    if (port || !allowed.includes(event.origin) || event.source !== win.parent) return;
    if ((event.data as { type?: unknown })?.type !== SIGNER_CONNECT) return;
    const [given] = event.ports;
    if (!given) return;
    port = given;
    port.onmessage = (e) => {
      const data = e.data as { cb?: unknown; blob?: unknown } | null;
      if (typeof data?.cb === 'number') {
        const done = callbacks.get(data.cb);
        callbacks.delete(data.cb);
        const blob = data.blob;
        const ok =
          Object.prototype.toString.call(blob) === '[object Uint8Array]' && (blob as Uint8Array).length <= 8192;
        done?.(ok ? (blob as Uint8Array) : null);
        return;
      }
      answer(e.data);
    };
  };
  win.addEventListener('message', onMessage);
  // Told to each allowed origin by name: never '*', so no other page that
  // framed the signer hears it is there.
  if (win.parent !== win) for (const origin of allowed) win.parent.postMessage({ type: SIGNER_READY }, origin);
  return () => {
    fields.stop();
    stopShowing();
    win.removeEventListener('message', onMessage);
    port?.close();
    port = null;
  };
}

/**
 * An identity step's failure as the console gets it: the identity code's own
 * messages, said to the owner as they are, and whether one was written for
 * them (`shown`, which a console from before ignores).
 */
export function identityFailure(id: number, error: unknown): SignerReply {
  const kind =
    error instanceof UnlockFailed
      ? 'unlock-failed'
      : error instanceof PasskeyUnsupported
        ? 'passkey-unsupported'
        : 'failed';
  return {
    id,
    ok: false,
    error: kind,
    message: error instanceof Error ? error.message : undefined,
    ...(error instanceof ShownError ? { shown: true } : {}),
  };
}
