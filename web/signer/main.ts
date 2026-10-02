import { localDeviceKeys } from '@/platform/device-keys';
import { indexedDbKeyValue } from '@/platform/kv';
import { passkeysFor } from '@/platform/passkey';
import { approvalsIn } from './approvals';
import { serveConsole } from './serve';

/**
 * keys.tilder.run (ADR 0048). The console origins that may use this signer
 * are fixed at build time; a page on any other origin that frames it gets
 * nothing. The device key lives in this origin's IndexedDB, where the
 * console's origin cannot read it.
 */
const allowed = (import.meta.env.VITE_TILDER_CONSOLE_ORIGINS ?? '')
  .split(',')
  .map((o: string) => o.trim())
  .filter(Boolean);

// Passkeys belong to the console's site, as they did before the signer.
for (const origin of allowed) passkeysFor(new URL(origin).hostname);
void indexedDbKeyValue().then((kv) => serveConsole(window, allowed, localDeviceKeys(kv), approvalsIn(kv), kv));
