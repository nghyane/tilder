import { passkeysOf } from '@/platform/identity';
import { KEY, type Stored } from '@/platform/identity-store';
import { indexedDbKeyValue } from '@/platform/kv';
import { createPasskey, PasskeyUnsupported, passkeysFor } from '@/platform/passkey';
import { MADE_CHANNEL, type Made } from './made-passkeys';

/**
 * The signer's passkey button (ADR 0048), framed inside the console's
 * dialog: WebAuthn makes a passkey for this origin only on a click in a
 * frame of it. The passkey goes to the signer's hidden frame over a
 * same-origin channel; the console is told only that it is made, under the
 * nonce it chose. Framed by any page but an allowed console, it shows
 * nothing.
 */
const allowed = (import.meta.env.VITE_TILDER_CONSOLE_ORIGINS ?? '')
  .split(',')
  .map((o: string) => o.trim())
  .filter(Boolean);
const LABELS = ['Create a passkey', 'Add a passkey'];

const q = new URLSearchParams(location.search);
const nonce = q.get('nonce') ?? '';
const user = q.get('user') ?? '';
const label = q.get('label') ?? '';
// Where supported, the page that framed this one, as the browser says it;
// elsewhere storage partitioning keeps a stranger's frame from the signer's.
const parentOrigin = location.ancestorOrigins?.[0] ?? document.referrer.replace(/(^https?:\/\/[^/]+).*$/, '$1');
const button = document.getElementById('make') as HTMLButtonElement;

const valid =
  window.parent !== window &&
  allowed.includes(parentOrigin) &&
  /^[A-Za-z0-9_-]{16,64}$/.test(nonce) &&
  /^[A-Za-z0-9_-]{1,64}$/.test(user) &&
  LABELS.includes(label);

if (valid) {
  passkeysFor(new URL(parentOrigin).hostname);
  if (q.get('theme') === 'dark') document.documentElement.classList.add('dark');
  if (q.get('variant') === 'outline') button.classList.add('outline');
  if (q.get('size') === 'sm') button.classList.add('sm');
  button.textContent = label;
  button.hidden = false;
  const box = button.getBoundingClientRect();
  window.parent.postMessage(
    { type: 'tilder-passkey-size', width: box.width + 6, height: box.height + 6 },
    parentOrigin,
  );

  const channel = new BroadcastChannel(MADE_CHANNEL);
  const tell = (made: Made) => {
    channel.postMessage(made);
    const said = 'made' in made ? { nonce } : { nonce, error: made.error, message: made.message };
    window.parent.postMessage({ type: 'tilder-passkey', ...said }, parentOrigin);
  };
  button.addEventListener('click', (event) => {
    if (!event.isTrusted || button.disabled) return;
    button.disabled = true;
    void (async () => {
      // The account's passkeys already here are excluded: a manager keeps
      // one per site and user, and a second would replace the first.
      const stored = await (await indexedDbKeyValue()).get<Stored>(KEY);
      return createPasskey(user, stored?.user === user ? passkeysOf(stored) : []);
    })()
      .then(
        (made) => tell({ nonce, made }),
        (error: unknown) =>
          tell({
            nonce,
            error: error instanceof PasskeyUnsupported ? 'unsupported' : 'failed',
            message: error instanceof Error && error.name !== 'NotAllowedError' ? error.message : '',
          }),
      )
      .finally(() => {
        button.disabled = false;
      });
  });
}
