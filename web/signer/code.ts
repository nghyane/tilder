import { CODE_CHANNEL, FIELD_ID, SHOW_CHANNEL, TOKEN } from './code-fields';

/**
 * The recovery code where the console used to hold it (ADR 0054), in a
 * frame of this origin; the console hears only booleans. Three uses, by the
 * hash the console sets:
 * - `field`: the code typed for an admin action, sent to the signer over a
 *   channel only this origin reads;
 * - `field` and `confirm` (a new code's token): its last group typed back,
 *   checked here; the console hears whether it matches;
 * - `show` (a new code's token): the code itself, from the signer, with
 *   Copy, Download and Print.
 * The look is the console's own, measured there and passed in the hash (no
 * request carries it); the parent is answered only on its own origin.
 */
const allowed = (import.meta.env.VITE_TILDER_CONSOLE_ORIGINS ?? '')
  .split(',')
  .map((o: string) => o.trim())
  .filter(Boolean);

const params = new URLSearchParams(location.hash.slice(1));
const field = params.get('field') ?? '';
const tell = (message: Record<string, unknown>) => {
  for (const origin of allowed) window.parent.postMessage({ type: 'tilder-code', field, ...message }, origin);
};
const look = (el: HTMLElement, name: string, value: string | null) => {
  // Only plain values: a colour, a size, a font list; nothing that loads.
  if (value && value.length < 200 && !/url\(|[;{}<>]/i.test(value)) el.style.setProperty(name, value);
};

/** The code for a token, from the signer frame that holds it (a moment at most). */
function codeOf(token: string): Promise<string | null> {
  return new Promise((resolve) => {
    const channel = new BroadcastChannel(SHOW_CHANNEL);
    const nonce = crypto.randomUUID();
    const done = (code: string | null) => {
      clearTimeout(timer);
      channel.close();
      resolve(code);
    };
    const timer = setTimeout(() => done(null), 3_000);
    channel.onmessage = (event: MessageEvent) => {
      const m = event.data as { nonce?: unknown; code?: unknown } | null;
      if (m?.nonce === nonce && typeof m.code === 'string') done(m.code);
    };
    channel.postMessage({ want: token, nonce });
  });
}

function enter(input: HTMLInputElement, confirm: string | null) {
  input.hidden = false;
  look(input, 'color', params.get('fg'));
  look(input, 'background-color', params.get('bg'));
  look(input, 'border-color', params.get('border'));
  look(input, 'border-radius', params.get('radius'));
  look(input, 'font-family', params.get('font'));
  look(input, 'font-size', params.get('size'));
  input.addEventListener('focus', () => look(input, 'border-color', params.get('ring')));
  input.addEventListener('blur', () => look(input, 'border-color', params.get('border')));
  if (confirm) {
    input.placeholder = '';
    input.setAttribute('aria-label', 'Last group of your recovery code');
  }

  // Confirming a new code: the last group is checked here, against the code
  // the signer holds; nothing typed leaves this frame.
  let last: string | null = null;
  if (confirm) void codeOf(confirm).then((code) => (last = code?.split('-').at(-1) ?? null));
  const ok = () => (confirm ? last !== null && input.value.trim().toUpperCase() === last : input.value.trim() !== '');
  const channel = confirm ? null : new BroadcastChannel(CODE_CHANNEL);
  input.addEventListener('input', () => {
    channel?.postMessage({ field, code: input.value });
    tell({ filled: ok() });
  });
  input.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    channel?.postMessage({ field, code: input.value });
    if (ok()) tell({ submit: true });
  });
  window.addEventListener('message', (event) => {
    if (allowed.includes(event.origin) && (event.data as { type?: unknown })?.type === 'tilder-code-focus')
      input.focus();
  });
  tell({ ready: true });
}

async function show(section: HTMLElement, token: string) {
  const code = await codeOf(token);
  if (!code) {
    tell({ ready: true, missing: true });
    return;
  }
  section.hidden = false;
  look(section, 'color', params.get('fg'));
  look(section, 'font-family', params.get('font'));
  const list = document.getElementById('groups');
  for (const group of code.split('-')) {
    const li = document.createElement('li');
    li.textContent = group;
    list?.append(li);
  }
  const button = (id: string, run: () => void) => document.getElementById(id)?.addEventListener('click', run);
  button('copy', () => void navigator.clipboard?.writeText(code).catch(() => undefined));
  button('download', () => {
    const blob = new Blob(
      [`Tilder recovery code\n\n${code}\n\nKeep it offline. Anyone holding it can control your machines.\n`],
      {
        type: 'text/plain',
      },
    );
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'tilder-recovery-code.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1_000);
  });
  button('print', () => window.print());
  tell({ ready: true, height: Math.ceil(document.body.scrollHeight) });
}

function main() {
  if (window.top === window.self) return;
  // The page's own scheme: a frame whose scheme differs from its page's is
  // painted on an opaque canvas, a white block on a dark page.
  const scheme = params.get('scheme');
  if (scheme === 'dark' || scheme === 'light') document.documentElement.style.colorScheme = scheme;
  const input = document.getElementById('code') as HTMLInputElement | null;
  const section = document.getElementById('show');
  const showing = params.get('show');
  const confirm = params.get('confirm');
  if (showing && TOKEN.test(showing) && section && FIELD_ID.test(field)) void show(section, showing);
  else if (input && FIELD_ID.test(field) && (!confirm || TOKEN.test(confirm))) enter(input, confirm);
}

main();
