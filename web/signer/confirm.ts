import { isMachineId } from '@/model/signer-protocol';
import { indexedDbKeyValue } from '@/platform/kv';
import { type Approvals, approvalsIn } from './approvals';

/**
 * The signer's own window (ADR 0048): the only place the owner allows the
 * console to open shells and copy files on a machine. It refuses to show
 * inside a frame (a page could cover it and steer a click; production also
 * sends frame-ancestors 'none'), and Allow waits a moment and a real click.
 */
const ARM_MS = 700;

const el = (id: string) => {
  const found = document.getElementById(id);
  if (!found) throw new Error(`no #${id}`);
  return found;
};

function main() {
  if (window.top !== window.self) {
    el('refused').hidden = false;
    return;
  }
  const params = new URLSearchParams(location.search);
  const policy = params.get('policy');
  if (policy === 'on' || policy === 'off') {
    showPolicy(policy === 'on');
    return;
  }
  const machines = params.getAll('machine');
  // The names are the console's word, shown as text only; the ids are what is allowed.
  const names = params.getAll('name').map((n) => n.slice(0, 64));
  if (machines.length === 0 || machines.length > 2 || !machines.every(isMachineId)) {
    el('refused').hidden = false;
    return;
  }
  el('name').textContent = machines.map((m, i) => names[i] || m).join(' and ');
  el('machine').textContent = machines.join(', ');
  el('confirm').hidden = false;
  const allow = el('allow') as HTMLButtonElement;
  const all = el('all') as HTMLButtonElement;
  setTimeout(() => {
    allow.disabled = false;
    all.disabled = false;
  }, ARM_MS);
  const decide = (button: HTMLButtonElement, grant: (a: Approvals) => Promise<void>) =>
    button.addEventListener('click', (event) => {
      if (!event.isTrusted || button.disabled) return;
      allow.disabled = true;
      all.disabled = true;
      void indexedDbKeyValue()
        .then((kv) => grant(approvalsIn(kv)))
        .then(() => window.close());
    });
  decide(allow, async (a) => {
    for (const m of machines) await a.allow(m, Date.now());
  });
  decide(all, (a) => a.allowAll(Date.now()));
  el('deny').addEventListener('click', () => window.close());
}

/** Turning "ask before opening shells" on or off: only here, in the owner's click (ADR 0048). */
function showPolicy(on: boolean) {
  el('policy-title').textContent = on ? 'Ask before opening shells?' : 'Stop asking before opening shells?';
  el('policy-text').textContent = on
    ? 'Shells and copies on a machine will wait for your OK in this window, once every 12 hours on this browser.'
    : 'Shells and copies will open without asking. Your key still never leaves this window’s keeping.';
  const yes = el('policy-yes') as HTMLButtonElement;
  yes.textContent = on ? 'Turn on' : 'Turn off';
  el('policy').hidden = false;
  setTimeout(() => {
    yes.disabled = false;
  }, ARM_MS);
  yes.addEventListener('click', (event) => {
    if (!event.isTrusted || yes.disabled) return;
    yes.disabled = true;
    void indexedDbKeyValue()
      .then((kv) => approvalsIn(kv).setAsking(on))
      .then(() => window.close());
  });
  el('policy-no').addEventListener('click', () => window.close());
}

main();
