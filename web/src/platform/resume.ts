/**
 * Calls `wake` when the page comes back: shown again, restored from the
 * back-forward cache, or back online (ADR 0034). iOS suspends a PWA in the
 * background and its connections die with it; left to its backoff, the app
 * could sit up to 30 s on "reconnecting" after being opened (VibeTunnel has
 * no such handler and does exactly that).
 */
export function onResume(wake: () => void): () => void {
  if (typeof document === 'undefined' || typeof window === 'undefined') return () => undefined;
  const visible = () => {
    if (document.visibilityState === 'visible') wake();
  };
  const shown = (event: PageTransitionEvent) => {
    if (event.persisted) wake();
  };
  document.addEventListener('visibilitychange', visible);
  window.addEventListener('pageshow', shown);
  window.addEventListener('online', wake);
  return () => {
    document.removeEventListener('visibilitychange', visible);
    window.removeEventListener('pageshow', shown);
    window.removeEventListener('online', wake);
  };
}
