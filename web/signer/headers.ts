/**
 * The key signer's headers (ADR 0048), for its own Pages project. Only the
 * consoles it serves may frame its page; nothing may
 * frame its confirm window. It loads nothing but its own files and reaches
 * no network: a recovery's blob is fetched by the console. The confirm
 * window's frame-ancestors 'none' is a second policy beside the shared one,
 * so both hold.
 */
export function signerHeaders(consoleOrigins: readonly string[]): string {
  if (consoleOrigins.length === 0) throw new Error('the key signer must serve at least one console origin');
  for (const o of consoleOrigins)
    if (new URL(o).origin !== o || !o.startsWith('https://'))
      throw new Error(`a console origin must be a bare https: origin, not ${o}`);
  const csp = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    // Every path, not only the page: Pages answers an unknown one with it.
    `frame-ancestors ${consoleOrigins.join(' ')}`,
  ].join('; ');
  const framedBy = (paths: string[], ancestors: string) =>
    paths.flatMap((p) => [p, `  Content-Security-Policy: frame-ancestors ${ancestors}`]);
  return [
    '/*',
    `  Content-Security-Policy: ${csp}`,
    '  Strict-Transport-Security: max-age=31536000; includeSubDomains',
    '  X-Content-Type-Options: nosniff',
    '  Referrer-Policy: no-referrer',
    '  Permissions-Policy: camera=(), microphone=(), geolocation=()',
    ...framedBy(['/confirm', '/confirm.html'], "'none'"),
    '/assets/*',
    '  Cache-Control: public, max-age=31536000, immutable',
    '',
  ].join('\n');
}
