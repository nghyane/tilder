import { writeFileSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import { signerHeaders } from './signer/headers';

/**
 * The key signer (ADR 0048) builds apart from the console: its own origin
 * (keys.tilder.run; localhost:4175 in development), its own small bundle
 * with nothing of the console's interface in it. The console origins it
 * serves are fixed here at build time; a build without them serves no one.
 */
export default defineConfig(({ command }) => {
  const origins =
    process.env.VITE_TILDER_CONSOLE_ORIGINS ??
    (command === 'serve' ? 'http://localhost:5173,http://localhost:5391,http://localhost:4173' : '');
  return {
    root: fileURLToPath(new URL('./signer', import.meta.url)),
    resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
    define: { 'import.meta.env.VITE_TILDER_CONSOLE_ORIGINS': JSON.stringify(origins) },
    server: { port: 4175, strictPort: true },
    // A build for real consoles carries its Pages headers with it, so the
    // signer is never deployed without them (ADR 0048).
    plugins: [
      {
        name: 'signer-headers',
        apply: 'build',
        writeBundle(options) {
          const list = origins
            .split(',')
            .map((o) => o.trim())
            .filter(Boolean);
          if (list.length > 0 && options.dir) writeFileSync(`${options.dir}/_headers`, signerHeaders(list));
        },
      },
    ],
    build: {
      target: 'es2022',
      outDir: fileURLToPath(new URL('./dist-signer', import.meta.url)),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: fileURLToPath(new URL('./signer/index.html', import.meta.url)),
          confirm: fileURLToPath(new URL('./signer/confirm.html', import.meta.url)),
          code: fileURLToPath(new URL('./signer/code.html', import.meta.url)),
        },
      },
    },
  };
});
