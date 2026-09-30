import { toBase64Url } from './base64';

/**
 * The signed statements, byte for byte as Go builds them
 * (go/internal/identity/statements.go); vectors/statements.json holds both
 * sides to the same text. Digests are passed in so this stays pure.
 */
const statement = (kind: string, fields: [string, string][]) =>
  `tilder/${kind}/v2\n${fields.map(([key, value]) => `${key}=${value}\n`).join('')}`;

export const deviceHelloStatement = (nonce: Uint8Array, key: Uint8Array) =>
  statement('device-hello', [
    ['nonce', toBase64Url(nonce)],
    ['key', toBase64Url(key)],
  ]);

export const agentHelloStatement = (nonce: Uint8Array, key: Uint8Array) =>
  statement('agent-hello', [
    ['nonce', toBase64Url(nonce)],
    ['key', toBase64Url(key)],
  ]);

export const offerStatement = (machineId: string, session: Uint8Array, sdpDigest: Uint8Array) =>
  statement('offer', [
    ['machine', machineId],
    ['session', toBase64Url(session)],
    ['sdp', toBase64Url(sdpDigest)],
  ]);

export const answerStatement = (
  machineId: string,
  session: Uint8Array,
  offerDigest: Uint8Array,
  answerDigest: Uint8Array,
) =>
  statement('answer', [
    ['machine', machineId],
    ['session', toBase64Url(session)],
    ['offer', toBase64Url(offerDigest)],
    ['sdp', toBase64Url(answerDigest)],
  ]);

/** What an id hashes: a domain tag, then the key (identity.MachineID / UserID). */
export const machineIdPreimage = (key: Uint8Array) => concat(new TextEncoder().encode('tilder/machine-id/v2\n'), key);
export const userIdPreimage = (key: Uint8Array) => concat(new TextEncoder().encode('tilder/user-id/v2\n'), key);

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** What the server stores for a join instead of the secret (core.HashJoinSecret). */
export const joinSecretPreimage = (secret: Uint8Array) =>
  concat(new TextEncoder().encode('tilder/join-secret/v2\n'), secret);

/**
 * The release the console was built with: its install scripts' hashes (ADR
 * 0020); a release from before Windows (ADR 0044) has no install.ps1.
 */
type Release = { version: string; installSha256: string; installPs1Sha256?: string };

/**
 * The one command the owner runs on a new machine (ADR 0020). It checks the
 * release's install script against the hash this console was built with
 * before running it, so the server cannot hand over another script; the
 * script in turn pins each agent binary. The token rides in the
 * environment, which other users cannot read, not in the command line; the
 * script's file comes from mktemp, so no one else on the machine can plant
 * it. macOS has shasum where Linux has sha256sum.
 */
export const joinCommand = (origin: string, token: string, release: Release, os: 'linux' | 'macos') => {
  const check = os === 'macos' ? 'shasum -a 256 -c' : 'sha256sum -c';
  const url = `${origin}/dist/${release.version}/install.sh`;
  return `f=$(mktemp) && curl -fsSLo "$f" ${url} && echo "${release.installSha256}  $f" | ${check} && TILDER_JOIN=${token} sh "$f" ${origin}`;
};

/**
 * The same command for PowerShell (ADR 0044), or undefined for a release
 * with no install.ps1. The script is held as bytes, checked, and run from
 * memory: nothing lands on disk for another process to swap, and a script
 * block is not subject to the execution policy that blocks .ps1 files by
 * default. 3072 is TLS 1.2, which Windows PowerShell 5.1 may not offer
 * unless asked.
 */
export const windowsJoinCommand = (origin: string, token: string, release: Release) => {
  if (!release.installPs1Sha256) return undefined;
  const url = `${origin}/dist/${release.version}/install.ps1`;
  return (
    `[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072; ` +
    `$b=(New-Object Net.WebClient).DownloadData('${url}'); ` +
    `if((-join([Security.Cryptography.SHA256]::Create().ComputeHash($b)|%{$_.ToString('x2')})) -ne '${release.installPs1Sha256}'){throw 'tilder: the install script does not match its checksum'}; ` +
    `$env:TILDER_JOIN='${token}'; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) '${origin}'`
  );
};

/**
 * A device's grant for one copy (ADR 0035): machine `dst` may pull `srcPath`
 * from machine `src` into `dstPath` until `notAfter` (Unix seconds, at most
 * a day on). Paths are the agent's name bytes; the nonce (16 bytes) names
 * the copy on both machines.
 */
export const transferStatement = (t: {
  user: string;
  device: Uint8Array;
  src: string;
  srcPath: Uint8Array;
  dst: string;
  dstPath: Uint8Array;
  notAfter: number;
  nonce: Uint8Array;
}) =>
  statement('transfer', [
    ['user', t.user],
    ['device', toBase64Url(t.device)],
    ['src_machine', t.src],
    ['src_path', toBase64Url(t.srcPath)],
    ['dst_machine', t.dst],
    ['dst_path', toBase64Url(t.dstPath)],
    ['not_after', String(t.notAfter)],
    ['nonce', toBase64Url(t.nonce)],
  ]);
