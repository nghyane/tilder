import { fromBase64Url, toBase64Url } from '@/model/base64';
import type { Machine } from '@/model/machines';
import type { KeyValue } from './kv';
import { joinProofHolds } from './machine-trust';

/**
 * The private halves of the join secrets this browser made (ADR 0004), kept
 * so a machine can be confirmed after the Add machine dialog is closed: only
 * the console that made a secret can check a machine proved its key with it.
 * Each is dropped once its machine is confirmed, or after a week.
 */
const KEY = 'join-secrets';
const KEEP_MS = 7 * 24 * 3600 * 1000;

type Stored = { auth: string; madeAt: number }[];

async function load(kv: KeyValue, now: number): Promise<Stored> {
  const all = (await kv.get<Stored>(KEY)) ?? [];
  return all.filter((s) => now - s.madeAt < KEEP_MS);
}

export async function rememberJoin(kv: KeyValue, auth: Uint8Array, now: number): Promise<void> {
  await kv.set(KEY, [...(await load(kv, now)), { auth: toBase64Url(auth), madeAt: now }]);
}

/**
 * Whether `machine` proved its key with one of this browser's join secrets:
 * 'unknown' when none was made here, which is not a pass.
 */
export async function machineProof(
  kv: KeyValue,
  machine: Machine,
  now: number,
): Promise<'holds' | 'fails' | 'unknown'> {
  const secrets = await load(kv, now);
  if (secrets.length === 0 || !machine.joinProof) return 'unknown';
  const key = fromBase64Url(machine.publicKey);
  const proof = fromBase64Url(machine.joinProof);
  for (const s of secrets) {
    if (await joinProofHolds(fromBase64Url(s.auth), key, proof).catch(() => false)) return 'holds';
  }
  return 'fails';
}

/** Drops the secret `machine` proved its key with: it has done its one job. */
export async function forgetJoin(kv: KeyValue, machine: Machine, now: number): Promise<void> {
  if (!machine.joinProof) return;
  const key = fromBase64Url(machine.publicKey);
  const proof = fromBase64Url(machine.joinProof);
  const kept: Stored = [];
  for (const s of await load(kv, now)) {
    if (!(await joinProofHolds(fromBase64Url(s.auth), key, proof).catch(() => false))) kept.push(s);
  }
  await kv.set(KEY, kept);
}

/** The private half of the join secret `machine` proved its key with, or null when none of this browser's. */
export async function joinSecretFor(kv: KeyValue, machine: Machine, now: number): Promise<Uint8Array | null> {
  if (!machine.joinProof) return null;
  const key = fromBase64Url(machine.publicKey);
  const proof = fromBase64Url(machine.joinProof);
  for (const s of await load(kv, now)) {
    const auth = fromBase64Url(s.auth);
    if (await joinProofHolds(auth, key, proof).catch(() => false)) return auth;
  }
  return null;
}
