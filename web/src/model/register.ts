import { toBase64Url } from './base64';

/** The root's registration of a machine key (ADR 0004), byte for byte as Go writes it. */
export const registerStatement = (user: string, machineId: string, machinePublic: Uint8Array, atSeconds: number) =>
  `tilder/register/v2\nuser=${user}\nmachine=${machineId}\nmachine_pub=${toBase64Url(machinePublic)}\nat=${atSeconds}\n`;

/** The `at` of a registration that is exactly the canonical text for these values, or null. */
export function registrationAt(
  text: string,
  user: string,
  machineId: string,
  machinePublic: Uint8Array,
): number | null {
  const at = /\nat=(0|[1-9][0-9]{0,15})\n$/.exec(text)?.[1];
  if (at === undefined) return null;
  return registerStatement(user, machineId, machinePublic, Number(at)) === text ? Number(at) : null;
}

/** A device's registration of a machine key (ADR 0053), byte for byte as Go writes it. */
export const deviceRegisterStatement = (
  user: string,
  machineId: string,
  machinePublic: Uint8Array,
  devicePublic: Uint8Array,
  atSeconds: number,
) =>
  `tilder/register-by-device/v2\nuser=${user}\nmachine=${machineId}\nmachine_pub=${toBase64Url(machinePublic)}\ndevice=${toBase64Url(devicePublic)}\nat=${atSeconds}\n`;

/** The `at` of a device's registration that is exactly the canonical text for these values, or null. */
export function deviceRegistrationAt(
  text: string,
  user: string,
  machineId: string,
  machinePublic: Uint8Array,
  devicePublic: Uint8Array,
): number | null {
  const at = /\nat=(0|[1-9][0-9]{0,15})\n$/.exec(text)?.[1];
  if (at === undefined) return null;
  return deviceRegisterStatement(user, machineId, machinePublic, devicePublic, Number(at)) === text ? Number(at) : null;
}
