/**
 * What a machine says it runs (ADR 0019), as the server clamped it. Shown,
 * never used to decide anything: the server could lie about it.
 */
export type HostInfo = {
  os: string;
  osVersion: string;
  distro: string;
  distroVersion: string;
  arch: string;
  agentVersion: string;
  container: string;
  /** Unix seconds; uptime is worked out from it. */
  bootTime: number;
};

/**
 * A machine as the console lists it. `publicKey` (base64url) is what its
 * signed answers are checked against. The full model arrives with P5.
 */
export type Machine = {
  id: string;
  /** The owner's name for it (ADR 0052), else the name it gives itself. */
  name: string;
  /** The name it gives itself (its hostname), when the owner named it otherwise. */
  hostname?: string;
  publicKey: string;
  online: boolean;
  host?: HostInfo;
  /** What the agent proved at join (base64url), for the console holding the secret. */
  joinProof?: string;
  registration?: { statement: string; signature: Uint8Array };
  /**
   * The owner's root registered this machine's key, checked here (ADR 0004).
   * Only a confirmed machine's key is trusted: an unconfirmed one may be a
   * machine the server made up.
   */
  confirmed?: boolean;
};
