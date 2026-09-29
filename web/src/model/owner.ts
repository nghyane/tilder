/**
 * This browser as the owner's device (ADR 0004): its key signs hellos and
 * offers, and the root's certificate for it rides along. The root itself is
 * not here: it is wrapped, and opened only for admin work.
 */
export type Identity = {
  /** The owner's root public key: what machines pin, and the user id's source. */
  rootPublic: Uint8Array;
  user: string;
  /** What the owner calls this browser ("Chrome on macOS"); its hash is in the cert. */
  name: string;
  devicePublic: Uint8Array;
  cert: { statement: string; signature: Uint8Array };
  /** Signs with the device key. */
  sign(text: string): Promise<Uint8Array>;
};
