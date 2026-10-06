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
  /**
   * What the device key signs, named (ADR 0048): the holder builds each
   * statement, so nothing asking it can have arbitrary bytes signed.
   */
  signHello(nonce: Uint8Array): Promise<Uint8Array>;
  signOffer(machineId: string, sessionId: Uint8Array, offerDigest: Uint8Array): Promise<Uint8Array>;
  signTransfer(t: {
    user: string;
    src: string;
    srcPath: Uint8Array;
    dst: string;
    dstPath: Uint8Array;
    notAfter: number;
    nonce: Uint8Array;
  }): Promise<{ statement: string; signature: Uint8Array }>;
  /**
   * Registers a machine with the device key (ADR 0053): only one that proved
   * its key with a join command this browser made (`auth` is that secret's
   * private half, `proof` the agent's), which the holder checks itself.
   */
  signRegistration(r: RegistrationIntent): Promise<{ statement: string; signature: Uint8Array }>;
};

export type RegistrationIntent = {
  user: string;
  machineId: string;
  machineKey: Uint8Array;
  at: number;
  auth: Uint8Array;
  proof: Uint8Array;
};
