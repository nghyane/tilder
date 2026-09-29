/**
 * The recovery code (ADR 0004): 144 random bits and a 16-bit checksum, as 32
 * Crockford base32 characters in 8 groups of 4. The checksum catches a typo
 * before anything is tried; 144 random bits need no stretching, even against
 * a server holding the wrapped root (Tailscale stretches its disablement
 * secret anyway; a random code gains nothing from it).
 */
export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ALPHABET = CROCKFORD;
export const SECRET_BYTES = 18;

/** Groups of four, dash-separated: what the owner writes down. */
export function formatRecoveryCode(secret: Uint8Array, checksum: Uint8Array): string {
  const chars = toBase32(concat(secret, checksum.subarray(0, 2)));
  return chars.match(/.{4}/g)?.join('-') ?? chars;
}

/**
 * Reads what the owner typed: case, dashes and spaces do not matter, and
 * I and L read as 1, O as 0 (Crockford). Returns the secret and the
 * checksum it carried, or null when it is not 32 base32 characters.
 */
export function parseRecoveryCode(typed: string): { secret: Uint8Array; checksum: Uint8Array } | null {
  const clean = typed.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
  if (clean.length !== 32 || [...clean].some((c) => !ALPHABET.includes(c))) return null;
  const bytes = fromBase32(clean);
  return { secret: bytes.subarray(0, SECRET_BYTES), checksum: bytes.subarray(SECRET_BYTES, SECRET_BYTES + 2) };
}

function toBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function fromBase32(text: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of text) {
    value = (value << 5) | ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
