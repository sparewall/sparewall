// SHA-512 crypt(3) ("$6$"), as shadow and the coordinator keep passwords:
// Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512", on the
// browser's own SHA-512 (WebCrypto). The CLI hashes on the admin's machine
// the same way (5000 rounds, a 16-character salt), so a password never
// leaves the browser, only its hash.

const ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const DEFAULT_ROUNDS = 5000;

async function sha512(...parts: Uint8Array[]): Promise<Uint8Array> {
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-512', all));
}

/** `bytes` repeated to `length` bytes. */
function stretch(bytes: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = bytes[i % bytes.length];
  return out;
}

/** The spec's byte groups for SHA-512, then the last byte alone. */
const GROUPS: [number, number, number][] = [];
for (let i = 0; i < 21; i++) {
  const a = (i * 22) % 63;
  GROUPS.push([a, (a + 21) % 63, (a + 42) % 63]);
}

/** The digest's 64 bytes in crypt's order and alphabet: 86 characters. */
function encodeDigest(c: Uint8Array): string {
  let out = '';
  const put = (b2: number, b1: number, b0: number, n: number) => {
    let w = (b2 << 16) | (b1 << 8) | b0;
    for (let i = 0; i < n; i++) {
      out += ALPHABET[w & 0x3f];
      w >>= 6;
    }
  };
  for (const [a, b, d] of GROUPS) put(c[a], c[b], c[d], 4);
  put(0, 0, c[63], 2);
  return out;
}

/** The hash of `password` with `salt` (at most 16 characters). */
export async function sha512Crypt(
  password: string,
  salt: string,
  rounds = DEFAULT_ROUNDS,
): Promise<string> {
  const enc = new TextEncoder();
  const p = enc.encode(password);
  const s = enc.encode(salt.slice(0, 16));

  const b = await sha512(p, s, p);
  const aParts: Uint8Array[] = [p, s, stretch(b, p.length)];
  for (let n = p.length; n > 0; n >>= 1) aParts.push(n & 1 ? b : p);
  const a = await sha512(...aParts);

  const dp = await sha512(...Array.from({ length: p.length }, () => p));
  const pBytes = stretch(dp, p.length);
  const ds = await sha512(...Array.from({ length: 16 + a[0] }, () => s));
  const sBytes = stretch(ds, s.length);

  let c = a;
  for (let r = 0; r < rounds; r++) {
    const parts: Uint8Array[] = [r & 1 ? pBytes : c];
    if (r % 3) parts.push(sBytes);
    if (r % 7) parts.push(pBytes);
    parts.push(r & 1 ? c : pBytes);
    c = await sha512(...parts);
  }

  const prefix = rounds === DEFAULT_ROUNDS ? '$6$' : `$6$rounds=${rounds}$`;
  return `${prefix}${salt.slice(0, 16)}$${encodeDigest(c)}`;
}

/** A random 16-character salt, as the CLI makes (12 random bytes). */
export function newSalt(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (x) => ALPHABET[x & 0x3f]).join('');
}

/** `password` hashed with a new salt, ready for `Auth.SetUser`. */
export function hashPassword(password: string): Promise<string> {
  return sha512Crypt(password, newSalt());
}
