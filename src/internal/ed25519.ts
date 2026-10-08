import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// The synchronous verify hashes with this. noble's verifyAsync uses WebCrypto
// (globalThis.crypto), which Node 18 doesn't have (P-52).
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/**
 * Verify a raw Ed25519 signature. Isomorphic — works in Node (18 on) and
 * browsers without polyfills or WebCrypto. `publicKey` is the 32-byte raw
 * public key (strip SPKI DER prefix with rawEd25519FromSpkiDer if you have a
 * DER-encoded key).
 */
export async function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    return ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
