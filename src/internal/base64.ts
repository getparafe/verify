/**
 * Base64 / base64url helpers. Standard lib only — works in Node 18+ and browsers.
 */

const STANDARD_B64_RE = /^[A-Za-z0-9+/]+=*$/;

export function assertValidBase64(s: string): void {
  if (!STANDARD_B64_RE.test(s)) {
    throw new Error('Invalid base64 encoding');
  }
}

/**
 * Convert base64 SPKI DER (as returned by Parafe's /public-key) to PEM wrapping.
 * Mirrors parafe-A2A-extension/src/verification.ts:258-267.
 */
export function derBase64ToPem(base64: string): string {
  assertValidBase64(base64);
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

export function base64ToBytes(base64: string): Uint8Array {
  assertValidBase64(base64);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number);
  return btoa(binary);
}

export function base64UrlToBytes(base64url: string): Uint8Array {
  const pad = base64url.length % 4 === 0 ? '' : '='.repeat(4 - (base64url.length % 4));
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return base64ToBytes(base64);
}

/**
 * Extract the 32-byte raw Ed25519 public key from an SPKI DER-encoded key.
 * The Ed25519 SPKI DER layout is a 12-byte ASN.1 header followed by the raw 32-byte key.
 */
export function rawEd25519FromSpkiDer(spkiDerBase64: string): Uint8Array {
  const der = base64ToBytes(spkiDerBase64);
  if (der.length < 32) {
    throw new Error(`SPKI DER too short (${der.length} bytes) to contain an Ed25519 key`);
  }
  return der.slice(der.length - 32);
}
