/**
 * Mint AP2 Delegate SD-JWT chains in tests, shaped like the AP2 Python SDK's
 * output (the mandate is an array-element disclosure of `delegate_payload`).
 * Used for negative variants; the positive vectors come from the SDK itself.
 */
import { CompactSign, importJWK, type JWK } from 'jose';
import { createHash, randomBytes } from 'node:crypto';

const b64u = (s: string | Buffer) => Buffer.from(s).toString('base64url');
export const sha = (s: string) => createHash('sha256').update(s, 'ascii').digest('base64url');

export function disclosure(...parts: unknown[]): string {
  return b64u(JSON.stringify([randomBytes(16).toString('base64url'), ...parts]));
}

export async function sign(payload: object, key: JWK, header: Record<string, unknown> = {}): Promise<string> {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ES256', ...header })
    .sign(await importJWK(key, 'ES256'));
}

export interface MintedSegment {
  raw: string;
  /** Disclosures appended after the mandate's own disclosure. */
  extra: string[];
}

/**
 * One segment: `delegate_payload: [{...: digest(mandate)}]`. `extraDisclosures`
 * are appended to the segment (e.g. for array elements inside the mandate);
 * `withhold` leaves them out of the presented segment while their digests stay.
 */
export async function segment(opts: {
  mandate: Record<string, unknown>;
  key: JWK;
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  extraDisclosures?: string[];
  withhold?: string[];
}): Promise<string> {
  const d = disclosure(opts.mandate);
  const payload = { delegate_payload: [{ '...': sha(d) }], _sd_alg: 'sha-256', ...(opts.claims ?? {}) };
  const jwt = await sign(payload, opts.key, opts.header ?? {});
  const shown = [d, ...(opts.extraDisclosures ?? []).filter((x) => !(opts.withhold ?? []).includes(x))];
  return `${jwt}~${shown.join('~')}~`;
}

/** A KB-SD-JWT hop bound (sd_hash) to `prev` as presented. */
export async function hop(prev: string, mandate: Record<string, unknown>, key: JWK, opts: {
  aud?: string | null; nonce?: string | null; iat?: number; typ?: string; claims?: Record<string, unknown>; extraDisclosures?: string[]; withhold?: string[];
} = {}): Promise<string> {
  const terminal = !('cnf' in mandate);
  const claims: Record<string, unknown> = { iat: opts.iat ?? Math.floor(Date.now() / 1000), sd_hash: sha(prev) };
  if (opts.aud !== null) claims.aud = opts.aud ?? 'merchant';
  if (opts.nonce !== null) claims.nonce = opts.nonce ?? 'nonce-1';
  const seg: Parameters<typeof segment>[0] = {
    mandate, key,
    header: { typ: opts.typ ?? (terminal ? 'kb+sd-jwt' : 'kb+sd-jwt+kb') },
    claims: { ...claims, ...(opts.claims ?? {}) },
  };
  if (opts.extraDisclosures) seg.extraDisclosures = opts.extraDisclosures;
  if (opts.withhold) seg.withhold = opts.withhold;
  return segment(seg);
}

export const join = (...segs: string[]) => segs.map((s, i) => (i < segs.length - 1 ? s.slice(0, -1) : s)).join('~~');

export const pub = (k: JWK): JWK => { const { d: _d, ...p } = k; return p; };

export async function checkoutJwt(payload: Record<string, unknown>, key: JWK): Promise<string> {
  return sign(payload, key, { typ: 'JWT', kid: 'merchant-key-1' });
}
