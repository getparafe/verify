import { jwtVerify, calculateJwkThumbprint, type JWK } from 'jose';
import { sha256 } from '@noble/hashes/sha256';
import { MalformedArtifactError, VerifyError, InvalidSignatureError } from './errors.js';
import { brokerKeyFor } from './internal/broker-key.js';
import { coerceJoseError } from './jwt-verify.js';
import type { IdentityCredentialClaims, VerifyOptions, VerifyResult } from './types.js';
import { splitChain, parseSegment, cnfJwk } from './ap2/sdjwt.js';
import type { Ap2MandateResult } from './ap2/types.js';

export const IDENTITY_VCT = 'https://parafe.ai/vct/agent-identity/1';

function b64u(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64u(s: string): string {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

/**
 * Verify the agent identity credential as an SD-JWT VC (issued since
 * 2026-09-30): `<issuer JWT>~<disclosure>~...~`. Checks the broker's ES256
 * signature (kid is a DID URL), typ `dc+sd-jwt`, vct, expiry, and that every
 * disclosure is one the issuer committed to (`_sd`). Returns the plain claims
 * plus the disclosed ones (`owner`, `owner_id` when presented). `cnf.jwk` is the
 * agent's registered key. A key-binding JWT, if appended, is not checked here.
 */
export async function verifyIdentityCredential(
  sdJwt: string,
  opts: VerifyOptions
): Promise<VerifyResult<IdentityCredentialClaims>> {
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  let keyId: string | undefined;
  try {
    const parts = sdJwt.split('~');
    const issuerJwt = parts[0];
    if (!issuerJwt || parts.length < 2) throw new MalformedArtifactError('Not an SD-JWT (expected <jwt>~<disclosures>~)');
    const verifyOpts: Parameters<typeof jwtVerify>[2] = { typ: 'dc+sd-jwt', algorithms: ['ES256'] };
    if (opts.expectedIssuer !== undefined) verifyOpts.issuer = opts.expectedIssuer;
    if (opts.clockToleranceSec !== undefined) verifyOpts.clockTolerance = opts.clockToleranceSec;
    if (opts.now !== undefined) verifyOpts.currentDate = opts.now;
    const { payload } = await jwtVerify(issuerJwt, async (header) => {
      const found = await brokerKeyFor(opts.key, header);
      keyId = found.keyId;
      return found.key;
    }, verifyOpts);
    if (payload.vct !== IDENTITY_VCT) throw new MalformedArtifactError(`Unexpected vct "${String(payload.vct)}"`, 'vct');
    if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') throw new MalformedArtifactError('Unsupported _sd_alg', '_sd_alg');
    const committed = new Set(Array.isArray(payload._sd) ? (payload._sd as string[]) : []);
    const claims: Record<string, unknown> = { ...payload };
    delete claims._sd;
    delete claims._sd_alg;
    // Disclosures sit between the issuer JWT and the last '~'; a trailing
    // segment without '~' after it would be a key-binding JWT.
    for (const d of parts.slice(1, -1)) {
      if (!d) continue;
      const digest = b64u(sha256(new TextEncoder().encode(d)));
      if (!committed.has(digest)) throw new InvalidSignatureError('A disclosure is not one the issuer signed');
      const decoded = JSON.parse(fromB64u(d)) as unknown;
      if (!Array.isArray(decoded) || decoded.length !== 3 || typeof decoded[1] !== 'string') throw new MalformedArtifactError('Malformed disclosure');
      if (decoded[1] in claims) throw new MalformedArtifactError(`Disclosure overrides claim "${decoded[1]}"`);
      claims[decoded[1]] = decoded[2];
    }
    return { valid: true, claims: claims as unknown as IdentityCredentialClaims, format: 'sd-jwt', keyId, verifiedAt };
  } catch (err) {
    if (err instanceof VerifyError && (err.code === 'KEY_FETCH_FAILED' || err.code === 'KEY_PIN_MISMATCH')) throw err;
    const error = err instanceof VerifyError ? err : coerceJoseError(err, sdJwt.split('~')[0] ?? '', opts.expectedIssuer ?? '');
    return { valid: false, error, format: 'sd-jwt', keyId, verifiedAt };
  }
}

/**
 * Does an AP2 open mandate's key belong to this Parafé agent? Compares the
 * RFC 7638 thumbprint of the credential's `cnf.jwk` (the agent's registered key)
 * with the mandate's agent key.
 *
 * `credential` is the verified claims from `verifyIdentityCredential`. `mandate`
 * is one of: a `verifyAp2Mandate` result (its `agentKey`); an AP2 mandate or
 * chain as presented (the last disclosed open mandate's `cnf.jwk`, else the
 * root's `cnf.jwk`); or decoded mandate content with `cnf.jwk`. A string is
 * NOT verified here: use `verifyAp2Mandate` for that.
 */
export async function matchAgentKey(
  credential: Pick<IdentityCredentialClaims, 'cnf'>,
  mandate: string | { cnf?: { jwk?: JWK } } | Pick<Ap2MandateResult, 'agentKey'>
): Promise<boolean> {
  let key: JWK | undefined;
  if (typeof mandate === 'string') {
    try {
      const segs = splitChain(mandate.endsWith('~') ? mandate : `${mandate}~`).map((raw, i) => parseSegment(raw, i));
      for (const s of segs) key = cnfJwk(s) ?? key;
    } catch {
      key = undefined;
    }
  } else if ('agentKey' in mandate) {
    key = mandate.agentKey;
  } else {
    key = (mandate as { cnf?: { jwk?: JWK } }).cnf?.jwk;
  }
  const a = credential.cnf?.jwk;
  if (!a || !key) return false;
  return (await calculateJwkThumbprint(a)) === (await calculateJwkThumbprint(key));
}
