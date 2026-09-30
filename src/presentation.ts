import { jwtVerify, importJWK, calculateJwkThumbprint, decodeProtectedHeader, type JWK } from 'jose';
import { sha256 } from '@noble/hashes/sha256';
import { ProofInvalidError } from './errors.js';

const POP_TYP = 'parafe-pop+jwt';
const MAX_AGE_SECONDS = 5 * 60;

export interface PresentationProofOptions {
  /**
   * The initiator's registered public key as a JWK (from its DID document at
   * `<broker>/agents/<agent_id>/did.json`). If omitted, `brokerUrl` is used to
   * fetch that DID document.
   */
  initiatorKey?: JWK;
  /** Broker base URL, to fetch the initiator's DID document. Default https://api.parafe.ai. */
  brokerUrl?: string;
  /** If set, the proof's `aud` must equal it (your agent's DID). */
  expectedAudience?: string;
  /** If set, the proof's `mid` must equal it (the A2A message ID it came with). */
  expectedMessageId?: string;
  /** Override the current time. */
  now?: Date;
  fetch?: typeof fetch;
}

export interface PresentationProofResult {
  valid: boolean;
  /** The proof's jti: remember it for 5 minutes and refuse a repeat (replay). */
  jti?: string;
  mid?: string | null;
  error?: ProofInvalidError;
}

function b64u(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function initiatorJwk(sub: string, opts: PresentationProofOptions): Promise<JWK> {
  if (opts.initiatorKey) return opts.initiatorKey;
  const brokerUrl = (opts.brokerUrl ?? 'https://api.parafe.ai').replace(/\/$/, '');
  const fetchImpl = opts.fetch ?? (globalThis.fetch as typeof fetch);
  const res = await fetchImpl(`${brokerUrl}/agents/${encodeURIComponent(sub)}/did.json`);
  if (!res.ok) throw new ProofInvalidError(`Could not fetch the initiator's DID document (${res.status})`);
  const doc = (await res.json()) as { verificationMethod?: Array<{ publicKeyJwk?: JWK }> };
  const jwk = doc.verificationMethod?.[0]?.publicKeyJwk;
  if (!jwk) throw new ProofInvalidError("The initiator's DID document has no public key");
  return jwk;
}

/**
 * Check the presentation proof an initiator sends beside a key-bound consent
 * token (B7): signed by the key the token names (`cnf.jkt`), bound to this
 * token (`ath` = base64url SHA-256 of the token), to you (`aud`), fresh (`iat`
 * within 5 minutes). Verify the consent token itself first (`verifyConsent`)
 * and pass its claims. Replay protection is yours: refuse a `jti` you've seen.
 */
export async function verifyPresentationProof(
  proof: string,
  consentToken: string,
  consentClaims: { sub?: string; initiator_agent_id?: string | null; aud?: string; cnf?: { jkt: string } },
  opts: PresentationProofOptions = {}
): Promise<PresentationProofResult> {
  try {
    const jkt = consentClaims.cnf?.jkt;
    if (!jkt) throw new ProofInvalidError('The consent token is not key-bound (no cnf.jkt)');
    const sub = consentClaims.sub ?? consentClaims.initiator_agent_id;
    if (!sub) throw new ProofInvalidError('The consent token names no initiator');
    const jwk = await initiatorJwk(sub, opts);
    if ((await calculateJwkThumbprint(jwk)) !== jkt) throw new ProofInvalidError("The initiator's key does not match the token's cnf.jkt");
    const alg = jwk.kty === 'EC' ? 'ES256' : 'EdDSA';
    if (decodeProtectedHeader(proof).alg !== alg) throw new ProofInvalidError(`Proof must be ${alg}`);
    const now = opts.now ?? new Date();
    const { payload } = await jwtVerify(proof, await importJWK(jwk, alg), {
      typ: POP_TYP, algorithms: [alg], maxTokenAge: MAX_AGE_SECONDS, clockTolerance: 60, currentDate: now,
    });
    if (typeof payload.jti !== 'string' || payload.jti.length < 16) throw new ProofInvalidError('Proof needs a random jti');
    if (payload.ath !== b64u(sha256(new TextEncoder().encode(consentToken)))) throw new ProofInvalidError('Proof is not for this token (ath)');
    if (payload.aud !== consentClaims.aud) throw new ProofInvalidError("Proof aud is not the token's audience");
    if (opts.expectedAudience !== undefined && payload.aud !== opts.expectedAudience) throw new ProofInvalidError('Proof is for another audience');
    if (opts.expectedMessageId !== undefined && payload.mid !== opts.expectedMessageId) throw new ProofInvalidError('Proof is for another message (mid)');
    return { valid: true, jti: payload.jti, mid: (payload.mid as string) ?? null };
  } catch (err) {
    const error = err instanceof ProofInvalidError ? err : new ProofInvalidError(err instanceof Error ? err.message : String(err), err);
    return { valid: false, error };
  }
}
