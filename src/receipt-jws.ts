import { jwtVerify } from 'jose';
import { MalformedArtifactError, VerifyError, InvalidSignatureError } from './errors.js';
import { brokerKeyFor } from './internal/broker-key.js';
import { coerceJoseError } from './jwt-verify.js';
import type { ReceiptV2Payload, VerifyOptions, VerifyResult } from './types.js';

export const RECEIPT_TYP = 'parafe-session-receipt+jwt';

/**
 * Verify a session receipt v2 (issued since 2026-09-30): a compact JWS signed by
 * the broker's ES256 key (`kid` in the header, typ parafe-session-receipt+jwt).
 * Returns the verified payload as claims. `opts.expectedIssuer`, when set, is
 * compared to `iss` (the broker DID, e.g. did:web:api.parafe.ai).
 */
export async function verifyReceiptJWS(
  jws: string,
  opts: VerifyOptions
): Promise<VerifyResult<ReceiptV2Payload>> {
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  let keyId: string | undefined;
  const verifyOpts: Parameters<typeof jwtVerify>[2] = { typ: RECEIPT_TYP, algorithms: ['ES256'] };
  if (opts.expectedIssuer !== undefined) verifyOpts.issuer = opts.expectedIssuer;
  if (opts.clockToleranceSec !== undefined) verifyOpts.clockTolerance = opts.clockToleranceSec;
  if (opts.now !== undefined) verifyOpts.currentDate = opts.now;
  try {
    const { payload } = await jwtVerify(jws, async (header) => {
      const found = await brokerKeyFor(opts.key, header);
      keyId = found.keyId;
      return found.key;
    }, verifyOpts);
    if (payload.ver !== 2) throw new MalformedArtifactError('Not a v2 session receipt (ver)', 'ver');
    for (const f of ['receipt_id', 'session_id', 'participants', 'consent_tokens', 'session'] as const) {
      if (payload[f] === undefined || payload[f] === null) throw new MalformedArtifactError(`Receipt missing "${f}"`, f);
    }
    return { valid: true, claims: payload as unknown as ReceiptV2Payload, format: 'receipt-jws', keyId, verifiedAt };
  } catch (err) {
    if (err instanceof VerifyError && (err.code === 'KEY_FETCH_FAILED' || err.code === 'KEY_PIN_MISMATCH')) throw err;
    const error = err instanceof VerifyError ? err : coerceJoseError(err, jws, opts.expectedIssuer ?? '');
    return { valid: false, error: error ?? new InvalidSignatureError(), format: 'receipt-jws', keyId, verifiedAt };
  }
}
