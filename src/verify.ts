import { FormatDetectionError } from './errors.js';
import { verifyCredentialJWT, verifyConsentJWT } from './jwt-verify.js';
import { verifySignedReceipt } from './receipt-verify.js';
import { verifyReceiptJWS } from './receipt-jws.js';
import type {
  CredentialClaims,
  ConsentClaims,
  ReceiptPayload,
  ReceiptV2Payload,
  VerifyOptions,
  VerifyResult,
  ArtifactFormat,
} from './types.js';

function isSignedReceipt(obj: Record<string, unknown>): boolean {
  return typeof obj['signature'] === 'string' && typeof obj['receipt_id'] === 'string';
}

/**
 * The receipt as the broker signed it. `@getparafe/sdk` 0.3.2+ returns a
 * camelCase copy with the signed original under `issued`; accept either.
 */
function signedReceiptOf(input: unknown): Record<string, unknown> | null {
  if (!input || typeof input !== 'object') return null;
  const obj = input as Record<string, unknown>;
  if (isSignedReceipt(obj)) return obj;
  const issued = obj['issued'];
  if (issued && typeof issued === 'object' && isSignedReceipt(issued as Record<string, unknown>)) {
    return issued as Record<string, unknown>;
  }
  return null;
}

/** Detect whether an input is a JWT string or a signed receipt (as issued, or an SDK receipt with `issued`). */
export function detectFormat(input: unknown): ArtifactFormat | null {
  if (typeof input === 'string') {
    return input.split('.').length === 3 ? 'jwt' : null;
  }
  return signedReceiptOf(input) ? 'receipt' : null;
}

function badFormat<T>(input: unknown, opts: VerifyOptions): VerifyResult<T> {
  let message: string | undefined;
  if (input && typeof input === 'object') {
    const obj = input as Record<string, unknown>;
    if (Array.isArray(obj['@context']) && obj['proof']) {
      message = 'W3C Verifiable Credential (`*_vdc`) artifacts are no longer issued (removed 2026-09-29) or verified. Verify the JWT or signed-receipt form instead.';
    } else if (typeof obj['receiptId'] === 'string') {
      message = 'This is an @getparafe/sdk receipt without `issued` (SDK 0.3.1 or earlier). Pass the receipt from SDK 0.3.2+, or its `issued` field.';
    }
  }
  return {
    valid: false,
    verifiedAt: (opts.now ?? new Date()).toISOString(),
    error: new FormatDetectionError(message),
  };
}

export async function verifyCredential(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<CredentialClaims>> {
  const format = detectFormat(input);
  if (format === 'jwt') return verifyCredentialJWT(input as string, opts);
  return badFormat<CredentialClaims>(input, opts);
}

export async function verifyConsent(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<ConsentClaims>> {
  const format = detectFormat(input);
  if (format === 'jwt') return verifyConsentJWT(input as string, opts);
  return badFormat<ConsentClaims>(input, opts);
}

/**
 * A v2 receipt: the JWS string, or an object carrying it (@getparafe/sdk 0.4's
 * SessionReceipt, or the broker's /session/close response: `receipt` is the JWS).
 */
function receiptJwsOf(input: unknown): string | null {
  if (typeof input === 'string') return input.split('.').length === 3 ? input : null;
  if (input && typeof input === 'object') {
    const r = (input as Record<string, unknown>)['receipt'];
    if (typeof r === 'string' && r.split('.').length === 3) return r;
  }
  return null;
}

/**
 * Verify a session receipt: v2 (a JWS, since 2026-09-30) or v1 (signed JSON,
 * before; also inside an SDK 0.3.2+ receipt's `issued`). v2 claims come back as
 * `ReceiptV2Payload` (format 'receipt-jws'), v1 as `ReceiptPayload` ('receipt').
 */
export async function verifyReceipt(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<ReceiptPayload | ReceiptV2Payload>> {
  const jws = receiptJwsOf(input);
  if (jws) return verifyReceiptJWS(jws, opts);
  const receipt = signedReceiptOf(input);
  if (receipt) return verifySignedReceipt(receipt, opts);
  return badFormat<ReceiptPayload>(input, opts);
}
