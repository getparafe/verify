import { FormatDetectionError } from './errors.js';
import { verifyCredentialJWT, verifyConsentJWT } from './jwt-verify.js';
import { verifyCredentialVDC, verifyConsentVDC, verifyReceiptVDC } from './vdc-verify.js';
import { verifySignedReceipt } from './receipt-verify.js';
import type {
  CredentialClaims,
  ConsentClaims,
  ReceiptPayload,
  VerifyOptions,
  VerifyResult,
  ArtifactFormat,
} from './types.js';

/** Detect whether an input is a JWT string, a VDC object, or a signed receipt object. */
export function detectFormat(input: unknown): ArtifactFormat | null {
  if (typeof input === 'string') {
    return input.split('.').length === 3 ? 'jwt' : null;
  }
  if (input && typeof input === 'object') {
    const obj = input as Record<string, unknown>;
    if (Array.isArray(obj['@context']) && Array.isArray(obj['type']) && obj['proof']) return 'vdc';
    if (typeof obj['signature'] === 'string' && typeof obj['receipt_id'] === 'string') return 'receipt';
  }
  return null;
}

function badFormat<T>(opts: VerifyOptions): VerifyResult<T> {
  return {
    valid: false,
    verifiedAt: (opts.now ?? new Date()).toISOString(),
    error: new FormatDetectionError(),
  };
}

export async function verifyCredential(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<CredentialClaims>> {
  const format = detectFormat(input);
  if (format === 'jwt') return verifyCredentialJWT(input as string, opts);
  if (format === 'vdc') return verifyCredentialVDC(input, opts);
  return badFormat<CredentialClaims>(opts);
}

export async function verifyConsent(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<ConsentClaims>> {
  const format = detectFormat(input);
  if (format === 'jwt') return verifyConsentJWT(input as string, opts);
  if (format === 'vdc') return verifyConsentVDC(input, opts);
  return badFormat<ConsentClaims>(opts);
}

export async function verifyReceipt(
  input: string | object,
  opts: VerifyOptions
): Promise<VerifyResult<ReceiptPayload>> {
  const format = detectFormat(input);
  if (format === 'receipt') return verifySignedReceipt(input, opts);
  if (format === 'vdc') return verifyReceiptVDC(input, opts);
  return badFormat<ReceiptPayload>(opts);
}
