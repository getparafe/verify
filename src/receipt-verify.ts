import { signingInputForReceipt } from './canonicalize.js';
import { verifyEd25519 } from './internal/ed25519.js';
import { base64ToBytes } from './internal/base64.js';
import {
  InvalidSignatureError,
  MalformedArtifactError,
  VerifyError,
} from './errors.js';
import type { ReceiptPayload, VerifyOptions, VerifyResult } from './types.js';

const REQUIRED_RECEIPT_FIELDS = [
  'receipt_id',
  'session_id',
  'handshake_id',
  'participants',
  'handshake',
  'consent_tokens',
  'session',
  'signed_by',
  'issued_at',
  'signature',
] as const;

export async function verifySignedReceipt(
  receipt: unknown,
  opts: VerifyOptions
): Promise<VerifyResult<ReceiptPayload>> {
  const resolved = await opts.key.resolve();
  const verifiedAt = (opts.now ?? new Date()).toISOString();

  try {
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      throw new MalformedArtifactError('Receipt must be a JSON object');
    }
    const r = receipt as Record<string, unknown>;
    for (const field of REQUIRED_RECEIPT_FIELDS) {
      if (r[field] === undefined || r[field] === null) {
        throw new MalformedArtifactError(`Receipt missing required field "${field}"`, field);
      }
    }
    if (typeof r['signature'] !== 'string') {
      throw new MalformedArtifactError('Receipt "signature" must be a string', 'signature');
    }

    // Strip signature + receipt_vdc (as the broker's /receipt/verify does),
    // then canonicalize and verify the Ed25519 signature.
    const message = new TextEncoder().encode(signingInputForReceipt(r));
    const signature = base64ToBytes(r['signature'] as string);
    const ok = await verifyEd25519(message, signature, resolved.rawBytes);
    if (!ok) throw new InvalidSignatureError('Receipt signature verification failed');

    // S-44: return only what the signature covers (plus the signature itself).
    // An unsigned receipt_vdc attached to a genuine receipt must not come back as
    // "verified" claims.
    const { receipt_vdc: _unsigned, ...signed } = r;
    return {
      valid: true,
      claims: signed as unknown as ReceiptPayload,
      format: 'receipt',
      keyId: resolved.keyId,
      verifiedAt,
    };
  } catch (err) {
    const error = err instanceof VerifyError
      ? err
      : new InvalidSignatureError(err instanceof Error ? err.message : String(err), err);
    return { valid: false, error, format: 'receipt', keyId: resolved.keyId, verifiedAt };
  }
}
