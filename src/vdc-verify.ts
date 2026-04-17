import { signingInputForVDC } from './canonicalize.js';
import { verifyEd25519 } from './internal/ed25519.js';
import { base64UrlToBytes } from './internal/base64.js';
import {
  ExpiredArtifactError,
  InvalidSignatureError,
  IssuerMismatchError,
  MalformedArtifactError,
  NotYetValidError,
  WrongArtifactTypeError,
} from './errors.js';
import type {
  VerifiableCredential,
  VerifyOptions,
  VerifyResult,
  CredentialClaims,
  ConsentClaims,
  ReceiptPayload,
  ParafeVDCType,
} from './types.js';

const DEFAULT_VDC_ISSUER_PREFIX = 'did:web:';

interface VDCVerifyArgs {
  expectedType: ParafeVDCType;
  now?: Date;
  clockToleranceSec?: number;
  expectedIssuer?: string;
}

async function verifyVDCInner(
  vdc: unknown,
  resolvedRawKey: Uint8Array,
  args: VDCVerifyArgs
): Promise<{ subject: Record<string, unknown>; issuer: string; issuanceDate?: string; expirationDate?: string }> {
  if (!vdc || typeof vdc !== 'object' || Array.isArray(vdc)) {
    throw new MalformedArtifactError('VDC must be a JSON object');
  }
  const v = vdc as Record<string, unknown>;
  if (!Array.isArray(v['@context'])) throw new MalformedArtifactError('VDC missing "@context" array', '@context');
  if (!Array.isArray(v['type'])) throw new MalformedArtifactError('VDC missing "type" array', 'type');
  const types = v['type'] as unknown[];
  if (types[0] !== 'VerifiableCredential') {
    throw new MalformedArtifactError(`VDC "type[0]" must be "VerifiableCredential", got "${String(types[0])}"`, 'type');
  }
  if (types[1] !== args.expectedType) {
    throw new WrongArtifactTypeError(args.expectedType, String(types[1] ?? 'unknown'));
  }
  if (typeof v['issuer'] !== 'string') throw new MalformedArtifactError('VDC missing "issuer" string', 'issuer');
  if (typeof v['credentialSubject'] !== 'object' || v['credentialSubject'] === null) {
    throw new MalformedArtifactError('VDC missing "credentialSubject" object', 'credentialSubject');
  }
  const proof = v['proof'] as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== 'object') throw new MalformedArtifactError('VDC missing "proof"', 'proof');
  if (proof['type'] !== 'Ed25519Signature2020') {
    throw new MalformedArtifactError(`Unsupported proof type "${String(proof['type'])}" — expected Ed25519Signature2020`, 'proof.type');
  }
  if (typeof proof['proofValue'] !== 'string') {
    throw new MalformedArtifactError('VDC proof.proofValue must be a string', 'proof.proofValue');
  }

  // Issuer check
  const issuer = v['issuer'] as string;
  if (args.expectedIssuer !== undefined) {
    if (issuer !== args.expectedIssuer) throw new IssuerMismatchError(args.expectedIssuer, issuer);
  } else if (!issuer.startsWith(DEFAULT_VDC_ISSUER_PREFIX)) {
    throw new IssuerMismatchError(`${DEFAULT_VDC_ISSUER_PREFIX}*`, issuer);
  }

  // Time checks (using issuance/expiration dates on the VDC itself).
  const now = args.now ?? new Date();
  const toleranceMs = (args.clockToleranceSec ?? 0) * 1000;
  if (typeof v['expirationDate'] === 'string') {
    const exp = new Date(v['expirationDate'] as string);
    if (!Number.isNaN(exp.getTime()) && exp.getTime() + toleranceMs < now.getTime()) {
      throw new ExpiredArtifactError(exp);
    }
  }
  if (typeof v['issuanceDate'] === 'string') {
    const iss = new Date(v['issuanceDate'] as string);
    if (!Number.isNaN(iss.getTime()) && iss.getTime() - toleranceMs > now.getTime()) {
      throw new NotYetValidError(iss);
    }
  }

  // Signature check — canonicalize without proof, verify proofValue (base64url).
  const message = new TextEncoder().encode(signingInputForVDC(v));
  const signature = base64UrlToBytes(proof['proofValue'] as string);
  const ok = await verifyEd25519(message, signature, resolvedRawKey);
  if (!ok) throw new InvalidSignatureError('VDC proof.proofValue signature verification failed');

  const out: { subject: Record<string, unknown>; issuer: string; issuanceDate?: string; expirationDate?: string } = {
    subject: v['credentialSubject'] as Record<string, unknown>,
    issuer,
  };
  if (typeof v['issuanceDate'] === 'string') out.issuanceDate = v['issuanceDate'] as string;
  if (typeof v['expirationDate'] === 'string') out.expirationDate = v['expirationDate'] as string;
  return out;
}

async function verifyAndMap<T>(
  vdc: unknown,
  opts: VerifyOptions,
  expectedType: ParafeVDCType,
  mapSubject: (subject: Record<string, unknown>, meta: { issuer: string; issuanceDate?: string; expirationDate?: string }) => T
): Promise<VerifyResult<T>> {
  const resolved = await opts.key.resolve();
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  try {
    const args: VDCVerifyArgs = { expectedType };
    if (opts.now !== undefined) args.now = opts.now;
    if (opts.clockToleranceSec !== undefined) args.clockToleranceSec = opts.clockToleranceSec;
    if (opts.expectedIssuer !== undefined) args.expectedIssuer = opts.expectedIssuer;
    const { subject, issuer, issuanceDate, expirationDate } = await verifyVDCInner(vdc, resolved.rawBytes, args);
    const meta: { issuer: string; issuanceDate?: string; expirationDate?: string } = { issuer };
    if (issuanceDate !== undefined) meta.issuanceDate = issuanceDate;
    if (expirationDate !== undefined) meta.expirationDate = expirationDate;
    return {
      valid: true,
      claims: mapSubject(subject, meta),
      format: 'vdc',
      keyId: resolved.keyId,
      verifiedAt,
    };
  } catch (err) {
    const error = err instanceof Error && 'code' in err
      ? (err as unknown as import('./errors.js').VerifyError)
      : new InvalidSignatureError(err instanceof Error ? err.message : String(err), err);
    return { valid: false, error, format: 'vdc', keyId: resolved.keyId, verifiedAt };
  }
}

export async function verifyCredentialVDC(
  vdc: unknown,
  opts: VerifyOptions
): Promise<VerifyResult<CredentialClaims>> {
  return verifyAndMap<CredentialClaims>(vdc, opts, 'ParafeIdentityCredential', (subject, meta) => {
    const sub = subject as Record<string, unknown>;
    return {
      sub: String(sub['agent_id'] ?? sub['id'] ?? ''),
      name: String(sub['agent_name'] ?? ''),
      owner: String(sub['owner'] ?? ''),
      identity_assurance: String(sub['identity_assurance'] ?? 'registered'),
      verification_tier: String(sub['verification_tier'] ?? 'unverified'),
      pub_key_thumbprint: String(sub['public_key_thumbprint'] ?? sub['pub_key_thumbprint'] ?? ''),
      ...(typeof sub['owner_type'] === 'string' ? { owner_type: sub['owner_type'] } : {}),
      ...(typeof sub['owner_id'] === 'string' ? { owner_id: sub['owner_id'] } : {}),
      iat: meta.issuanceDate ? Math.floor(new Date(meta.issuanceDate).getTime() / 1000) : 0,
      exp: meta.expirationDate ? Math.floor(new Date(meta.expirationDate).getTime() / 1000) : 0,
      iss: meta.issuer,
    };
  });
}

export async function verifyConsentVDC(
  vdc: unknown,
  opts: VerifyOptions
): Promise<VerifyResult<ConsentClaims>> {
  return verifyAndMap<ConsentClaims>(vdc, opts, 'ParafeConsentCredential', (subject, meta) => {
    const sub = subject as Record<string, unknown>;
    return {
      scope: String(sub['scope'] ?? ''),
      permissions: Array.isArray(sub['permissions']) ? (sub['permissions'] as string[]) : [],
      excluded: Array.isArray(sub['excluded']) ? (sub['excluded'] as string[]) : [],
      session_id: String(sub['session_id'] ?? ''),
      token_type: 'consent',
      authorization_modality: String(sub['authorization_modality'] ?? 'autonomous'),
      initiator_agent_id: (sub['initiator_agent_id'] as string | null) ?? null,
      target_agent_id: (sub['target_agent_id'] as string | null) ?? null,
      parent_token_id: (sub['parent_credential_id'] as string | null) ?? null,
      iat: meta.issuanceDate ? Math.floor(new Date(meta.issuanceDate).getTime() / 1000) : 0,
      exp: meta.expirationDate ? Math.floor(new Date(meta.expirationDate).getTime() / 1000) : 0,
      iss: meta.issuer,
    };
  });
}

export async function verifyReceiptVDC(
  vdc: unknown,
  opts: VerifyOptions
): Promise<VerifyResult<ReceiptPayload>> {
  return verifyAndMap<ReceiptPayload>(vdc, opts, 'ParafeReceiptCredential', (subject) => {
    return subject as unknown as ReceiptPayload;
  });
}

// Re-export the type for convenience
export type { VerifiableCredential };
