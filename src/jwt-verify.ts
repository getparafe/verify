import { jwtVerify, decodeJwt, decodeProtectedHeader, errors as joseErrors } from 'jose';
import {
  ExpiredArtifactError,
  InvalidSignatureError,
  IssuerMismatchError,
  MalformedArtifactError,
  NotYetValidError,
  WrongArtifactTypeError,
  VerifyError,
} from './errors.js';
import type { CredentialClaims, ConsentClaims, VerifyOptions, VerifyResult } from './types.js';
import { brokerKeyFor } from './internal/broker-key.js';

const DEFAULT_JWT_ISSUER = 'parafe-trust-broker';

interface LowLevelVerifyOptions extends VerifyOptions {
  expectedTokenType?: 'consent';
}

async function verifyJwtInner<T>(
  token: string,
  opts: LowLevelVerifyOptions,
  validateClaims: (payload: Record<string, unknown>) => void
): Promise<VerifyResult<T>> {
  const expectedIssuer = opts.expectedIssuer ?? DEFAULT_JWT_ISSUER;
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  // The broker signs ES256 since 2026-09-30 (kid in the header). Tokens signed
  // with the retired Ed25519 key (EdDSA) are refused since 2026-10-09 (broker
  // S-72): that key only checks v1 receipts.
  let keyId: string | undefined;

  const verifyOpts: Parameters<typeof jwtVerify>[2] = {
    algorithms: ['ES256'],
    issuer: expectedIssuer,
  };
  if (opts.clockToleranceSec !== undefined) verifyOpts.clockTolerance = opts.clockToleranceSec;
  if (opts.now !== undefined) verifyOpts.currentDate = opts.now;

  try {
    let alg: unknown;
    try { alg = decodeProtectedHeader(token).alg; } catch { /* jose reports the malformed token below */ }
    if (alg === 'EdDSA') {
      throw new InvalidSignatureError('Signed with the retired Ed25519 key: Parafé refuses these tokens since 2026-10-09');
    }
    const { payload } = await jwtVerify(token, async (header) => {
      const found = await brokerKeyFor(opts.key, header);
      keyId = found.keyId;
      return found.key;
    }, verifyOpts);
    validateClaims(payload as Record<string, unknown>);
    return {
      valid: true,
      claims: payload as unknown as T,
      format: 'jwt',
      keyId,
      verifiedAt,
    };
  } catch (err) {
    if (err instanceof VerifyError && (err.code === 'KEY_FETCH_FAILED' || err.code === 'KEY_PIN_MISMATCH')) throw err;
    const error = coerceJoseError(err, token, expectedIssuer);
    return { valid: false, error, format: 'jwt', keyId, verifiedAt };
  }
}

export function coerceJoseError(err: unknown, token: string, expectedIssuer: string): VerifyError {
  if (err instanceof VerifyError) return err;
  if (err instanceof joseErrors.JWTExpired) {
    try {
      const decoded = decodeJwt(token);
      const exp = typeof decoded.exp === 'number' ? decoded.exp : 0;
      return new ExpiredArtifactError(new Date(exp * 1000), err);
    } catch {
      return new ExpiredArtifactError(new Date(0), err);
    }
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === 'iss') {
      try {
        const decoded = decodeJwt(token);
        return new IssuerMismatchError(expectedIssuer, String(decoded.iss ?? ''));
      } catch {
        return new IssuerMismatchError(expectedIssuer, '<unparseable>');
      }
    }
    if (err.claim === 'nbf') {
      try {
        const decoded = decodeJwt(token);
        const nbf = typeof decoded.nbf === 'number' ? decoded.nbf : 0;
        return new NotYetValidError(new Date(nbf * 1000), err);
      } catch {
        return new NotYetValidError(new Date(0), err);
      }
    }
    return new MalformedArtifactError(err.message, err.claim, err);
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return new InvalidSignatureError('JWS signature verification failed', err);
  }
  if (err instanceof joseErrors.JWSInvalid || err instanceof joseErrors.JWTInvalid) {
    return new MalformedArtifactError(err.message, undefined, err);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new InvalidSignatureError(message, err);
}

function assertCredentialShape(payload: Record<string, unknown>): void {
  if (payload.token_type === 'consent') {
    throw new WrongArtifactTypeError('credential', 'consent token');
  }
  const required: Array<keyof CredentialClaims> = [
    // No name claim: the agent's free-text principal name is `principal_name`
    // since broker SPEC-002 and `owner` before; neither is security-relevant.
    'sub', 'name', 'identity_assurance', 'verification_tier', 'pub_key_thumbprint', 'iat', 'exp', 'iss',
  ];
  for (const field of required) {
    if (payload[field] === undefined || payload[field] === null) {
      throw new MalformedArtifactError(`Credential missing required claim "${String(field)}"`, String(field));
    }
  }
  if (typeof payload.sub !== 'string') throw new MalformedArtifactError('Credential "sub" must be a string', 'sub');
  if (typeof payload.pub_key_thumbprint !== 'string') {
    throw new MalformedArtifactError('Credential "pub_key_thumbprint" must be a string', 'pub_key_thumbprint');
  }
}

function assertConsentShape(payload: Record<string, unknown>): void {
  if (payload.token_type !== 'consent') {
    throw new WrongArtifactTypeError('consent token', String(payload.token_type ?? 'unknown'));
  }
  if (typeof payload.scope !== 'string') throw new MalformedArtifactError('Consent "scope" must be a string', 'scope');
  if (!Array.isArray(payload.permissions)) {
    throw new MalformedArtifactError('Consent "permissions" must be an array', 'permissions');
  }
  if (typeof payload.session_id !== 'string') {
    throw new MalformedArtifactError('Consent "session_id" must be a string', 'session_id');
  }
  // Consent token v2 names the claim `exclusions`; older tokens `excluded`.
  // Report both, so no caller silently sees "nothing excluded".
  const exclusions = payload.exclusions ?? payload.excluded ?? [];
  if (!Array.isArray(exclusions)) throw new MalformedArtifactError('Consent "exclusions" must be an array', 'exclusions');
  payload.exclusions = exclusions;
  payload.excluded = payload.excluded ?? exclusions;
}

export async function verifyCredentialJWT(
  token: string,
  opts: VerifyOptions
): Promise<VerifyResult<CredentialClaims>> {
  return verifyJwtInner<CredentialClaims>(token, opts, assertCredentialShape);
}

export async function verifyConsentJWT(
  token: string,
  opts: VerifyOptions
): Promise<VerifyResult<ConsentClaims>> {
  return verifyJwtInner<ConsentClaims>(token, { ...opts, expectedTokenType: 'consent' }, assertConsentShape);
}
