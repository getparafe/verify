import { jwtVerify, decodeJwt, errors as joseErrors } from 'jose';
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
  const resolved = await opts.key.resolve();
  const verifiedAt = (opts.now ?? new Date()).toISOString();

  const verifyOpts: Parameters<typeof jwtVerify>[2] = {
    algorithms: ['EdDSA'],
    issuer: expectedIssuer,
  };
  if (opts.clockToleranceSec !== undefined) verifyOpts.clockTolerance = opts.clockToleranceSec;
  if (opts.now !== undefined) verifyOpts.currentDate = opts.now;

  try {
    const { payload } = await jwtVerify(token, resolved.josePublicKey, verifyOpts);
    validateClaims(payload as Record<string, unknown>);
    return {
      valid: true,
      claims: payload as unknown as T,
      format: 'jwt',
      keyId: resolved.keyId,
      verifiedAt,
    };
  } catch (err) {
    const error = coerceJoseError(err, token, expectedIssuer);
    return { valid: false, error, format: 'jwt', keyId: resolved.keyId, verifiedAt };
  }
}

function coerceJoseError(err: unknown, token: string, expectedIssuer: string): VerifyError {
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
    'sub', 'name', 'owner', 'identity_assurance', 'verification_tier', 'pub_key_thumbprint', 'iat', 'exp', 'iss',
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
