export type VerifyErrorCode =
  | 'INVALID_SIGNATURE'
  | 'EXPIRED'
  | 'NOT_YET_VALID'
  | 'ISSUER_MISMATCH'
  | 'MALFORMED'
  | 'KEY_FETCH_FAILED'
  | 'KEY_PIN_MISMATCH'
  | 'FORMAT_UNKNOWN'
  | 'WRONG_ARTIFACT_TYPE'
  | 'KEY_NOT_FOUND'
  | 'PROOF_INVALID'
  | 'AP2_MANDATE_INVALID'
  | 'ISSUER_REVOKED'
  | 'NOT_IMPLEMENTED';

export class VerifyError extends Error {
  readonly code: VerifyErrorCode;
  override readonly cause?: unknown;

  constructor(code: VerifyErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'VerifyError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

export class InvalidSignatureError extends VerifyError {
  constructor(message = 'Signature verification failed', cause?: unknown) {
    super('INVALID_SIGNATURE', message, cause);
    this.name = 'InvalidSignatureError';
  }
}

export class ExpiredArtifactError extends VerifyError {
  readonly expiredAt: Date;
  constructor(expiredAt: Date, cause?: unknown) {
    super('EXPIRED', `Artifact expired at ${expiredAt.toISOString()}`, cause);
    this.name = 'ExpiredArtifactError';
    this.expiredAt = expiredAt;
  }
}

export class NotYetValidError extends VerifyError {
  readonly notBefore: Date;
  constructor(notBefore: Date, cause?: unknown) {
    super('NOT_YET_VALID', `Artifact not valid until ${notBefore.toISOString()}`, cause);
    this.name = 'NotYetValidError';
    this.notBefore = notBefore;
  }
}

export class IssuerMismatchError extends VerifyError {
  readonly expected: string;
  readonly actual: string;
  constructor(expected: string, actual: string) {
    super('ISSUER_MISMATCH', `Expected issuer "${expected}", got "${actual}"`);
    this.name = 'IssuerMismatchError';
    this.expected = expected;
    this.actual = actual;
  }
}

export class MalformedArtifactError extends VerifyError {
  readonly field?: string;
  constructor(message: string, field?: string, cause?: unknown) {
    super('MALFORMED', message, cause);
    this.name = 'MalformedArtifactError';
    if (field !== undefined) this.field = field;
  }
}

export class KeyFetchError extends VerifyError {
  readonly url: string;
  readonly status?: number;
  constructor(url: string, message: string, status?: number, cause?: unknown) {
    super('KEY_FETCH_FAILED', message, cause);
    this.name = 'KeyFetchError';
    this.url = url;
    if (status !== undefined) this.status = status;
  }
}

export class KeyPinningError extends VerifyError {
  readonly expected: string;
  readonly actual: string;
  constructor(field: 'keyId' | 'thumbprintSha256', expected: string, actual: string) {
    super('KEY_PIN_MISMATCH', `Key pin mismatch on ${field}: expected "${expected}", got "${actual}"`);
    this.name = 'KeyPinningError';
    this.expected = expected;
    this.actual = actual;
  }
}

export class FormatDetectionError extends VerifyError {
  constructor(message = 'Could not detect artifact format (expected a JWT string or a signed receipt)') {
    super('FORMAT_UNKNOWN', message);
    this.name = 'FormatDetectionError';
  }
}

export class WrongArtifactTypeError extends VerifyError {
  constructor(expected: string, actual: string) {
    super('WRONG_ARTIFACT_TYPE', `Expected ${expected}, got ${actual}`);
    this.name = 'WrongArtifactTypeError';
  }
}

export class NotImplementedError extends VerifyError {
  constructor(what: string) {
    super('NOT_IMPLEMENTED', `${what} is not yet implemented`);
    this.name = 'NotImplementedError';
  }
}

/**
 * The agent that signed the artifact was revoked (broker decision (f)). Its
 * receipts check out only with the broker's acknowledgment that it indexed them
 * before `revokedAt`.
 */
export class IssuerRevokedError extends VerifyError {
  readonly revokedAt: string;
  constructor(revokedAt: string, message?: string) {
    super('ISSUER_REVOKED', message ?? `The agent that signed this was revoked at ${revokedAt}. Pass the broker's acknowledgment of this receipt (acknowledgment, with key) to check it was filed before then.`);
    this.name = 'IssuerRevokedError';
    this.revokedAt = revokedAt;
  }
}

/** The artifact names a key (`kid`) the broker doesn't publish. */
export class KeyNotFoundError extends VerifyError {
  readonly kid: string;
  constructor(kid: string, message?: string) {
    super('KEY_NOT_FOUND', message ?? `The broker publishes no key with kid "${kid}"`);
    this.name = 'KeyNotFoundError';
    this.kid = kid;
  }
}

/** A proof of possession (presentation proof) did not check out. */
export class ProofInvalidError extends VerifyError {
  constructor(message: string, cause?: unknown) {
    super('PROOF_INVALID', message, cause);
    this.name = 'ProofInvalidError';
  }
}
