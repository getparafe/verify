export { canonicalize, signingInputForVDC, signingInputForReceipt } from './canonicalize.js';

export {
  createPublicKeySource,
  staticKey,
  pinKey,
  computeKeyThumbprint,
  type PublicKeySource,
  type PublicKeySourceOptions,
  type KeyPin,
  type ResolvedPublicKey,
} from './keys.js';

export {
  verifyCredentialJWT,
  verifyConsentJWT,
} from './jwt-verify.js';

export {
  verifyCredentialVDC,
  verifyConsentVDC,
  verifyReceiptVDC,
} from './vdc-verify.js';

export {
  verifySignedReceipt,
} from './receipt-verify.js';

export {
  verifyCredential,
  verifyConsent,
  verifyReceipt,
  detectFormat,
} from './verify.js';

export {
  VerifyError,
  InvalidSignatureError,
  ExpiredArtifactError,
  NotYetValidError,
  IssuerMismatchError,
  MalformedArtifactError,
  KeyFetchError,
  KeyPinningError,
  FormatDetectionError,
  WrongArtifactTypeError,
  NotImplementedError,
  type VerifyErrorCode,
} from './errors.js';

export type {
  VerifyOptions,
  VerifyResult,
  ArtifactFormat,
  CredentialClaims,
  ConsentClaims,
  ReceiptPayload,
  ReceiptParticipant,
  ReceiptConsentToken,
  IdentityAssurance,
  AuthorizationModality,
  VerifiableCredential,
  VDCProof,
  ParafeVDCType,
  PublicKeyResponse,
} from './types.js';
