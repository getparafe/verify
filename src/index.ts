export { canonicalize, signingInputForReceipt } from './canonicalize.js';

export {
  createPublicKeySource,
  staticKey,
  pinKey,
  computeKeyThumbprint,
  staticJwks,
  type Jwks,
  type ResolvedJwk,
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
  verifySignedReceipt,
} from './receipt-verify.js';

export { verifyReceiptJWS, RECEIPT_TYP } from './receipt-jws.js';
export { verifyPresentationProof, type PresentationProofOptions, type PresentationProofResult } from './presentation.js';
export { verifyIdentityCredential, matchAgentKey, IDENTITY_VCT } from './identity-credential.js';
export {
  verifyActionReceipt,
  verifyIndexAck,
  verifySessionIndex,
  receiptHash,
  consentRef,
  entryHash,
  ACTION_RECEIPT_TYP,
  INDEX_ACK_TYP,
  ACTION_ERROR_CODES,
  type ActionReceiptOptions,
  type SessionIndexOptions,
  type SessionIndexResult,
} from './action-receipt.js';

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
  KeyNotFoundError,
  ProofInvalidError,
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
  ReceiptV2Payload,
  ReceiptV2ConsentToken,
  ReceiptV2Action,
  ActionReceiptClaims,
  IndexAckClaims,
  IdentityCredentialClaims,
  IdentityAssurance,
  AuthorizationModality,
  PublicKeyResponse,
} from './types.js';
