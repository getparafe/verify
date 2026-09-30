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
  verifyAp2Mandate,
  verifyAp2Chain,
  ap2MandateReferences,
} from './ap2/mandate.js';
export { Ap2MandateError, type Ap2ErrorCode } from './ap2/errors.js';
export { merchantMatches, lineItemsSatisfied } from './ap2/constraints.js';
export {
  AP2_VCT,
  type Ap2MandateFamily,
  type Ap2TrustedIssuer,
  type Ap2MandateContext,
  type Ap2ChainOptions,
  type Ap2MandateOptions,
  type Ap2ChainResult,
  type Ap2ChainSegmentInfo,
  type Ap2MandateResult,
  type Ap2MandateReferences,
} from './ap2/types.js';

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
  MandateRef,
  PublicKeyResponse,
} from './types.js';
