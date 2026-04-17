import type { VerifyError } from './errors.js';
import type { PublicKeySource } from './keys.js';

export type ArtifactFormat = 'jwt' | 'vdc' | 'receipt';

export interface VerifyResult<T> {
  valid: boolean;
  claims?: T;
  format?: ArtifactFormat;
  keyId?: string;
  verifiedAt: string;
  error?: VerifyError;
}

export interface VerifyOptions {
  key: PublicKeySource;
  /** Override issuer check (default: 'parafe-trust-broker' for JWTs, 'did:web:api.parafe.ai' for VDCs) */
  expectedIssuer?: string;
  /** Clock tolerance in seconds for exp/iat/nbf (default 0). */
  clockToleranceSec?: number;
  /** Override current time (useful in tests). */
  now?: Date;
}

// ─────────────── Credential ───────────────

export type IdentityAssurance =
  | 'self_attested'
  | 'registered'
  | 'claimed'
  | 'verified'
  // Some broker paths set these too; accept them as opaque strings rather than narrowing further.
  | (string & {});

export interface CredentialClaims {
  /** Agent ID (sub claim) */
  sub: string;
  name: string;
  owner: string;
  identity_assurance: IdentityAssurance;
  verification_tier: string;
  pub_key_thumbprint: string;
  owner_type?: string;
  owner_id?: string;
  iat: number;
  exp: number;
  iss: string;
  jti?: string;
}

// ─────────────── Consent ───────────────

export type AuthorizationModality = 'autonomous' | 'attested' | 'verified' | (string & {});

export interface ConsentClaims {
  scope: string;
  permissions: string[];
  excluded: string[];
  session_id: string;
  token_type: 'consent';
  authorization_modality: AuthorizationModality;
  initiator_agent_id: string | null;
  target_agent_id: string | null;
  parent_token_id: string | null;
  iat: number;
  exp: number;
  iss: string;
}

// ─────────────── Receipt ───────────────

export interface ReceiptParticipant {
  agent_id: string;
  agent_name: string;
  identity_assurance: IdentityAssurance;
  did?: string;
}

export interface ReceiptConsentToken {
  scope: string;
  permissions: string[];
  authorization?: unknown;
  issued_at: string;
  expired_at: string;
}

export interface ReceiptPayload {
  receipt_id: string;
  session_id: string;
  handshake_id: string;
  participants: {
    initiator: ReceiptParticipant;
    target: ReceiptParticipant;
  };
  handshake: {
    handshake_id: string;
    mutual_auth_completed: boolean;
    completed_at: string;
  };
  consent_tokens: ReceiptConsentToken[];
  session: {
    started_at: string;
    closed_at: string;
    status: string;
  };
  signed_by: string;
  issued_at: string;
  signature: string;
}

// ─────────────── VDC shapes ───────────────

export type ParafeVDCType =
  | 'ParafeIdentityCredential'
  | 'ParafeConsentCredential'
  | 'ParafeReceiptCredential';

export interface VDCProof {
  type: 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod' | string;
  proofValue: string;
}

export interface VerifiableCredential<Subject = Record<string, unknown>> {
  '@context': string[];
  type: [string, ParafeVDCType, ...string[]];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: Subject;
  proof: VDCProof;
}

// ─────────────── Broker response ───────────────

export interface PublicKeyResponse {
  public_key: string;
  algorithm: 'Ed25519' | string;
  key_id: string;
}
