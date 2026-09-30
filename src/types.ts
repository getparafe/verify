import type { VerifyError } from './errors.js';
import type { PublicKeySource } from './keys.js';

export type ArtifactFormat = 'jwt' | 'receipt' | 'receipt-jws' | 'sd-jwt';

export interface VerifyResult<T> {
  valid: boolean;
  claims?: T;
  format?: ArtifactFormat;
  keyId?: string | undefined;
  verifiedAt: string;
  error?: VerifyError;
}

export interface VerifyOptions {
  key: PublicKeySource;
  /** Override issuer check (default: 'parafe-trust-broker'). */
  expectedIssuer?: string;
  /** Clock tolerance in seconds for exp/iat/nbf (default 0). */
  clockToleranceSec?: number;
  /** Override current time (useful in tests). */
  now?: Date;
}

// ─────────────── Credential ───────────────

export type IdentityAssurance =
  | 'registered'
  | 'self_registered'
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
  /** Forbidden actions. Always set: from `exclusions` (v2) or `excluded` (older tokens). */
  exclusions: string[];
  /** The pre-v2 name of `exclusions`; also always set. */
  excluded: string[];
  /** 2 for key-bound tokens (2026-09-30+). */
  ver?: number;
  /** Initiator agent ID. */
  sub?: string;
  /** Target agent DID. */
  aud?: string;
  /** The key the token is bound to: RFC 7638 thumbprint of the initiator's registered key. */
  cnf?: { jkt: string };
  jti?: string;
  /** How the initiator proved itself when the token was issued. */
  initiator_proof?: 'pop' | 'credential';
  initiator_proof_at?: number;
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

// ─────────────── Receipt v2 (JWS, since 2026-09-30) ───────────────

export interface ReceiptV2ConsentToken {
  token_ref: string | null;
  scope: string;
  permissions: string[];
  exclusions: string[];
  authorization: { modality: AuthorizationModality; evidence_hash: string | null; mandate_refs: string[] };
  initiator_proof?: 'pop' | 'credential' | null;
  initiator_proof_at?: string | null;
  issued_at: string;
  expires_at: string;
}

export interface ReceiptV2Payload {
  iss: string;
  iat: number;
  jti: string;
  ver: 2;
  receipt_id: string;
  session_id: string;
  handshake_id: string;
  participants: {
    initiator: ReceiptParticipant & { verification_tier?: string };
    target: ReceiptParticipant & { verification_tier?: string };
  };
  handshake: { mutual_auth_completed: boolean; completed_at: string; context_hash: string | null };
  consent_tokens: ReceiptV2ConsentToken[];
  actions: unknown[];
  chain_head: string | null;
  session: { started_at: string; closed_at: string; closed_by: string | null; status: string };
}

// ─────────────── Identity credential (SD-JWT VC, since 2026-09-30) ───────────────

export interface IdentityCredentialClaims {
  iss: string;
  sub: string;
  vct: string;
  iat: number;
  exp: number;
  jti?: string;
  /** The agent's registered public key. */
  cnf: { jwk: import('jose').JWK };
  agent_id: string;
  agent_name: string;
  identity_assurance: IdentityAssurance;
  verification_tier: string;
  owner_type?: string;
  /** Selectively disclosed. */
  owner?: string;
  /** Selectively disclosed. */
  owner_id?: string;
  /** Only for agents of an org that verified its domain. */
  org_domain?: string;
  org_domain_verified_at?: number;
}

// ─────────────── Broker response ───────────────

export interface PublicKeyResponse {
  public_key: string;
  algorithm: 'Ed25519' | string;
  key_id: string;
}
