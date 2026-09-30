import type { VerifyError } from './errors.js';
import type { PublicKeySource } from './keys.js';

export type ArtifactFormat = 'jwt' | 'receipt' | 'receipt-jws' | 'sd-jwt' | 'action-receipt' | 'index-ack';

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
  // Self-registered, then approved by a signed-in person through a claim link (broker Phase 1.5).
  | 'claimed'
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

/** Weakest to strongest: autonomous < attested < delegated < verified (delegated and verified: a broker-checked AP2 mandate, broker B8). */
export type AuthorizationModality = 'autonomous' | 'attested' | 'delegated' | 'verified' | (string & {});

/** An AP2 mandate behind a consent token, by hash both ways (broker B8). */
export interface MandateRef {
  family: 'checkout' | 'payment';
  /** SHA-256 of the closed mandate JWT (the AP2 SDK's receipt reference). */
  closed_jwt: string;
  /** sd_hash of the final SD-JWT as presented (the AP2 spec's). */
  sd_hash: string;
}

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
  /** The AP2 mandates behind 'delegated' / 'verified' (broker B8). */
  mandate_refs?: MandateRef[];
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
  authorization: { modality: AuthorizationModality; evidence_hash: string | null; mandate_refs: MandateRef[] };
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
  /** B6: every receipt filed in the session's index, in chain order. */
  actions: ReceiptV2Action[];
  /** entry_hash of the last action, or null when none was filed. */
  chain_head: string | null;
  session: { started_at: string; closed_at: string; closed_by: string | null; status: string };
}

/** A session receipt's entry for a filed receipt (B6). */
export interface ReceiptV2Action {
  seq: number;
  /** base64url(SHA-256(<receipt JWS>)). */
  receipt_hash: string;
  kind: 'parafe.action_receipt' | 'ap2.checkout_receipt' | 'ap2.payment_receipt' | (string & {});
  /** The receipt's issuer: an agent DID, or an AP2 receipt's iss. */
  iss: string;
  /** false: an AP2 receipt no participant's registered key verifies. */
  issuer_verified: boolean;
  action: string;
  result: 'success' | 'error';
  error: string | null;
}

// ─────────────── Action receipt and index acknowledgment (B6) ───────────────

export interface ActionReceiptClaims {
  /** The acting agent's DID. */
  iss: string;
  iat: number;
  jti: string;
  ver: 1;
  session_id: string;
  /** base64url(SHA-256(<consent token JWS>)). */
  consent_ref: string;
  action: string;
  result: 'success' | 'error';
  error: 'not_permitted' | 'excluded' | 'consent_invalid' | 'consent_expired' | 'proof_invalid' | 'failed' | null;
  error_description?: string | null;
  request_ref?: string | null;
  details_hash?: string | null;
  business_ref?: string | null;
  mandate_ref?: string | null;
}

export interface IndexAckClaims {
  /** The broker DID. */
  iss: string;
  iat: number;
  jti: string;
  ver: 1;
  session_id: string;
  seq: number;
  receipt_hash: string;
  kind: string;
  /** The filed receipt's issuer. */
  receipt_iss: string;
  issuer_verified: boolean;
  prev: string | null;
  entry_hash: string;
  indexed_at: string;
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
