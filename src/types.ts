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
  /** Action receipts: the signer was revoked at this time; the receipt was indexed before it. */
  issuerRevokedAt?: string;
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
  /** Who the agent acts for (its principal), as free text (broker SPEC-002). Not required. */
  principal_name?: string;
  /** The same, in credentials issued before SPEC-002 (they renew within 30 days). */
  owner?: string;
  identity_assurance: IdentityAssurance;
  verification_tier: string;
  pub_key_thumbprint: string;
  principal_type?: 'personal' | 'org' | 'external';
  /** An org principal's ID (a person's user ID is never in the credential). */
  principal_id?: string;
  /** The operator's reference for an external principal (one of a platform's users). */
  principal_ref?: string;
  /** Who runs the agent and answers for it; absent when self-registered or claimed. */
  operator_type?: 'personal' | 'org';
  /** An org operator's ID (absent for a personal operator). */
  operator_id?: string;
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
  /** Broker SPEC-002: the initiator's operator and principal. */
  initiator_parties?: Parties;
  /** Broker SPEC-002: the target's operator and principal. */
  target_parties?: Parties;
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
  /** Broker SPEC-002 (v2 receipts): the participant's operator and principal. */
  parties?: Parties;
}

/**
 * Broker SPEC-002: who runs an agent (operator) and who it acts for
 * (principal). A person's user ID is never shown: a personal operator or
 * principal has `type` only; an org has `id`; an external principal (a
 * platform's user) has the platform's opaque `ref`.
 */
export interface Parties {
  operator: { type: 'personal' | 'org'; id?: string } | null;
  principal: { type: 'personal' | 'org' | 'external'; id?: string; ref?: string } | null;
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
  /**
   * A3 (broker, entries that name an AP2 mandate): whether the reference (an AP2
   * receipt's `reference`, an action receipt's `mandate_ref`) matched a mandate
   * the receipt's issuer, or the handshake, verified in the session; the matched
   * closed-mandate hash; which agent verified it; and whose trust list it
   * passed (`scope_policy`, `broker` or `request`: the verifier's own list).
   */
  reference_verified?: boolean;
  mandate_ref?: string | null;
  mandate_verified_by?: string | null;
  mandate_issuer_source?: string | null;
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
  /**
   * A3 (broker, entries that name an AP2 mandate): whether the reference (an AP2
   * receipt's `reference`, an action receipt's `mandate_ref`) matched a mandate
   * the receipt's issuer, or the handshake, verified in the session; the matched
   * closed-mandate hash; which agent verified it; and whose trust list it
   * passed (`scope_policy`, `broker` or `request`: the verifier's own list).
   */
  reference_verified?: boolean;
  mandate_ref?: string | null;
  mandate_verified_by?: string | null;
  mandate_issuer_source?: string | null;
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
  principal_type?: 'personal' | 'org' | 'external';
  /** Selectively disclosed. */
  principal_name?: string;
  /** Selectively disclosed. */
  principal_id?: string;
  /** Selectively disclosed: the operator's reference for an external principal. */
  principal_ref?: string;
  operator_type?: 'personal' | 'org';
  /** Absent for a personal operator. */
  operator_id?: string;
  /** Only when the operator is an org that verified its domain. */
  operator_domain?: string;
  operator_domain_verified_at?: number;
}

// ─────────────── Broker response ───────────────

export interface PublicKeyResponse {
  public_key: string;
  algorithm: 'Ed25519' | string;
  key_id: string;
}
