import type { JWK } from 'jose';
import type { Ap2MandateError } from './errors.js';

export const AP2_VCT = {
  checkout: 'mandate.checkout.1',
  checkoutOpen: 'mandate.checkout.open.1',
  payment: 'mandate.payment.1',
  paymentOpen: 'mandate.payment.open.1',
} as const;

export type Ap2MandateFamily = 'checkout' | 'payment';

/**
 * A mandate issuer you trust: a Credential Provider (User Credential model) or
 * an Agent Provider (Trusted Agent Provider model). The chain's root must be
 * signed by one of these keys. `kid` (or `jwk.kid`) is matched against the root
 * header's `kid` when both are set; `iss` against the root payload's `iss`.
 */
export interface Ap2TrustedIssuer {
  jwk: JWK;
  kid?: string;
  iss?: string;
  /** A label returned in the result, e.g. "Example Agent Provider". */
  name?: string;
}

/** What has already happened under an open payment mandate, for `payment.budget` and `payment.agent_recurrence`. */
export interface Ap2MandateContext {
  /** Minor units already spent under this open mandate. */
  totalAmount?: number;
  /** Earlier closed payments under this open mandate. */
  totalUses?: number;
  /** Unix seconds of the last use. */
  lastUsedAt?: number;
}

export interface Ap2ChainOptions {
  trustedIssuers: Ap2TrustedIssuer[];
  /** The terminal hop's `aud` must equal this (your identifier as the verifier). It must be present either way. */
  expectedAudience?: string;
  /** The terminal hop's `nonce` must equal this. It must be present either way. */
  expectedNonce?: string;
  now?: Date;
  /** Clock tolerance for exp/iat/nbf, seconds (default 60). */
  clockToleranceSec?: number;
  /** Refuse a terminal hop whose `iat` is older than this many seconds. Unset: no limit (dispute-time checks). */
  maxPresentationAgeSec?: number;
}

export interface Ap2MandateOptions extends Ap2ChainOptions {
  /** Refuse any other mandate family. */
  expectedFamily?: Ap2MandateFamily;
  /**
   * Checkout mandate: the merchant-signed Checkout JWT, when the closed mandate
   * doesn't disclose `checkout_jwt` (if it does, both must be identical).
   * Payment mandate: the checkout being paid; its hash must equal `transaction_id`.
   */
  checkoutJwt?: string;
  /** Payment mandate: the expected `transaction_id` (the checkout hash), if you don't hold the Checkout JWT. */
  checkoutHash?: string;
  /**
   * Payment mandate: the verified checkout mandate this payment is for. Supplies
   * the checkout hash (`transaction_id`) and the open checkout hashes
   * (`payment.reference`).
   */
  checkout?: Ap2MandateResult;
  /** Payment mandate: sd_hash of each open checkout mandate segment, for `payment.reference`. */
  openCheckoutHashes?: string[];
  context?: Ap2MandateContext;
}

export interface Ap2ChainSegmentInfo {
  index: number;
  typ?: string;
  /** base64url hash of the segment as presented (what the next hop's sd_hash covers). */
  sdHash: string;
  /** The disclosed delegate item's `vct`, if any. */
  vct?: string;
}

export interface Ap2ChainResult {
  valid: boolean;
  error?: Ap2MandateError;
  verifiedAt: string;
  /** Effective payload per segment: the disclosed delegate item, or the payload when there is none. */
  payloads: Record<string, unknown>[];
  segments: Ap2ChainSegmentInfo[];
  issuer?: { kid?: string; iss?: string; name?: string; jkt: string };
  audience?: string;
  nonce?: string;
  /** The terminal hop's `iat`. */
  presentedAt?: number;
}

export interface Ap2MandateReferences {
  /** The AP2 spec's `reference`: hash of the final SD-JWT in the chain, computed like `sd_hash` (agent_authorization.md). */
  sdHash: string;
  /** The AP2 Python SDK's `reference`: SHA-256 of the closed mandate's JWT (`get_closed_mandate_jwt`). */
  closedJwt: string;
}

export interface Ap2MandateResult extends Ap2ChainResult {
  family?: Ap2MandateFamily;
  /** `human_present`: the closed mandate is signed by a trusted issuer or a key it certified. `human_not_present`: signed by an agent key an open mandate endorsed. */
  mode?: 'human_present' | 'human_not_present';
  closedMandate?: Record<string, unknown>;
  openMandates: Record<string, unknown>[];
  /** Human not present: the agent key (the last open mandate's `cnf.jwk`) that signed the closed mandate. */
  agentKey?: JWK;
  /** RFC 7638 thumbprint of `agentKey`. */
  agentKeyThumbprint?: string;
  checkoutHash?: string;
  transactionId?: string;
  /** Checkout mandate: the decoded Checkout JWT payload. */
  checkout?: Record<string, unknown>;
  /** Both ways of computing a receipt's `reference` (set even when verification fails, so a rejection receipt can be issued). */
  references?: Ap2MandateReferences;
  /** sd_hash of each open mandate segment (a payment mandate's `payment.reference` points at one of a checkout chain's). */
  openSegmentHashes: string[];
}
