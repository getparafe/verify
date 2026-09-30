import { VerifyError } from '../errors.js';

/** The four action-authorization errors AP2 defines (agent_authorization.md, "Errors"). */
export type Ap2ErrorCode = 'invalid_credential' | 'unresolved_constraint' | 'invalid_mandate' | 'mandates_not_supported';

/**
 * Why an AP2 mandate failed: `ap2Error` is the AP2 code to put in a Checkout or
 * Payment Receipt's `error`; `reason` is a stable, more specific Parafé code
 * (`signature`, `untrusted_issuer`, `binding_mismatch`, `missing_audience`,
 * `audience_mismatch`, `nonce_mismatch`, `expired`, `withheld_disclosure`,
 * `unknown_constraint`, `constraint_failed`, `checkout_hash_mismatch`,
 * `transaction_id_mismatch`, `wrong_vct`, `chain_shape`, ...);
 * `violations` lists every failed constraint.
 */
export class Ap2MandateError extends VerifyError {
  readonly ap2Error: Ap2ErrorCode;
  readonly reason: string;
  readonly violations: string[];
  constructor(ap2Error: Ap2ErrorCode, reason: string, message: string, violations: string[] = []) {
    super('AP2_MANDATE_INVALID', message);
    this.name = 'Ap2MandateError';
    this.ap2Error = ap2Error;
    this.reason = reason;
    this.violations = violations;
  }
}

/** Internal: thrown inside the verifier, turned into an Ap2MandateError in the result. */
export class Ap2Failure extends Error {
  constructor(readonly ap2Error: Ap2ErrorCode, readonly reason: string, message: string, readonly violations: string[] = []) {
    super(message);
  }
}
