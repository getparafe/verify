/**
 * AP2 v0.2 mandate verification (agent_authorization.md "Verification and
 * Processing Rules"; specification.md "Verification"). Offline: the caller
 * supplies the trust list; nothing is fetched.
 */
import type { JWK } from 'jose';
import { canonicalize } from '../canonicalize.js';
import { Ap2Failure, Ap2MandateError } from './errors.js';
import { IDENTITY_VCT } from '../identity-credential.js';
import {
  splitChain, parseSegment, verifySegmentSignature, cnfJwk, thumbprint, sdHash, issuerJwtHash, hashAscii,
  KB_TYP_TERMINAL, KB_TYP_INTERMEDIATE, type Segment,
} from './sdjwt.js';
import { evaluateCheckoutConstraints, evaluatePaymentConstraints, CHECKOUT_CONSTRAINTS, PAYMENT_CONSTRAINTS } from './constraints.js';
import {
  AP2_VCT, type Ap2ChainOptions, type Ap2ChainResult, type Ap2MandateOptions, type Ap2MandateResult,
  type Ap2MandateReferences, type Ap2TrustedIssuer, type Ap2MandateFamily,
} from './types.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

const VCT_INFO: Record<string, { family: Ap2MandateFamily; open: boolean }> = {
  [AP2_VCT.checkout]: { family: 'checkout', open: false },
  [AP2_VCT.checkoutOpen]: { family: 'checkout', open: true },
  [AP2_VCT.payment]: { family: 'payment', open: false },
  [AP2_VCT.paymentOpen]: { family: 'payment', open: true },
};

/** Claims of an open mandate that aren't carried into the closed one. */
const NOT_CARRIED = new Set(['vct', 'cnf', 'constraints', 'iat', 'exp', 'nbf', 'iss', 'sub', 'jti', 'status', 'risk_data']);
/** Arrays whose elements AP2 makes selectively disclosable (x-selectively-disclosable-array): withholding some is the design. */
const DISCLOSABLE_ARRAYS = new Set(['allowed', 'acceptable_items']);

function failureToError(err: unknown): Ap2MandateError {
  if (err instanceof Ap2Failure) return new Ap2MandateError(err.ap2Error, err.reason, err.message, err.violations);
  return new Ap2MandateError('invalid_credential', 'malformed', (err as Error)?.message ?? String(err));
}

/**
 * Both ways of computing a receipt's `reference` for a presented chain, without
 * verifying it (a merchant rejecting a mandate still returns a receipt bound to it).
 */
export function ap2MandateReferences(chain: string): Ap2MandateReferences {
  const parts = splitChain(chain);
  const last = parseSegment(parts[parts.length - 1]!, parts.length - 1);
  return { sdHash: sdHash(last), closedJwt: hashAscii(last.issuerJwt, 'sha-256') };
}

async function rootKey(seg: Segment, trusted: Ap2TrustedIssuer[]): Promise<Ap2TrustedIssuer> {
  const kid = typeof seg.header.kid === 'string' ? seg.header.kid : undefined;
  const iss = typeof seg.claims.iss === 'string' ? seg.claims.iss : undefined;
  const candidates = trusted.filter((t) => {
    const tk = t.kid ?? (typeof t.jwk.kid === 'string' ? t.jwk.kid : undefined);
    if (kid !== undefined && tk !== undefined && tk !== kid) return false;
    if (iss !== undefined && t.iss !== undefined && t.iss !== iss) return false;
    return true;
  });
  for (const c of candidates) if (await verifySegmentSignature(seg, c.jwk)) return c;
  throw new Ap2Failure('invalid_credential', 'untrusted_issuer', kid || iss
    ? `The root isn't signed by a trusted issuer (kid "${kid ?? ''}", iss "${iss ?? ''}")`
    : "The root isn't signed by a trusted issuer");
}

function checkTimes(what: string, claims: Obj, nowSec: number, skew: number): void {
  for (const k of ['exp', 'nbf', 'iat'] as const) {
    if (claims[k] !== undefined && typeof claims[k] !== 'number') throw new Ap2Failure('invalid_credential', 'malformed', `${what}: "${k}" must be a number`);
  }
  if (typeof claims.exp === 'number' && nowSec > claims.exp + skew) throw new Ap2Failure('invalid_credential', 'expired', `${what} expired at ${new Date(claims.exp * 1000).toISOString()}`);
  if (typeof claims.nbf === 'number' && nowSec + skew < claims.nbf) throw new Ap2Failure('invalid_credential', 'not_yet_valid', `${what} is not valid before ${new Date(claims.nbf * 1000).toISOString()}`);
  if (typeof claims.iat === 'number' && claims.iat > nowSec + skew) throw new Ap2Failure('invalid_credential', 'issued_in_future', `${what} is issued in the future`);
}

interface VerifiedChain {
  segments: Segment[];
  result: Ap2ChainResult;
}

async function verifyChainInternal(chain: string, opts: Ap2ChainOptions, result: Ap2ChainResult): Promise<VerifiedChain> {
  if (!Array.isArray(opts.trustedIssuers) || !opts.trustedIssuers.length) {
    throw new Ap2Failure('invalid_credential', 'untrusted_issuer', 'No trusted issuers: pass trustedIssuers (the Credential Providers or Agent Providers you accept)');
  }
  const nowSec = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.clockToleranceSec ?? 60;
  const segments = splitChain(chain).map((raw, i) => parseSegment(raw, i));
  result.segments = segments.map((s) => {
    const info: Ap2ChainResult['segments'][number] = { index: s.index, sdHash: sdHash(s) };
    if (typeof s.header.typ === 'string') info.typ = s.header.typ;
    if (typeof s.item?.vct === 'string') info.vct = s.item.vct;
    return info;
  });

  const root = segments[0]!;
  const rootTyp = String(root.header.typ ?? '');
  if ([...KB_TYP_TERMINAL, ...KB_TYP_INTERMEDIATE].includes(rootTyp)) {
    throw new Ap2Failure('invalid_credential', 'chain_shape', 'The chain starts with a key-binding hop: the issuer-signed root is missing');
  }
  // S-53: Parafé's agent identity credential has the User Credential shape (a
  // trusted root whose cnf.jwk the holder signs with), but its holder is an
  // agent. It never stands for a user.
  if (root.claims.vct === IDENTITY_VCT) {
    throw new Ap2Failure('invalid_credential', 'agent_credential_root', "The chain's root is a Parafé agent identity credential: an agent's key can't sign for the user");
  }
  const issuer = await rootKey(root, opts.trustedIssuers);
  result.issuer = { jkt: await thumbprint(issuer.jwk) };
  const kid = typeof root.header.kid === 'string' ? root.header.kid : issuer.kid;
  if (kid) result.issuer.kid = kid;
  const iss = typeof root.claims.iss === 'string' ? root.claims.iss : issuer.iss;
  if (iss) result.issuer.iss = iss;
  if (issuer.name) result.issuer.name = issuer.name;
  checkTimes('The root', root.claims, nowSec, skew);
  if (root.item) checkTimes('The root mandate', root.item, nowSec, skew);

  // S-60: a root-only chain (the issuer signed the closed mandate itself) has no
  // key-binding hop, so no aud or nonce. Valid when nothing is expected (as in
  // AP2), but a caller's expectations are refused, never silently skipped; its
  // age is the root's (or its mandate's) iat.
  if (segments.length === 1) {
    if (opts.expectedAudience !== undefined) throw new Ap2Failure('invalid_credential', 'missing_audience', 'The chain has no key-binding hop, so no aud: it is not presented to anyone');
    if (opts.expectedNonce !== undefined) throw new Ap2Failure('invalid_credential', 'missing_nonce', 'The chain has no key-binding hop, so no nonce');
    if (opts.maxPresentationAgeSec !== undefined) {
      const issued = typeof root.claims.iat === 'number' ? root.claims.iat : root.item?.iat;
      if (typeof issued !== 'number') throw new Ap2Failure('invalid_credential', 'not_presented', 'The chain has no key-binding hop and no iat, so its age can\'t be checked');
      if (nowSec - issued > opts.maxPresentationAgeSec + skew) throw new Ap2Failure('invalid_credential', 'stale', `The mandate was signed more than ${opts.maxPresentationAgeSec}s ago`);
    }
  }

  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i]!;
    const prev = segments[i - 1]!;
    const last = i === segments.length - 1;
    const typ = String(seg.header.typ ?? '');
    if (!(last ? KB_TYP_TERMINAL : KB_TYP_INTERMEDIATE).includes(typ)) {
      throw new Ap2Failure('invalid_credential', 'typ', `Hop ${i}: typ "${typ}" is not ${last ? 'a terminal (kb+sd-jwt)' : 'an intermediate (kb+sd-jwt+kb)'} hop`);
    }
    const key = cnfJwk(prev);
    if (!key) throw new Ap2Failure('invalid_credential', 'missing_cnf', `Segment ${i - 1} endorses no key (cnf.jwk) for hop ${i}`);
    if (!(await verifySegmentSignature(seg, key))) throw new Ap2Failure('invalid_credential', 'signature', `Hop ${i} isn't signed by the key segment ${i - 1} endorses`);
    const hasSd = 'sd_hash' in seg.claims, hasIjh = 'issuer_jwt_hash' in seg.claims;
    if (hasSd === hasIjh) throw new Ap2Failure('invalid_credential', 'binding_mismatch', `Hop ${i} must carry exactly one of sd_hash and issuer_jwt_hash`);
    const expected = hasSd ? sdHash(prev) : issuerJwtHash(prev);
    if ((hasSd ? seg.claims.sd_hash : seg.claims.issuer_jwt_hash) !== expected) {
      throw new Ap2Failure('invalid_credential', 'binding_mismatch', `Hop ${i}'s ${hasSd ? 'sd_hash' : 'issuer_jwt_hash'} doesn't match segment ${i - 1} as presented`);
    }
    if (typeof seg.claims.iat !== 'number') throw new Ap2Failure('invalid_credential', 'malformed', `Hop ${i} has no iat`);
    if (!seg.item) throw new Ap2Failure('invalid_credential', 'chain_shape', `Hop ${i} delegates nothing (no delegate_payload)`);
    const itemHasCnf = isObj(seg.item.cnf);
    if (last && itemHasCnf) throw new Ap2Failure('invalid_credential', 'chain_shape', 'The terminal hop must not carry cnf');
    if (!last && !itemHasCnf) throw new Ap2Failure('invalid_credential', 'chain_shape', `Intermediate hop ${i} must carry cnf for the next hop`);
    checkTimes(`Hop ${i}`, seg.claims, nowSec, skew);
    checkTimes(`Hop ${i}'s mandate`, seg.item, nowSec, skew);
    if (last) {
      // #319/#342: the terminal hop's aud and nonce are required, whatever the caller expects.
      if (!nonEmpty(seg.claims.aud)) throw new Ap2Failure('invalid_credential', 'missing_audience', 'The terminal hop has no aud (a single string)');
      if (!nonEmpty(seg.claims.nonce)) throw new Ap2Failure('invalid_credential', 'missing_nonce', 'The terminal hop has no nonce');
      if (opts.expectedAudience !== undefined && seg.claims.aud !== opts.expectedAudience) {
        throw new Ap2Failure('invalid_credential', 'audience_mismatch', `The terminal hop is for "${seg.claims.aud}", not "${opts.expectedAudience}"`);
      }
      if (opts.expectedNonce !== undefined && seg.claims.nonce !== opts.expectedNonce) {
        throw new Ap2Failure('invalid_credential', 'nonce_mismatch', "The terminal hop's nonce isn't the expected one");
      }
      if (opts.maxPresentationAgeSec !== undefined && nowSec - seg.claims.iat > opts.maxPresentationAgeSec + skew) {
        throw new Ap2Failure('invalid_credential', 'stale', `The terminal hop is older than ${opts.maxPresentationAgeSec}s`);
      }
      result.audience = seg.claims.aud;
      result.nonce = seg.claims.nonce;
      result.presentedAt = seg.claims.iat;
    }
  }
  result.payloads = segments.map((s) => s.item ?? s.claims);
  return { segments, result };
}

function emptyChainResult(opts: Ap2ChainOptions): Ap2ChainResult {
  return { valid: false, verifiedAt: (opts.now ?? new Date()).toISOString(), payloads: [], segments: [] };
}

/**
 * Verify the Delegate SD-JWT chain only: the root against the trust list, every
 * hop's signature against the previous `cnf.jwk`, the sd_hash/issuer_jwt_hash
 * bindings, typ, times, and the terminal hop's aud and nonce. Returns each
 * segment's effective payload (like the AP2 SDK's `MandateClient.verify`). Use
 * `verifyAp2Mandate` to also check what the mandate authorizes.
 */
export async function verifyAp2Chain(chain: string, opts: Ap2ChainOptions): Promise<Ap2ChainResult> {
  const result = emptyChainResult(opts);
  try {
    await verifyChainInternal(chain, opts, result);
    result.valid = true;
  } catch (err) {
    result.error = failureToError(err);
    result.payloads = [];
  }
  return result;
}

function decodeCheckoutJwt(jwt: string): Obj {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Ap2Failure('invalid_mandate', 'malformed_checkout', 'checkout_jwt is not a compact JWT');
  try {
    const seg = parts[1]!;
    const json = new TextDecoder().decode(Uint8Array.from(atob(seg.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (seg.length % 4)) % 4)), (c) => c.charCodeAt(0)));
    const v = JSON.parse(json);
    if (!isObj(v)) throw new Error('not an object');
    return v;
  } catch (err) {
    throw new Ap2Failure('invalid_mandate', 'malformed_checkout', `checkout_jwt payload: ${(err as Error).message}`);
  }
}

/**
 * Verify an AP2 v0.2 Checkout or Payment Mandate as presented (a `~~`-joined
 * Delegate SD-JWT chain): the chain (see `verifyAp2Chain`), the exact `vct`s
 * (open mandates, then one closed mandate, one family), claims carried from open
 * to closed unchanged, no withheld constraint, every constraint (unknown ones
 * fail), `checkout_hash` against the Checkout JWT, and `transaction_id` against
 * the checkout hash. Failures carry the AP2 error code (`error.ap2Error`).
 */
export async function verifyAp2Mandate(chain: string, opts: Ap2MandateOptions): Promise<Ap2MandateResult> {
  const result: Ap2MandateResult = { ...emptyChainResult(opts), openMandates: [], openSegmentHashes: [] };
  try {
    result.references = ap2MandateReferences(chain);
  } catch { /* reported below */ }
  try {
    const { segments } = await verifyChainInternal(chain, opts, result);
    await checkMandate(segments, opts, result);
    result.valid = true;
  } catch (err) {
    result.error = failureToError(err);
    result.valid = false;
  }
  return result;
}

/**
 * What the mandate authorizes, once the chain's signatures check out: exported
 * for tests that can't verify a root (the AP2 spec's examples publish no issuer key).
 * @internal
 */
export async function checkMandate(segments: Segment[], opts: Ap2MandateOptions, result: Ap2MandateResult): Promise<void> {
  const nowSec = Math.floor((opts.now ?? new Date()).getTime() / 1000);

  // Mandate sequence: [a root credential without delegate_payload], open*, closed.
  const mandateSegs = segments.filter((s) => s.item);
  if (segments.some((s, i) => i > 0 && !s.item)) throw new Ap2Failure('invalid_credential', 'chain_shape', 'Every hop must delegate a mandate');
  if (!mandateSegs.length) throw new Ap2Failure('invalid_mandate', 'chain_shape', 'The chain carries no mandate');
  let family: Ap2MandateFamily | undefined;
  const opens: Segment[] = [];
  let closed: Segment | undefined;
  for (const s of mandateSegs) {
    const vct = s.item!.vct;
    const info = typeof vct === 'string' ? VCT_INFO[vct] : undefined;
    if (!info) throw new Ap2Failure('invalid_mandate', 'wrong_vct', `Unknown mandate type "${String(vct)}" (vct must match exactly, version suffix included)`);
    if (family && info.family !== family) throw new Ap2Failure('invalid_mandate', 'chain_shape', 'A chain mixes checkout and payment mandates');
    family = info.family;
    if (closed) throw new Ap2Failure('invalid_mandate', 'chain_shape', 'A mandate follows the closed mandate');
    if (info.open) {
      if (!isObj(s.item!.cnf) || !isObj((s.item!.cnf as Obj).jwk)) throw new Ap2Failure('invalid_mandate', 'chain_shape', 'An open mandate must carry cnf.jwk');
      opens.push(s);
    } else {
      closed = s;
    }
  }
  if (!closed || closed !== segments[segments.length - 1]) {
    throw new Ap2Failure('invalid_mandate', 'chain_shape', 'The chain must end with a closed mandate (an open mandate authorizes nothing by itself)');
  }
  if (opts.expectedFamily && family !== opts.expectedFamily) throw new Ap2Failure('invalid_mandate', 'wrong_family', `Expected a ${opts.expectedFamily} mandate, got ${family}`);
  result.family = family!;
  result.mode = opens.length ? 'human_not_present' : 'human_present';
  result.closedMandate = closed.item!;
  result.openMandates = opens.map((s) => s.item!);
  result.openSegmentHashes = opens.map((s) => sdHash(s));
  if (opens.length) {
    result.agentKey = (opens[opens.length - 1]!.item!.cnf as { jwk: JWK }).jwk;
    result.agentKeyThumbprint = await thumbprint(result.agentKey);
  }
  // Who signed the closed mandate: the root issuer itself; the holder of a root
  // credential (User Credential model: the user's key); or the key an open
  // mandate endorsed (an agent).
  if (segments.length === 1) {
    result.closedBy = 'issuer';
  } else {
    const key = cnfJwk(segments[segments.length - 2]!);
    result.closedBy = opens.length ? 'open_mandate_key' : 'credential_holder';
    if (key) {
      result.closedByKey = key;
      result.closedByKeyThumbprint = await thumbprint(key);
    }
  }
  // S-59: who signed the first open mandate (the user's limits): the root
  // issuer itself, or the holder of a root credential (User Credential model:
  // the user's key). A verifier must check it isn't an agent's key before
  // treating the limits as the user's.
  if (opens.length) {
    const first = opens[0]!;
    if (first.index === 0) {
      result.openedBy = 'issuer';
    } else {
      result.openedBy = 'credential_holder';
      const key = cnfJwk(segments[first.index - 1]!);
      if (key) {
        result.openedByKey = key;
        result.openedByKeyThumbprint = await thumbprint(key);
      }
    }
  }
  const c = closed.item!;

  // #339: a withheld constraint (or any withheld claim of an open mandate) disables enforcement; refuse it.
  for (const s of opens) {
    for (const w of s.itemWithheld) {
      const container = w.path[w.path.length - 1];
      if (w.kind === 'element' && typeof container === 'string' && DISCLOSABLE_ARRAYS.has(container)) continue;
      // P-36: a decoy digest (RFC 9901 §4.2.5) can't be told from a withheld claim, so it is refused too.
      throw new Ap2Failure('unresolved_constraint', 'withheld_disclosure', `An open mandate has an undisclosed (withheld or decoy) digest in ${w.path.length ? w.path.join('.') : 'the mandate'}: every constraint must be disclosed, and decoy digests can't be told from withheld claims`);
    }
  }
  // Claims set in an open mandate reach the closed mandate unchanged.
  for (const s of opens) {
    for (const [k, v] of Object.entries(s.item!)) {
      if (NOT_CARRIED.has(k)) continue;
      if (!(k in c) || canonicalize(c[k]) !== canonicalize(v)) throw new Ap2Failure('invalid_mandate', 'preset_mismatch', `The closed mandate changes "${k}" set by the open mandate`);
    }
  }

  const constraints: Obj[] = [];
  for (const s of opens) {
    const list = s.item!.constraints;
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.some((x) => !isObj(x) || !nonEmpty(x.type))) throw new Ap2Failure('invalid_mandate', 'malformed', 'constraints must be a list of objects with a type');
    constraints.push(...(list as Obj[]));
  }
  const known = family === 'checkout' ? CHECKOUT_CONSTRAINTS : PAYMENT_CONSTRAINTS;
  const unknown = constraints.filter((x) => !known.includes(String(x.type)));
  if (unknown.length) {
    throw new Ap2Failure('unresolved_constraint', 'unknown_constraint', `Unknown constraint: ${unknown.map((x) => String(x.type)).join(', ')}`, unknown.map((x) => `unknown constraint "${String(x.type)}"`));
  }
  // The schemas require these (`contains`) in every open mandate of the family.
  const requiredType = family === 'checkout' ? 'checkout.line_items' : 'payment.reference';
  for (const s of opens) {
    if (!Array.isArray(s.item!.constraints) || !(s.item!.constraints as Obj[]).some((x) => x.type === requiredType)) {
      throw new Ap2Failure('invalid_mandate', 'constraint_missing', `An open ${family} mandate must carry a ${requiredType} constraint`);
    }
  }

  let outcome = { violations: [] as string[], unresolved: [] as string[] };
  if (family === 'checkout') {
    if (!nonEmpty(c.checkout_hash)) throw new Ap2Failure('invalid_mandate', 'malformed', 'The closed checkout mandate has no checkout_hash');
    const disclosed = nonEmpty(c.checkout_jwt) ? c.checkout_jwt : undefined;
    if (disclosed && opts.checkoutJwt !== undefined && disclosed !== opts.checkoutJwt) {
      throw new Ap2Failure('invalid_mandate', 'checkout_hash_mismatch', 'The disclosed checkout_jwt is not the Checkout JWT you passed');
    }
    const checkoutJwt = disclosed ?? opts.checkoutJwt;
    if (!checkoutJwt) throw new Ap2Failure('invalid_mandate', 'checkout_jwt_required', 'The Checkout JWT is needed to check checkout_hash: the mandate does not disclose it, so pass checkoutJwt');
    // #358: always bind the closed mandate to the Checkout JWT actually presented.
    if (hashAscii(checkoutJwt, closed.sdAlg) !== c.checkout_hash) throw new Ap2Failure('invalid_mandate', 'checkout_hash_mismatch', 'checkout_hash is not the hash of the Checkout JWT');
    result.checkoutHash = c.checkout_hash;
    const checkout = decodeCheckoutJwt(checkoutJwt);
    result.checkout = checkout;
    outcome = evaluateCheckoutConstraints(constraints, checkout);
  } else {
    for (const k of ['transaction_id', 'payee', 'payment_amount', 'payment_instrument'] as const) {
      if (c[k] === undefined) throw new Ap2Failure('invalid_mandate', 'malformed', `The closed payment mandate has no ${k}`);
    }
    if (!nonEmpty(c.transaction_id)) throw new Ap2Failure('invalid_mandate', 'malformed', 'transaction_id must be a string');
    const fromCheckout = opts.checkout?.valid ? opts.checkout.checkoutHash : undefined;
    if (opts.checkout && !opts.checkout.valid) throw new Ap2Failure('invalid_mandate', 'checkout_invalid', 'The checkout mandate passed for this payment did not verify');
    const expected = [
      opts.checkoutJwt !== undefined ? hashAscii(opts.checkoutJwt, closed.sdAlg) : undefined,
      opts.checkoutHash, fromCheckout,
    ].filter((x): x is string => x !== undefined);
    if (!expected.length) throw new Ap2Failure('invalid_mandate', 'transaction_id_unchecked', 'Pass the checkout (checkoutJwt, checkoutHash or the verified checkout mandate) so transaction_id can be checked');
    if (expected.some((e) => e !== c.transaction_id)) throw new Ap2Failure('invalid_mandate', 'transaction_id_mismatch', "transaction_id is not the checkout's hash");
    result.transactionId = c.transaction_id;
    const openCheckoutHashes = opts.openCheckoutHashes ?? (opts.checkout?.valid ? opts.checkout.openSegmentHashes : undefined);
    outcome = evaluatePaymentConstraints({ closed: c, constraints, nowSec, context: opts.context, openCheckoutHashes });
  }
  if (outcome.violations.length) throw new Ap2Failure('invalid_mandate', 'constraint_failed', outcome.violations[0]!, [...outcome.violations, ...outcome.unresolved]);
  if (outcome.unresolved.length) throw new Ap2Failure('unresolved_constraint', 'constraint_unresolved', outcome.unresolved[0]!, outcome.unresolved);
}
