import { jwtVerify, importJWK, decodeProtectedHeader, decodeJwt, type JWK } from 'jose';
import { sha256 } from '@noble/hashes/sha256';
import { InvalidSignatureError, KeyFetchError, KeyNotFoundError, MalformedArtifactError, VerifyError } from './errors.js';
import { brokerKeyFor } from './internal/broker-key.js';
import { coerceJoseError } from './jwt-verify.js';
import type {
  ActionReceiptClaims, IndexAckClaims, ReceiptV2Payload, VerifyOptions, VerifyResult,
} from './types.js';

// AP2 change request B6 (broker Phase 2): the agent that performs or refuses an
// action signs an action receipt; either participant files it with the broker,
// which chains it per session and signs an index acknowledgment; the session
// receipt lists every filed receipt and the chain head.

export const ACTION_RECEIPT_TYP = 'parafe-action-receipt+jwt';
export const INDEX_ACK_TYP = 'parafe-index-ack+jwt';
export const ACTION_ERROR_CODES = ['not_permitted', 'excluded', 'consent_invalid', 'consent_expired', 'proof_invalid', 'failed'] as const;

function b64u(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sha256b64u(s: string): string {
  return b64u(sha256(new TextEncoder().encode(s)));
}

/** How Parafé references a compact JWS: base64url(SHA-256(<the JWS string>)). */
export function receiptHash(jws: string): string {
  return sha256b64u(jws);
}

/** An action receipt's `consent_ref`: base64url(SHA-256(<consent token JWS>)). */
export function consentRef(consentToken: string): string {
  return sha256b64u(consentToken);
}

/** An index entry's hash: base64url(SHA-256("<seq>|<receipt_hash>|<prev>")), prev "" for seq 1. */
export function entryHash(seq: number, receiptHashValue: string, prev: string | null): string {
  return sha256b64u(`${seq}|${receiptHashValue}|${prev ?? ''}`);
}

export interface ActionReceiptOptions {
  /**
   * The issuing agent's registered public key as a JWK. If omitted, it is read
   * from the agent's DID document at `<brokerUrl>/agents/<agent_id>/did.json`.
   */
  issuerKey?: JWK;
  /** Broker base URL, to fetch the issuer's DID document. Default https://api.parafe.ai. */
  brokerUrl?: string;
  /** If set, the receipt's `session_id` must equal it. */
  expectedSessionId?: string;
  /** If set, the receipt's `consent_ref` must be this consent token's hash. */
  consentToken?: string;
  /** Override the current time (iat may not be in the future). */
  now?: Date;
  fetch?: typeof fetch;
}

async function issuerJwk(iss: string, kid: string | undefined, opts: ActionReceiptOptions): Promise<JWK> {
  if (opts.issuerKey) return opts.issuerKey;
  const agentId = iss.split(':').pop() ?? '';
  if (!iss.startsWith('did:web:') || !iss.includes(':agents:') || !agentId.startsWith('prf_agent_')) {
    throw new MalformedArtifactError("iss is not a Parafé agent DID; pass issuerKey", 'iss');
  }
  const brokerUrl = (opts.brokerUrl ?? 'https://api.parafe.ai').replace(/\/$/, '');
  const url = `${brokerUrl}/agents/${encodeURIComponent(agentId)}/did.json`;
  const fetchImpl = opts.fetch ?? (globalThis.fetch as typeof fetch);
  let res: Response;
  try {
    res = await fetchImpl(url);
  } catch (err) {
    throw new KeyFetchError(url, `Could not fetch the issuer's DID document: ${String(err)}`, undefined, err);
  }
  if (!res.ok) throw new KeyFetchError(url, `Could not fetch the issuer's DID document (${res.status})`, res.status);
  const doc = (await res.json()) as { id?: string; verificationMethod?: Array<{ id?: string; publicKeyJwk?: JWK }> };
  if (doc.id !== iss) throw new MalformedArtifactError("The DID document is not the issuer's", 'iss');
  const method = doc.verificationMethod?.find((m) => m.id === kid);
  if (!method?.publicKeyJwk) throw new KeyNotFoundError(kid ?? '(none)', `The issuer's DID document has no key ${kid}`);
  return method.publicKeyJwk;
}

/**
 * Verify an action receipt: signed by the acting agent's registered key
 * (`kid` = `<agent DID>#keys-1`, typ parafe-action-receipt+jwt), `ver: 1`,
 * `result` success or error (with a known error code). Returns its claims.
 * Check it was indexed with `verifySessionIndex`.
 */
export async function verifyActionReceipt(
  jws: string,
  opts: ActionReceiptOptions = {}
): Promise<VerifyResult<ActionReceiptClaims>> {
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  let keyId: string | undefined;
  try {
    let header;
    let unverified;
    try {
      header = decodeProtectedHeader(jws);
      unverified = decodeJwt(jws);
    } catch (err) {
      throw new MalformedArtifactError('Not a compact JWS', undefined, err);
    }
    if (header.typ !== ACTION_RECEIPT_TYP) throw new MalformedArtifactError(`typ must be ${ACTION_RECEIPT_TYP}`, 'typ');
    if (typeof unverified.iss !== 'string') throw new MalformedArtifactError('iss is required', 'iss');
    const jwk = await issuerJwk(unverified.iss, header.kid, opts);
    keyId = header.kid;
    const alg = jwk.kty === 'EC' ? 'ES256' : 'EdDSA';
    if (header.alg !== alg) throw new InvalidSignatureError(`The issuer's key signs ${alg}, the receipt says ${header.alg}`);
    const { payload } = await jwtVerify(jws, await importJWK(jwk, alg), {
      typ: ACTION_RECEIPT_TYP, algorithms: [alg], issuer: unverified.iss, clockTolerance: 60,
      ...(opts.now ? { currentDate: opts.now } : {}),
    });
    const p = payload as Record<string, unknown>;
    if (p['ver'] !== 1) throw new MalformedArtifactError('Not a v1 action receipt (ver)', 'ver');
    for (const f of ['session_id', 'consent_ref', 'action', 'jti'] as const) {
      if (typeof p[f] !== 'string' || !p[f]) throw new MalformedArtifactError(`Action receipt missing "${f}"`, f);
    }
    if (typeof p['iat'] !== 'number') throw new MalformedArtifactError('iat is required', 'iat');
    const nowSec = Math.floor((opts.now ?? new Date()).getTime() / 1000);
    if ((p['iat'] as number) > nowSec + 60) throw new MalformedArtifactError('iat is in the future', 'iat');
    if (p['result'] !== 'success' && p['result'] !== 'error') throw new MalformedArtifactError("result must be 'success' or 'error'", 'result');
    if (p['result'] === 'error' && !(ACTION_ERROR_CODES as readonly unknown[]).includes(p['error'])) {
      throw new MalformedArtifactError(`error must be one of ${ACTION_ERROR_CODES.join(', ')}`, 'error');
    }
    if (p['result'] === 'success' && p['error'] != null) throw new MalformedArtifactError("error must be null on 'success'", 'error');
    if (opts.expectedSessionId !== undefined && p['session_id'] !== opts.expectedSessionId) {
      throw new MalformedArtifactError('The receipt is for another session', 'session_id');
    }
    if (opts.consentToken !== undefined && p['consent_ref'] !== consentRef(opts.consentToken)) {
      throw new MalformedArtifactError('The receipt is bound to another consent token', 'consent_ref');
    }
    return { valid: true, claims: payload as unknown as ActionReceiptClaims, format: 'action-receipt', keyId, verifiedAt };
  } catch (err) {
    if (err instanceof VerifyError && err.code === 'KEY_FETCH_FAILED') throw err;
    const error = err instanceof VerifyError ? err : coerceJoseError(err, jws, '');
    return { valid: false, error: error ?? new InvalidSignatureError(), format: 'action-receipt', keyId, verifiedAt };
  }
}

/**
 * Verify an index acknowledgment: the broker's signed statement that a receipt
 * was filed at `seq` in a session's chain (typ parafe-index-ack+jwt, the
 * broker's ES256 key). `opts.expectedIssuer`, when set, is compared to `iss`
 * (the broker DID).
 */
export async function verifyIndexAck(
  jws: string,
  opts: VerifyOptions
): Promise<VerifyResult<IndexAckClaims>> {
  const verifiedAt = (opts.now ?? new Date()).toISOString();
  let keyId: string | undefined;
  const verifyOpts: Parameters<typeof jwtVerify>[2] = { typ: INDEX_ACK_TYP, algorithms: ['ES256'] };
  if (opts.expectedIssuer !== undefined) verifyOpts.issuer = opts.expectedIssuer;
  if (opts.clockToleranceSec !== undefined) verifyOpts.clockTolerance = opts.clockToleranceSec;
  if (opts.now !== undefined) verifyOpts.currentDate = opts.now;
  try {
    const { payload } = await jwtVerify(jws, async (header) => {
      const found = await brokerKeyFor(opts.key, header);
      keyId = found.keyId;
      return found.key;
    }, verifyOpts);
    const p = payload as Record<string, unknown>;
    if (p['ver'] !== 1) throw new MalformedArtifactError('Not a v1 index acknowledgment (ver)', 'ver');
    if (typeof p['seq'] !== 'number' || typeof p['receipt_hash'] !== 'string' || typeof p['entry_hash'] !== 'string') {
      throw new MalformedArtifactError('Acknowledgment missing seq, receipt_hash or entry_hash');
    }
    if (p['entry_hash'] !== entryHash(p['seq'] as number, p['receipt_hash'] as string, (p['prev'] as string | null) ?? null)) {
      throw new MalformedArtifactError('entry_hash does not recompute from seq, receipt_hash and prev', 'entry_hash');
    }
    return { valid: true, claims: payload as unknown as IndexAckClaims, format: 'index-ack', keyId, verifiedAt };
  } catch (err) {
    if (err instanceof VerifyError && (err.code === 'KEY_FETCH_FAILED' || err.code === 'KEY_PIN_MISMATCH')) throw err;
    const error = err instanceof VerifyError ? err : coerceJoseError(err, jws, opts.expectedIssuer ?? '');
    return { valid: false, error: error ?? new InvalidSignatureError(), format: 'index-ack', keyId, verifiedAt };
  }
}

export interface SessionIndexOptions {
  /** Action receipts (or AP2 receipts) you hold: each must be listed on the session receipt. */
  receipts?: string[];
  /** Index acknowledgments you hold: each must be broker-signed and match the listed entry. */
  acknowledgments?: string[];
  /** Needed to check acknowledgments (the broker's keys). */
  key?: VerifyOptions['key'];
  now?: Date;
}

export interface SessionIndexResult {
  valid: boolean;
  /** The chain head recomputed from the receipt's `actions`. */
  chainHead: string | null;
  /** For each receipt you passed, its entry on the session receipt (null: not listed). */
  listed: Array<{ receiptHash: string; seq: number | null }>;
  error?: VerifyError;
}

/**
 * Check a session receipt's index: the `actions` list recomputes to its
 * `chain_head`; every receipt you hold is listed; every acknowledgment you hold
 * is broker-signed and matches its entry. Verify the session receipt itself
 * first (`verifyReceipt`) and pass its claims.
 */
export async function verifySessionIndex(
  session: Pick<ReceiptV2Payload, 'session_id' | 'actions' | 'chain_head'>,
  opts: SessionIndexOptions = {}
): Promise<SessionIndexResult> {
  const actions = Array.isArray(session.actions) ? session.actions : [];
  let prev: string | null = null;
  let chainHead: string | null = null;
  const listed = (opts.receipts ?? []).map((r) => {
    const h = receiptHash(r);
    const entry = actions.find((a) => a.receipt_hash === h);
    return { receiptHash: h, seq: entry ? entry.seq : null };
  });
  const chain: string[] = [];
  try {
    for (const [i, a] of actions.entries()) {
      if (a.seq !== i + 1) throw new MalformedArtifactError(`actions[${i}] has seq ${a.seq}, expected ${i + 1}`, 'actions');
      prev = entryHash(a.seq, a.receipt_hash, prev);
      chain.push(prev);
    }
    chainHead = prev;
    if ((session.chain_head ?? null) !== chainHead) throw new MalformedArtifactError('chain_head does not recompute from actions', 'chain_head');
    const missing = listed.filter((l) => l.seq === null);
    if (missing.length) throw new MalformedArtifactError(`${missing.length} receipt(s) not listed on the session receipt`, 'actions');
    if (opts.acknowledgments?.length) {
      if (!opts.key) throw new MalformedArtifactError('Pass key (the broker key source) to check acknowledgments');
      for (const ack of opts.acknowledgments) {
        const res = await verifyIndexAck(ack, { key: opts.key, ...(opts.now ? { now: opts.now } : {}) });
        if (!res.valid || !res.claims) throw res.error ?? new InvalidSignatureError('Acknowledgment does not verify');
        const c = res.claims;
        const entry = actions[c.seq - 1];
        if (c.session_id !== session.session_id) throw new MalformedArtifactError(`Acknowledgment ${c.seq} is for another session`, 'session_id');
        if (!entry || entry.receipt_hash !== c.receipt_hash || entry.kind !== c.kind || chain[c.seq - 1] !== c.entry_hash) {
          throw new MalformedArtifactError(`Acknowledgment ${c.seq} does not match the session receipt's entry`, 'actions');
        }
      }
    }
    return { valid: true, chainHead, listed };
  } catch (err) {
    const error = err instanceof VerifyError ? err : new MalformedArtifactError(String(err));
    return { valid: false, chainHead, listed, error };
  }
}
