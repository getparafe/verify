/**
 * AP2 Delegate SD-JWT chains (draft-gco-oauth-delegate-sd-jwt-00, AP2 v0.2).
 *
 * A chain is `~~`-joined SD-JWTs: a root signed by an issuer the verifier
 * trusts, then KB-SD-JWT hops, each signed by the key in the previous hop's
 * `cnf.jwk`. Parsing, disclosure decoding and digests use the OpenWallet
 * Foundation library (`@sd-jwt/core` >= 0.20, which absorbed `@sd-jwt/decode`
 * and fixed GHSA-f9j6-8p6x-r9j6); disclosures are resolved with its
 * `unpackObj`. OWF drops what isn't disclosed without saying so, so a strict
 * pass here also records every withheld digest (and checks RFC 9901 §7.1
 * itself: unreferenced, duplicate and misplaced disclosures). The two must
 * produce the same claims.
 */
import { compactVerify, importJWK, calculateJwkThumbprint, type JWK, type KeyLike } from 'jose';
import { decodeJwt as owfDecodeJwt, unpackObj, createHashMappingSync, Disclosure } from '@sd-jwt/core';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { canonicalize } from '../canonicalize.js';
import { Ap2Failure } from './errors.js';

export const KB_TYP_TERMINAL = ['kb+sd-jwt', 'kb-sd-jwt'];
export const KB_TYP_INTERMEDIATE = ['kb+sd-jwt+kb', 'kb-sd-jwt+kb'];
const SIG_ALGS = ['ES256', 'ES384', 'ES512', 'EdDSA'];

const HASHES: Record<string, (b: Uint8Array) => Uint8Array> = {
  'sha-256': sha256,
  'sha-384': sha384,
  'sha-512': sha512,
};

function hashFn(alg: string): (b: Uint8Array) => Uint8Array {
  const f = HASHES[alg];
  if (!f) throw new Ap2Failure('invalid_credential', 'unsupported_sd_alg', `Unsupported _sd_alg "${alg}"`);
  return f;
}

/** OWF hasher signature: (data, alg) => digest bytes. */
export const owfHasher = (data: string | ArrayBuffer, alg: string): Uint8Array =>
  hashFn(alg.toLowerCase())(typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data));

export function b64u(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url(hash(ascii string)), the way AP2 hashes tokens, JWTs and disclosures. */
export function hashAscii(value: string, sdAlg = 'sha-256'): string {
  return b64u(hashFn(sdAlg)(new TextEncoder().encode(value)));
}

/** Where a withheld (undisclosed) digest sat, relative to the delegate item or the payload. */
export interface Withheld {
  path: (string | number)[];
  /** `property`: an `_sd` entry of the object at `path`; `element`: an element of the array at `path`. */
  kind: 'property' | 'element';
}

export interface Segment {
  index: number;
  /** The segment exactly as presented, ending in `~`. */
  raw: string;
  issuerJwt: string;
  header: Record<string, unknown>;
  /** The signed payload, before disclosures. */
  payload: Record<string, unknown>;
  sdAlg: string;
  disclosures: string[];
  /** Payload with disclosures resolved (OWF `unpackObj`). */
  claims: Record<string, unknown>;
  /** The one disclosed `delegate_payload` item, resolved; absent when the segment has no `delegate_payload`. */
  item?: Record<string, unknown>;
  /** Digests withheld inside `item` (paths relative to the item). */
  itemWithheld: Withheld[];
  /** Digests withheld elsewhere in the payload. */
  withheld: Withheld[];
}

/** Split a `~~`-joined chain; every segment comes back ending in `~`, exactly as it was presented. */
export function splitChain(chain: string): string[] {
  if (typeof chain !== 'string' || !chain) throw new Ap2Failure('invalid_credential', 'malformed', 'Mandate must be a non-empty string');
  if (!chain.endsWith('~')) {
    throw new Ap2Failure('invalid_credential', 'malformed', 'The chain must end with "~": a key-binding JWT after the last segment is not used in AP2 (each hop is a KB-SD-JWT)');
  }
  const parts = chain.split('~~');
  return parts.map((p, i) => (i === parts.length - 1 ? p : `${p}~`));
}

/** Parse one segment (no signature check): issuer JWT, disclosures, resolved claims. */
export function parseSegment(raw: string, index: number): Segment {
  const parts = raw.split('~');
  const issuerJwt = parts[0] ?? '';
  if (!issuerJwt || parts[parts.length - 1] !== '') {
    throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index} is not an SD-JWT ending in "~"`);
  }
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => !d)) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index} has an empty disclosure`);
  const jwtParts = issuerJwt.split('.');
  if (jwtParts.length !== 3) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: the issuer JWT must be header.payload.signature`);
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    ({ header, payload } = owfDecodeJwt(issuerJwt) as { header: Record<string, unknown>; payload: Record<string, unknown> });
  } catch (err) {
    throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: ${(err as Error).message}`);
  }
  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: the JWT header and payload must be JSON objects`);
  }
  const sdAlg = payload._sd_alg === undefined ? 'sha-256' : String(payload._sd_alg).toLowerCase();
  hashFn(sdAlg);

  const hasher = { hasher: owfHasher, alg: sdAlg };
  let parsed: Disclosure[];
  try {
    parsed = disclosures.map((d) => Disclosure.fromEncodeSync(d, hasher));
  } catch (err) {
    throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: a disclosure isn't valid (${(err as Error).message})`);
  }
  const byDigest = new Map<string, Disclosure>();
  for (const d of parsed) {
    const digest = d.digestSync(hasher);
    if (byDigest.has(digest)) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: the same disclosure appears twice`);
    const arr = d.decode();
    if (!Array.isArray(arr) || typeof arr[0] !== 'string' || (arr.length === 3 && (typeof arr[1] !== 'string' || !arr[1])) || (arr.length !== 2 && arr.length !== 3)) {
      throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: a disclosure isn't [salt, value] or [salt, name, value]`);
    }
    byDigest.set(digest, d);
  }

  // Strict pass: resolve like RFC 9901 §7.1, recording withheld digests.
  const used = new Set<string>();
  const withheldAt: Withheld[] = [];
  const strict = (value: unknown, path: (string | number)[]): unknown => {
    if (Array.isArray(value)) {
      const out: unknown[] = [];
      value.forEach((el, i) => {
        if (el && typeof el === 'object' && !Array.isArray(el) && '...' in el) {
          const keys = Object.keys(el);
          const digest = (el as Record<string, unknown>)['...'];
          if (keys.length !== 1 || typeof digest !== 'string') throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: a malformed array digest at ${path.join('.')}`);
          const d = byDigest.get(digest);
          if (!d) { withheldAt.push({ path, kind: 'element' }); return; }
          if (used.has(digest)) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: a digest is referenced twice`);
          if (d.key !== undefined) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: an array element's disclosure carries a claim name`);
          used.add(digest);
          out.push(strict(d.value, [...path, i]));
        } else {
          out.push(strict(el, [...path, i]));
        }
      });
      return out;
    }
    if (value && typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k === '_sd') continue;
        if (k === '...') throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: "..." outside an array at ${path.join('.')}`);
        out[k] = strict(v, [...path, k]);
      }
      if (obj._sd !== undefined) {
        if (!Array.isArray(obj._sd) || obj._sd.some((x) => typeof x !== 'string')) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: _sd must be a list of digests`);
        for (const digest of obj._sd as string[]) {
          const d = byDigest.get(digest);
          if (!d) { withheldAt.push({ path, kind: 'property' }); continue; }
          if (used.has(digest)) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: a digest is referenced twice`);
          if (d.key === undefined || d.key === '_sd' || d.key === '...') throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: an object disclosure needs a claim name`);
          if (d.key in out) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: disclosure "${d.key}" overrides a claim`);
          used.add(digest);
          out[d.key] = strict(d.value, [...path, d.key]);
        }
      }
      return out;
    }
    return value;
  };
  const payloadNoAlg: Record<string, unknown> = { ...payload };
  delete payloadNoAlg._sd_alg;
  const strictClaims = strict(payloadNoAlg, []) as Record<string, unknown>;
  if (used.size !== byDigest.size) {
    throw new Ap2Failure('invalid_credential', 'unreferenced_disclosure', `Segment ${index}: a disclosure isn't referenced by the payload (not one the signer committed to)`);
  }

  // The claims themselves come from the OWF library; they must agree.
  const owfMap = createHashMappingSync(parsed, hasher);
  const { unpackedObj } = unpackObj(payloadNoAlg, owfMap) as { unpackedObj: Record<string, unknown> };
  if (canonicalize(unpackedObj) !== canonicalize(strictClaims)) {
    throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: disclosures resolve inconsistently`);
  }
  const claims = unpackedObj;

  const seg: Segment = { index, raw, issuerJwt, header, payload, sdAlg, disclosures, claims, itemWithheld: [], withheld: [] };
  const dp = payload.delegate_payload;
  if (dp !== undefined) {
    if (!Array.isArray(dp)) throw new Ap2Failure('invalid_credential', 'malformed', `Segment ${index}: delegate_payload must be an array`);
    const items = claims.delegate_payload as unknown[];
    if (items.length !== 1 || !items[0] || typeof items[0] !== 'object' || Array.isArray(items[0])) {
      throw new Ap2Failure('invalid_credential', 'chain_shape', `Segment ${index}: delegate_payload must disclose exactly one mandate (it discloses ${items.length})`);
    }
    seg.item = items[0] as Record<string, unknown>;
  }
  for (const w of withheldAt) {
    if (w.path[0] === 'delegate_payload' && w.path.length >= 2) seg.itemWithheld.push({ path: w.path.slice(2), kind: w.kind });
    else if (w.path[0] === 'delegate_payload' && w.path.length === 1 && w.kind === 'element') continue; // other delegate items, not presented
    else seg.withheld.push(w);
  }
  return seg;
}

async function keyFrom(jwk: JWK): Promise<KeyLike | Uint8Array> {
  const { alg: _a, use: _u, key_ops: _k, ...pub } = jwk as JWK & { key_ops?: unknown };
  if ('d' in pub) throw new Ap2Failure('invalid_credential', 'malformed', 'A private key was given where a public key belongs');
  const alg = pub.kty === 'OKP' ? 'EdDSA' : pub.crv === 'P-384' ? 'ES384' : pub.crv === 'P-521' ? 'ES512' : 'ES256';
  return importJWK(pub, alg);
}

/** Verify a segment's signature with a public JWK; the signed payload must be what was parsed. */
export async function verifySegmentSignature(seg: Segment, jwk: JWK): Promise<boolean> {
  try {
    const { payload, protectedHeader } = await compactVerify(seg.issuerJwt, await keyFrom(jwk), { algorithms: SIG_ALGS });
    if (protectedHeader.alg === 'none') return false;
    return canonicalize(JSON.parse(new TextDecoder().decode(payload))) === canonicalize(seg.payload);
  } catch (err) {
    if (err instanceof Ap2Failure) throw err;
    return false;
  }
}

/** The key this segment endorses for the next hop: the disclosed item's `cnf.jwk`, else the payload's. */
export function cnfJwk(seg: Segment): JWK | undefined {
  const fromItem = (seg.item?.cnf as { jwk?: JWK } | undefined)?.jwk;
  if (fromItem && typeof fromItem === 'object') return fromItem;
  const top = (seg.claims.cnf as { jwk?: JWK } | undefined)?.jwk;
  return top && typeof top === 'object' ? top : undefined;
}

export async function thumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk as JWK);
}

/** sd_hash of a presented segment: hash over `<issuer JWT>~<disclosures>~` (no KB-JWT). */
export function sdHash(seg: Segment): string {
  return hashAscii(seg.raw, seg.sdAlg);
}

/** issuer_jwt_hash of a segment: hash over the issuer-signed JWT only. */
export function issuerJwtHash(seg: Segment): string {
  return hashAscii(seg.issuerJwt, seg.sdAlg);
}
