import { importSPKI, importJWK, type KeyLike, type JWK } from 'jose';
import { sha256 } from '@noble/hashes/sha256';
import { KeyFetchError, KeyPinningError } from './errors.js';
import { derBase64ToPem, rawEd25519FromSpkiDer, bytesToBase64, base64UrlToBytes } from './internal/base64.js';
import type { PublicKeyResponse } from './types.js';

export interface ResolvedPublicKey {
  /** PEM-wrapped SPKI DER — ready for jose.importSPKI */
  spkiPem: string;
  /** jose KeyLike object (imported SPKI, algorithm EdDSA) — ready for jwtVerify */
  josePublicKey: KeyLike;
  /** 32-byte raw Ed25519 public key — for raw signature checks */
  rawBytes: Uint8Array;
  /** Key identifier reported by the broker, e.g., 'parafe-signing-key-v1' */
  keyId: string;
  /** SHA-256 thumbprint of the base64 SPKI DER, hex-encoded */
  thumbprintSha256: string;
  /** Algorithm reported by the broker (expected: 'Ed25519') */
  algorithm: string;
}

/** One broker signing key from the JWKS, ready to verify with. */
export interface ResolvedJwk {
  kid: string;
  alg: 'ES256' | 'EdDSA' | string;
  status: 'active' | 'retired' | string;
  jwk: JWK;
  josePublicKey: KeyLike | Uint8Array;
}

export interface PublicKeySource {
  /**
   * The broker's Ed25519 key: it signed v1 receipts and tokens issued before
   * 2026-09-30 (no `kid`). For a JWKS source, the retired Ed25519 key.
   */
  resolve(): Promise<ResolvedPublicKey>;
  /**
   * Every broker key (the JWKS), for artifacts that name their key with `kid`
   * (everything since 2026-09-30, ES256). Absent on a single-key source such as
   * `staticKey()`, which can only verify Ed25519 artifacts.
   */
  resolveKeySet?(): Promise<ResolvedJwk[]>;
}

export interface Jwks {
  keys: Array<JWK & { kid: string; alg?: string; status?: string }>;
}

export interface KeyPin {
  keyId?: string;
  /** Hex-encoded SHA-256 of the base64 SPKI DER */
  thumbprintSha256?: string;
}

export interface PublicKeySourceOptions {
  /** Broker base URL. Defaults to https://api.parafe.ai. Trailing slash optional. */
  brokerUrl?: string;
  /** How long to cache the fetched key, in ms. Defaults to 24 hours. */
  cacheTtlMs?: number;
  /** Enforce a specific key_id and/or thumbprint on every resolve. */
  pin?: KeyPin;
  /** Override fetch (useful for tests, edge runtimes, custom agents). */
  fetch?: typeof fetch;
}

const DEFAULT_BROKER_URL = 'https://api.parafe.ai';
const ED25519_SPKI_PREFIX = 'MCowBQYDK2VwAyEA'; // base64 of the 12-byte Ed25519 SPKI header

/** Base64 SPKI DER for a raw Ed25519 key given as JWK `x`. */
function ed25519SpkiFromX(x: string): string {
  const raw = base64UrlToBytes(x);
  return bytesToBase64(new Uint8Array([...base64ToBytesStrict(ED25519_SPKI_PREFIX), ...raw]));
}
function base64ToBytesStrict(b64: string): Uint8Array {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function buildKeySet(jwks: Jwks): Promise<ResolvedJwk[]> {
  if (!jwks || !Array.isArray(jwks.keys)) throw new Error('JWKS must have a keys array');
  return Promise.all(jwks.keys.map(async (k) => {
    const alg = k.alg ?? (k.kty === 'OKP' ? 'EdDSA' : 'ES256');
    if (alg !== 'ES256' && alg !== 'EdDSA') throw new Error(`Unsupported broker key algorithm "${alg}"`);
    const { kty, crv, x, y } = k;
    const jwk = (y ? { kty, crv, x, y } : { kty, crv, x }) as JWK;
    return { kid: k.kid, alg, status: k.status ?? 'active', jwk, josePublicKey: await importJWK(jwk, alg) };
  }));
}

/** The legacy Ed25519 key (as ResolvedPublicKey) from a key set. */
async function legacyFromKeySet(set: ResolvedJwk[], keyId?: string): Promise<ResolvedPublicKey> {
  const ed = set.find((k) => k.alg === 'EdDSA');
  if (!ed || typeof ed.jwk.x !== 'string') throw new Error('The broker JWKS has no Ed25519 key');
  return buildResolved({ public_key: ed25519SpkiFromX(ed.jwk.x), algorithm: 'Ed25519', key_id: keyId ?? ed.kid });
}
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

function hexThumbprint(base64SpkiDer: string): string {
  const digest = sha256(new TextEncoder().encode(base64SpkiDer));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function buildResolved(res: PublicKeyResponse): Promise<ResolvedPublicKey> {
  const spkiPem = derBase64ToPem(res.public_key);
  const josePublicKey = await importSPKI(spkiPem, 'EdDSA');
  return {
    spkiPem,
    josePublicKey: josePublicKey as KeyLike,
    rawBytes: rawEd25519FromSpkiDer(res.public_key),
    keyId: res.key_id,
    thumbprintSha256: hexThumbprint(res.public_key),
    algorithm: res.algorithm,
  };
}

function enforcePin(resolved: ResolvedPublicKey, pin?: KeyPin): void {
  if (!pin) return;
  if (pin.keyId !== undefined && pin.keyId !== resolved.keyId) {
    throw new KeyPinningError('keyId', pin.keyId, resolved.keyId);
  }
  if (pin.thumbprintSha256 !== undefined) {
    const expected = pin.thumbprintSha256.toLowerCase();
    const actual = resolved.thumbprintSha256.toLowerCase();
    if (expected !== actual) throw new KeyPinningError('thumbprintSha256', expected, actual);
  }
}

/**
 * Create a PublicKeySource that fetches Parafe's public key once, caches it,
 * and optionally enforces pinning. Safe to share across many verify() calls.
 */
export function createPublicKeySource(opts: PublicKeySourceOptions = {}): PublicKeySource {
  const brokerUrl = (opts.brokerUrl ?? DEFAULT_BROKER_URL).replace(/\/$/, '');
  const ttlMs = opts.cacheTtlMs ?? DEFAULT_TTL_MS;
  const fetchImpl = opts.fetch ?? (globalThis.fetch as typeof fetch);
  const pin = opts.pin;

  interface Loaded { set: ResolvedJwk[] | null; legacy: ResolvedPublicKey | null }
  let cache: { loaded: Loaded; fetchedAt: number } | null = null;
  let inflight: Promise<Loaded> | null = null;

  async function getJson(url: string): Promise<{ status: number; body: unknown }> {
    let response: Response;
    try {
      response = await fetchImpl(url);
    } catch (err) {
      throw new KeyFetchError(url, `Could not reach ${url}: ${err instanceof Error ? err.message : String(err)}`, undefined, err);
    }
    if (!response.ok) return { status: response.status, body: null };
    try {
      return { status: response.status, body: await response.json() };
    } catch (err) {
      throw new KeyFetchError(url, `Broker returned non-JSON response for ${url}`, response.status, err);
    }
  }

  // The JWKS (every key, by kid); a broker from before 2026-09-30 has only /public-key.
  async function doFetch(): Promise<Loaded> {
    const jwksUrl = `${brokerUrl}/.well-known/jwks.json`;
    const jwks = await getJson(jwksUrl);
    if (jwks.body) {
      let set: ResolvedJwk[];
      try {
        set = await buildKeySet(jwks.body as Jwks);
      } catch (err) {
        throw new KeyFetchError(jwksUrl, `Unexpected JWKS: ${err instanceof Error ? err.message : String(err)}`, jwks.status, err);
      }
      let legacy: ResolvedPublicKey | null = null;
      try { legacy = await legacyFromKeySet(set); } catch { /* a broker with no Ed25519 key */ }
      return { set, legacy };
    }
    if (jwks.status !== 404) throw new KeyFetchError(jwksUrl, `Broker returned ${jwks.status} fetching its JWKS`, jwks.status);

    const url = `${brokerUrl}/public-key`;
    const res = await getJson(url);
    if (!res.body) throw new KeyFetchError(url, `Broker returned ${res.status} fetching public key`, res.status);
    const body = res.body as PublicKeyResponse;
    if (typeof body.public_key !== 'string' || typeof body.key_id !== 'string' || typeof body.algorithm !== 'string') {
      throw new KeyFetchError(url, 'Unexpected /public-key response shape: expected { public_key, algorithm, key_id }', res.status);
    }
    if (body.algorithm !== 'Ed25519') {
      throw new KeyFetchError(url, `Unsupported key algorithm "${body.algorithm}"`, res.status);
    }
    return { set: null, legacy: await buildResolved(body) };
  }

  async function load(): Promise<Loaded> {
    const now = Date.now();
    if (cache && now - cache.fetchedAt < ttlMs) return cache.loaded;
    if (inflight) return inflight;
    inflight = doFetch()
      .then((loaded) => {
        cache = { loaded, fetchedAt: Date.now() };
        return loaded;
      })
      .finally(() => {
        inflight = null;
      });
    return inflight;
  }

  return {
    async resolve(): Promise<ResolvedPublicKey> {
      const { legacy } = await load();
      if (!legacy) throw new KeyFetchError(brokerUrl, 'The broker publishes no Ed25519 key');
      enforcePin(legacy, pin);
      return legacy;
    },
    async resolveKeySet(): Promise<ResolvedJwk[]> {
      const { set, legacy } = await load();
      if (set) {
        if (pin?.keyId !== undefined && !set.some((k) => k.kid === pin.keyId)) {
          throw new KeyPinningError('keyId', pin.keyId, set.map((k) => k.kid).join(', '));
        }
        return pin?.keyId !== undefined ? set.filter((k) => k.kid === pin.keyId) : set;
      }
      // Pre-JWKS broker: its single Ed25519 key, with no kid.
      if (!legacy) return [];
      enforcePin(legacy, pin);
      return [{ kid: legacy.keyId, alg: 'EdDSA', status: 'active', jwk: { kty: 'OKP', crv: 'Ed25519', x: '' } as JWK, josePublicKey: legacy.josePublicKey }];
    },
  };
}

/**
 * Create a PublicKeySource from a JWKS you already have (e.g. the broker's
 * /.well-known/jwks.json, pinned into your build). Never touches the network.
 */
export function staticJwks(jwks: Jwks): PublicKeySource {
  let set: Promise<ResolvedJwk[]> | null = null;
  const load = () => (set ??= buildKeySet(jwks));
  return {
    async resolve(): Promise<ResolvedPublicKey> {
      return legacyFromKeySet(await load());
    },
    resolveKeySet: load,
  };
}

/**
 * Create a PublicKeySource from a key you already have. Never touches the network.
 * Use for air-gapped environments or when you've pinned the key into your build.
 */
export function staticKey(base64SpkiDer: string, keyId = 'parafe-signing-key-v1'): PublicKeySource {
  let cached: Promise<ResolvedPublicKey> | null = null;
  return {
    resolve(): Promise<ResolvedPublicKey> {
      if (!cached) {
        cached = buildResolved({
          public_key: base64SpkiDer,
          algorithm: 'Ed25519',
          key_id: keyId,
        });
      }
      return cached;
    },
  };
}

/**
 * Wrap an existing PublicKeySource with additional pinning checks.
 * Each resolve() re-validates the pin — useful when layering pins onto a pre-built source.
 */
export function pinKey(source: PublicKeySource, pin: KeyPin): PublicKeySource {
  const pinned: PublicKeySource = {
    async resolve(): Promise<ResolvedPublicKey> {
      const resolved = await source.resolve();
      enforcePin(resolved, pin);
      return resolved;
    },
  };
  if (source.resolveKeySet) {
    const inner = source.resolveKeySet.bind(source);
    // A keyId pin restricts the JWKS to that kid.
    pinned.resolveKeySet = async () => {
      const set = await inner();
      if (pin.keyId === undefined) return set;
      const kept = set.filter((k) => k.kid === pin.keyId);
      if (!kept.length) throw new KeyPinningError('keyId', pin.keyId, set.map((k) => k.kid).join(', '));
      return kept;
    };
  }
  return pinned;
}

/** Helper: compute the SHA-256 hex thumbprint of a base64 SPKI DER public key. */
export function computeKeyThumbprint(base64SpkiDer: string): string {
  return hexThumbprint(base64SpkiDer);
}

/** Helper: compute a base64 thumbprint of raw bytes (exposed for testing). */
export { bytesToBase64 };
