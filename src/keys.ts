import { importSPKI, type KeyLike } from 'jose';
import { sha256 } from '@noble/hashes/sha256';
import { KeyFetchError, KeyPinningError } from './errors.js';
import { derBase64ToPem, rawEd25519FromSpkiDer, bytesToBase64 } from './internal/base64.js';
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

export interface PublicKeySource {
  resolve(): Promise<ResolvedPublicKey>;
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

  let cache: { resolved: ResolvedPublicKey; fetchedAt: number } | null = null;
  let inflight: Promise<ResolvedPublicKey> | null = null;

  async function doFetch(): Promise<ResolvedPublicKey> {
    const url = `${brokerUrl}/public-key`;
    let response: Response;
    try {
      response = await fetchImpl(url);
    } catch (err) {
      throw new KeyFetchError(url, `Could not reach ${url}: ${err instanceof Error ? err.message : String(err)}`, undefined, err);
    }
    if (!response.ok) {
      throw new KeyFetchError(url, `Broker returned ${response.status} fetching public key`, response.status);
    }
    let body: PublicKeyResponse;
    try {
      body = (await response.json()) as PublicKeyResponse;
    } catch (err) {
      throw new KeyFetchError(url, 'Broker returned non-JSON response for /public-key', response.status, err);
    }
    if (typeof body.public_key !== 'string' || typeof body.key_id !== 'string' || typeof body.algorithm !== 'string') {
      throw new KeyFetchError(url, 'Unexpected /public-key response shape: expected { public_key, algorithm, key_id }', response.status);
    }
    if (body.algorithm !== 'Ed25519') {
      throw new KeyFetchError(url, `Unsupported key algorithm "${body.algorithm}" — this library only verifies Ed25519`, response.status);
    }
    const resolved = await buildResolved(body);
    enforcePin(resolved, pin);
    return resolved;
  }

  return {
    async resolve(): Promise<ResolvedPublicKey> {
      const now = Date.now();
      if (cache && now - cache.fetchedAt < ttlMs) return cache.resolved;
      if (inflight) return inflight;
      inflight = doFetch()
        .then((resolved) => {
          cache = { resolved, fetchedAt: Date.now() };
          return resolved;
        })
        .finally(() => {
          inflight = null;
        });
      return inflight;
    },
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
  return {
    async resolve(): Promise<ResolvedPublicKey> {
      const resolved = await source.resolve();
      enforcePin(resolved, pin);
      return resolved;
    },
  };
}

/** Helper: compute the SHA-256 hex thumbprint of a base64 SPKI DER public key. */
export function computeKeyThumbprint(base64SpkiDer: string): string {
  return hexThumbprint(base64SpkiDer);
}

/** Helper: compute a base64 thumbprint of raw bytes (exposed for testing). */
export { bytesToBase64 };
