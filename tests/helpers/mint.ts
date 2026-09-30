import { generateKeyPair, exportSPKI, SignJWT, type KeyLike } from 'jose';
import { createPrivateKey, createPublicKey, sign as nodeSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { staticKey, type PublicKeySource } from '../../src/keys.js';
import { canonicalize } from '../../src/canonicalize.js';

/**
 * Test keyring backed by Node's crypto module so we can exercise both the jose
 * (JWT) and node:crypto (raw Ed25519 signing used by receipts) paths
 * against the same public key the real broker would expose.
 */
export interface TestKeyring {
  joseSigningKey: KeyLike;
  josePublicKey: KeyLike;
  nodePrivateKey: KeyObject;
  nodePublicKey: KeyObject;
  publicKeyBase64Der: string;
  keySource: PublicKeySource;
  keyId: string;
}

export async function createTestKeyring(keyId = 'test-signing-key-v1'): Promise<TestKeyring> {
  // Generate with node:crypto so we can use crypto.sign() with null algorithm (raw Ed25519).
  const { publicKey: nodePublicKey, privateKey: nodePrivateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = nodePublicKey.export({ format: 'pem', type: 'spki' }) as string;
  const privateKeyPem = nodePrivateKey.export({ format: 'pem', type: 'pkcs8' }) as string;

  const publicKeyBase64Der = pemToBase64Der(publicKeyPem);

  // Re-import through jose so the JWT path works with the same key material.
  const { importSPKI, importPKCS8 } = await import('jose');
  const josePublicKey = await importSPKI(publicKeyPem, 'EdDSA');
  const joseSigningKey = await importPKCS8(privateKeyPem, 'EdDSA');

  return {
    joseSigningKey: joseSigningKey as KeyLike,
    josePublicKey: josePublicKey as KeyLike,
    nodePrivateKey: createPrivateKey(privateKeyPem),
    nodePublicKey: createPublicKey(publicKeyPem),
    publicKeyBase64Der,
    keySource: staticKey(publicKeyBase64Der, keyId),
    keyId,
  };
}

function pemToBase64Der(pem: string): string {
  return pem
    .replace(/-----BEGIN (?:PUBLIC|PRIVATE) KEY-----/g, '')
    .replace(/-----END (?:PUBLIC|PRIVATE) KEY-----/g, '')
    .replace(/\s/g, '');
}

// Silence unused-import warning for generateKeyPair in some strict setups
export async function _joseKeygen(): Promise<KeyLike> {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  return privateKey as KeyLike;
}
// Silence unused export helper
void exportSPKI;

const PARAFE_JWT_ISSUER = 'parafe-trust-broker';

// ─────────────── JWT minting ───────────────

export interface MintCredentialInput {
  privateKey: KeyLike;
  sub?: string;
  name?: string;
  owner?: string;
  identity_assurance?: string;
  verification_tier?: string;
  pub_key_thumbprint?: string;
  iat?: number;
  exp?: number;
  iss?: string;
  jti?: string;
}

export async function mintCredential(input: MintCredentialInput): Promise<string> {
  const now = input.iat ?? Math.floor(Date.now() / 1000);
  const exp = input.exp ?? now + 30 * 24 * 60 * 60;
  const builder = new SignJWT({
    sub: input.sub ?? 'prf_agent_test',
    name: input.name ?? 'Test Agent',
    owner: input.owner ?? 'Test Org',
    identity_assurance: input.identity_assurance ?? 'registered',
    verification_tier: input.verification_tier ?? 'email_verified',
    pub_key_thumbprint: input.pub_key_thumbprint ?? 'a'.repeat(64),
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer(input.iss ?? PARAFE_JWT_ISSUER);
  if (input.jti) builder.setJti(input.jti);
  return builder.sign(input.privateKey);
}

export interface MintConsentInput {
  privateKey: KeyLike;
  scope?: string;
  permissions?: string[];
  excluded?: string[];
  session_id?: string;
  authorization_modality?: string;
  initiator_agent_id?: string | null;
  target_agent_id?: string | null;
  iat?: number;
  exp?: number;
  iss?: string;
}

export async function mintConsent(input: MintConsentInput): Promise<string> {
  const now = input.iat ?? Math.floor(Date.now() / 1000);
  const exp = input.exp ?? now + 3600;
  return new SignJWT({
    scope: input.scope ?? 'read_profile',
    permissions: input.permissions ?? ['read:profile'],
    excluded: input.excluded ?? [],
    session_id: input.session_id ?? 'sess_test_123',
    token_type: 'consent',
    authorization_modality: input.authorization_modality ?? 'autonomous',
    initiator_agent_id: input.initiator_agent_id ?? 'prf_agent_initiator',
    target_agent_id: input.target_agent_id ?? 'prf_agent_target',
    parent_token_id: null,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer(input.iss ?? PARAFE_JWT_ISSUER)
    .sign(input.privateKey);
}

function signBroker(nodePrivateKey: KeyObject, canonicalString: string): Buffer {
  return nodeSign(null, Buffer.from(canonicalString), nodePrivateKey);
}

// ─────────────── Receipt minting (matches broker/src/routes/receipt.js) ───────────────

export interface MintReceiptInput {
  nodePrivateKey: KeyObject;
  receipt_id?: string;
  session_id?: string;
  handshake_id?: string;
  issued_at?: string;
}

export function mintSignedReceipt(input: MintReceiptInput): Record<string, unknown> {
  const receipt: Record<string, unknown> = {
    receipt_id: input.receipt_id ?? 'rcpt_testabcdef',
    session_id: input.session_id ?? 'sess_test_123',
    handshake_id: input.handshake_id ?? 'hs_test_123',
    participants: {
      initiator: { agent_id: 'prf_initiator', agent_name: 'Initiator', identity_assurance: 'registered' },
      target: { agent_id: 'prf_target', agent_name: 'Target', identity_assurance: 'registered' },
    },
    handshake: {
      handshake_id: input.handshake_id ?? 'hs_test_123',
      mutual_auth_completed: true,
      completed_at: new Date().toISOString(),
    },
    consent_tokens: [
      { scope: 'read_profile', permissions: ['read:profile'], authorization: 'autonomous', issued_at: new Date().toISOString(), expired_at: new Date(Date.now() + 3600 * 1000).toISOString() },
    ],
    session: {
      started_at: new Date().toISOString(),
      closed_at: new Date().toISOString(),
      status: 'completed',
    },
    signed_by: 'parafe-broker',
    issued_at: input.issued_at ?? new Date().toISOString(),
  };
  const sig = signBroker(input.nodePrivateKey, canonicalize(receipt));
  receipt['signature'] = sig.toString('base64');
  return receipt;
}
