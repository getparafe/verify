/**
 * Generates real fixtures by running a full handshake against a Parafe broker.
 *
 * Usage:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run fixtures:generate
 *   # or against a local broker started with `npm start` from broker/:
 *   npm run fixtures:generate
 *
 * Writes tests/fixtures/{public-key.json, credential.jwt, consent.jwt, receipt.json, ...}
 * for integration tests. The raw artifacts can also be replayed against unit verifiers
 * as a "known-good-from-production" smoke test.
 *
 * This script is NOT run in CI — fixtures are committed. Re-run only when the broker's
 * artifact formats change.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportSPKI, SignJWT, type KeyLike } from 'jose';
import { subtle } from 'node:crypto';

const BROKER_URL = (process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000').replace(/\/$/, '');
const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

interface AgentKeys {
  privateKey: KeyLike;
  publicKeyPem: string;
}

async function freshAgentKeys(): Promise<AgentKeys> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const publicKeyPem = await exportSPKI(publicKey);
  return { privateKey, publicKeyPem };
}

async function signChallenge(privateKey: KeyLike, nonce: string, issuer: string): Promise<string> {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setExpirationTime('5m')
    .sign(privateKey);
}

async function postJson(path: string, body: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(`${BROKER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${path}: ${await res.text()}`);
  }
  return res.json();
}

async function getJson(path: string, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(`${BROKER_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${path}: ${await res.text()}`);
  return res.json();
}

async function main(): Promise<void> {
  mkdirSync(FIXTURES_DIR, { recursive: true });

  console.log(`Generating fixtures against ${BROKER_URL}`);

  // 1. Capture public key
  const pubKey = await getJson('/public-key');
  writeFileSync(join(FIXTURES_DIR, 'public-key.json'), JSON.stringify(pubKey, null, 2));
  console.log('✓ public-key.json');

  // 2. Sign up a developer
  const suffix = Date.now();
  const signup = await postJson('/auth/signup', {
    email: `verify-fixture-${suffix}@test.parafe.ai`,
    password: 'test-password-12345',
    org_name: `Verify Fixtures ${suffix}`,
  });
  const apiKey = signup.api_key as string;
  const authHeader = { 'X-API-Key': apiKey };

  // 3. Register two agents
  const initiator = await freshAgentKeys();
  const target = await freshAgentKeys();
  const initReg = await postJson('/agents/register', {
    agent_name: `initiator-${suffix}`,
    owner_type: 'personal',
    public_key: initiator.publicKeyPem,
  }, authHeader);
  const targReg = await postJson('/agents/register', {
    agent_name: `target-${suffix}`,
    owner_type: 'personal',
    public_key: target.publicKeyPem,
  }, authHeader);

  writeFileSync(join(FIXTURES_DIR, 'credential.jwt'), initReg.credential);
  writeFileSync(join(FIXTURES_DIR, 'credential.vdc.json'), JSON.stringify(initReg.credential_vdc, null, 2));
  console.log('✓ credential.jwt + credential.vdc.json');

  // 4. Handshake
  const initiate = await postJson('/handshake/initiate', {
    initiator_agent_id: initReg.agent_id,
    target_agent_id: targReg.agent_id,
    scope: 'read_profile',
  }, authHeader);

  const initProof = await signChallenge(initiator.privateKey, initiate.initiator_challenge, initReg.agent_id);
  const targProof = await signChallenge(target.privateKey, initiate.target_challenge, targReg.agent_id);

  const complete = await postJson('/handshake/complete', {
    handshake_id: initiate.handshake_id,
    initiator_proof: initProof,
    target_proof: targProof,
  }, authHeader);

  writeFileSync(join(FIXTURES_DIR, 'consent.jwt'), complete.consent_token);
  if (complete.consent_token_vdc) {
    writeFileSync(join(FIXTURES_DIR, 'consent.vdc.json'), JSON.stringify(complete.consent_token_vdc, null, 2));
  }
  console.log('✓ consent.jwt' + (complete.consent_token_vdc ? ' + consent.vdc.json' : ''));

  // 5. Close session + capture receipt
  const close = await postJson('/session/close', { session_id: complete.session_id }, authHeader);
  const { receipt_vdc, ...receipt } = close;
  writeFileSync(join(FIXTURES_DIR, 'receipt.json'), JSON.stringify(receipt, null, 2));
  if (receipt_vdc) {
    writeFileSync(join(FIXTURES_DIR, 'receipt.vdc.json'), JSON.stringify(receipt_vdc, null, 2));
  }
  console.log('✓ receipt.json' + (receipt_vdc ? ' + receipt.vdc.json' : ''));

  console.log(`\nAll fixtures written to ${FIXTURES_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// Quiet TS about unused subtle import on some versions
void subtle;
