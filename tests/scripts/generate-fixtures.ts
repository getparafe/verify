/**
 * Generates real fixtures by running a full handshake against a Parafe broker.
 *
 * Usage:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run fixtures:generate
 *   # or against a local broker started with `npm start` from broker/:
 *   npm run fixtures:generate
 *
 * Writes tests/fixtures/{public-key.json, credential.jwt, consent.jwt, receipt.json}
 * for integration tests. The raw artifacts can also be replayed against unit verifiers
 * as a "known-good-from-production" smoke test.
 *
 * This script is NOT run in CI — fixtures are committed. Re-run only when the broker's
 * artifact formats change.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';

const BROKER_URL = (process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000').replace(/\/$/, '');
const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function freshAgentKeys(): { privateKey: KeyObject; publicKeyBase64: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicKeyBase64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
}

// The target proves key possession by signing the broker's hex challenge.
function signChallenge(privateKey: KeyObject, challengeHex: string): string {
  return nodeSign(null, Buffer.from(challengeHex, 'hex'), privateKey).toString('base64');
}

async function postJson(path: string, body: unknown, bearer?: string): Promise<any> {
  const res = await fetch(`${BROKER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${path}: ${await res.text()}`);
  }
  return res.json();
}

async function getJson(path: string): Promise<any> {
  const res = await fetch(`${BROKER_URL}${path}`);
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

  // 2. Sign up a developer (the starter API key registers agents)
  const suffix = Date.now().toString(36);
  const signup = await postJson('/auth/signup', {
    email: `verify-fixture-${suffix}@example.com`,
    password: 'test-password-12345',
    name: 'Verify Fixtures',
  });
  const apiKey = signup.api_key.key as string;

  // 3. Register two agents
  const initiator = freshAgentKeys();
  const target = freshAgentKeys();
  const initReg = await postJson('/agents/register', {
    agent_name: `initiator-${suffix}`, owner: 'Verify Fixtures', public_key: initiator.publicKeyBase64,
  }, apiKey);
  const targReg = await postJson('/agents/register', {
    agent_name: `target-${suffix}`, owner: 'Verify Fixtures', public_key: target.publicKeyBase64,
    scope_policies: { 'read-profile': { permissions: ['read_profile'], exclusions: ['delete_profile'] } },
  }, apiKey);

  writeFileSync(join(FIXTURES_DIR, 'credential.jwt'), initReg.credential);
  console.log('✓ credential.jwt');

  // 4. Handshake
  const initiate = await postJson('/handshake/initiate', {
    initiator_credential: initReg.credential,
    target_agent_id: targReg.agent_id,
    requested_scope: 'read-profile',
    authorization: { modality: 'autonomous' },
  });
  const complete = await postJson('/handshake/complete', {
    handshake_id: initiate.handshake_id,
    target_credential: targReg.credential,
    challenge_response: signChallenge(target.privateKey, initiate.challenge_for_target),
  });

  writeFileSync(join(FIXTURES_DIR, 'consent.jwt'), complete.consent_token.token);
  console.log('✓ consent.jwt');

  // 5. Close the session as a participant + capture the receipt
  const receipt = await postJson('/session/close', { session_id: complete.session.session_id }, initReg.credential);
  writeFileSync(join(FIXTURES_DIR, 'receipt.json'), JSON.stringify(receipt, null, 2));
  console.log('✓ receipt.json');

  console.log(`\nAll fixtures written to ${FIXTURES_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
