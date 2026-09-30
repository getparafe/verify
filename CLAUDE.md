# @getparafe/verify

Standalone npm package that verifies Parafe credentials (JWT and SD-JWT VC), consent tokens, presentation proofs and receipts (v2 JWS and v1 signed JSON) offline against Parafe's published keys (JWKS: ES256 since 2026-09-30, the retired Ed25519 key before). No broker API calls after bootstrap, no Parafe account required.

This is the **neutrality proof point** — any party receiving a Parafe artifact can verify it cryptographically without trusting Parafe for the verification step.

## Project Structure

- `src/index.ts` — Public re-exports only.
- `src/types.ts` — Public interfaces (claims, VerifyResult, options).
- `src/errors.ts` — VerifyError hierarchy with stable `code`s.
- `src/canonicalize.ts` — Deterministic JSON stringify (alphabetical key sort). Exported.
- `src/keys.ts` — PublicKeySource abstraction: fetch+cache the broker JWKS (falls back to /public-key), `staticJwks`, `staticKey` (Ed25519 only), pinning.
- `src/internal/broker-key.ts` — picks the broker key for a JWS header (`kid`, DID-URL kid, or no kid = legacy Ed25519).
- `src/receipt-jws.ts` — v2 receipt (JWS) verification.
- `src/presentation.ts` — presentation proof (B7) verification against a consent token's `cnf.jkt`.
- `src/action-receipt.ts` — B6: action receipts (agent-signed, key from the agent's DID document), index acknowledgments (broker-signed) and `verifySessionIndex` (the session receipt's `actions` recompute to `chain_head`; held receipts are listed).
- `src/identity-credential.ts` — SD-JWT VC identity credential; `matchAgentKey`.
- `src/ap2/` — AP2 v0.2 mandates (change request A1): `sdjwt.ts` (Delegate SD-JWT chain parsing on OWF `@sd-jwt/decode` plus a strict disclosure pass), `constraints.ts` (every v0.2 constraint), `mandate.ts` (`verifyAp2Chain`, `verifyAp2Mandate`, `ap2MandateReferences`), `errors.ts` (AP2 error codes).
- `src/jwt-verify.ts` — Credential + consent JWT verification via jose.
- `src/receipt-verify.ts` — v1 receipts: raw Ed25519 verification of canonicalized receipt JSON.
- `src/verify.ts` — Auto-detect façade.
- `src/internal/ed25519.ts` — Isomorphic Ed25519 via @noble/ed25519.
- `src/internal/base64.ts` — base64 / base64url helpers.
- `tests/unit/` — vitest unit tests against committed fixtures.
- `tests/integration/` — vitest integration tests against staging broker.
- `tests/fixtures/` — Committed artifacts: two production v1 receipts (verified against production's Ed25519 key), a set of v2 artifacts with their JWKS from a local Phase 1 broker, and `broker-phase2-artifacts.json` (action receipts, acknowledgments, a session receipt listing them, DID documents) from a local Phase 2 broker.
- `tests/fixtures/ap2-*.json` — AP2 vectors: `ap2-sdk-vectors.json` (minted and verified by the AP2 Python SDK; regenerate with `tests/scripts/generate-ap2-vectors.py`, instructions inside), the spec's encoded examples, and AP2 PR #307's golden vectors.
- `tests/scripts/generate-fixtures.ts` — Regenerates fixtures from a running broker. `generate-phase2-fixtures.ts` writes the Phase 2 fixture (`npx tsx`).

## Running

```bash
npm install
npm run build          # tsup → ESM + CJS + types
npm test               # Unit tests (no network)
npm run test:integration   # Integration tests (requires PARAFE_TEST_BROKER_URL)
npm run typecheck      # TS strict mode
npm run fixtures:generate  # Regenerate fixtures against a broker
```

**Releasing:** bump `version` in package.json, push, then publish a GitHub release tagged `v<version>` (ask Faris first). `.github/workflows/publish.yml` publishes to npm via trusted publishing (no npm token, no 2FA), with provenance. It refuses a tag that doesn't match package.json.

## Key Design Decisions

- **Single isomorphic implementation** — `jose` for JWTs/JWS (ES256, EdDSA) + `@noble/ed25519` for v1 receipt sigs + `@noble/hashes` for SD-JWT digests. Works in Node 18+ and all modern browsers without polyfills.
- **Byte-for-byte parity with broker (v1 only)** — `canonicalize.ts` must produce identical output to the broker's v1 receipt canonicalizer (`broker/src/routes/receipt.js`, `canonicalizeV1`). v2 receipts are JWS: no canonicalization.
- **VerifyResult instead of throwing** — Signature and claim failures populate `result.error` rather than throwing. Only key-fetch and key-pinning failures throw (caller can't meaningfully treat those as "signature invalid").
- **Auto-detect format** — JWT string vs signed receipt JSON (as issued, or an SDK 0.3.2+ receipt's `issued` field) is detected from structure. Explicit variants (`verifyCredentialJWT`, `verifySignedReceipt`) exist for power users.
- **No W3C VCs** — the broker stopped issuing `*_vdc` fields on 2026-09-29 (they failed standard VC verification), and 0.2.0 removed VDC verification. Don't add it back; the standard format is the SD-JWT VC credential (0.3.0).
- **Pinning by key_id and/or SHA-256 thumbprint** — Optional, layered on top of `createPublicKeySource`.

## When Making Changes

- `canonicalize` is load-bearing. If you modify it, run the golden-vector tests and regenerate fixtures against the broker.
- Runtime type guards (pattern from `parafe-A2A-extension/src/verification.ts:60-77`) are required after any `jose.jwtVerify()` cast.
- Any new verification path must have both a "valid" test and a "tampered" negative test.
