# @getparafe/verify

Standalone npm package that verifies Parafe credentials, consent tokens, and receipts offline using Parafe's Ed25519 public key. No broker API calls after bootstrap, no Parafe account required.

This is the **neutrality proof point** — any party receiving a Parafe artifact can verify it cryptographically without trusting Parafe for the verification step.

## Project Structure

- `src/index.ts` — Public re-exports only.
- `src/types.ts` — Public interfaces (claims, VerifyResult, options).
- `src/errors.ts` — VerifyError hierarchy with stable `code`s.
- `src/canonicalize.ts` — Deterministic JSON stringify (alphabetical key sort). Exported.
- `src/keys.ts` — PublicKeySource abstraction: fetch+cache from broker, static keys, pinning.
- `src/jwt-verify.ts` — Credential + consent JWT verification via jose.
- `src/receipt-verify.ts` — Raw Ed25519 verification of receipt JSON (future).
- `src/verify.ts` — Auto-detect façade.
- `src/internal/ed25519.ts` — Isomorphic Ed25519 via @noble/ed25519.
- `src/internal/base64.ts` — base64 / base64url helpers.
- `tests/unit/` — vitest unit tests against committed fixtures.
- `tests/integration/` — vitest integration tests against staging broker.
- `tests/fixtures/` — Committed artifact samples captured from a real broker.
- `tests/scripts/generate-fixtures.ts` — Regenerates fixtures from a running broker.

## Running

```bash
npm install
npm run build          # tsup → ESM + CJS + types
npm test               # Unit tests (no network)
npm run test:integration   # Integration tests (requires PARAFE_TEST_BROKER_URL)
npm run typecheck      # TS strict mode
npm run fixtures:generate  # Regenerate fixtures against a broker
```

## Key Design Decisions

- **Single isomorphic implementation** — `jose` for JWTs + `@noble/ed25519` for raw receipt sigs. Works in Node 18+ and all modern browsers without polyfills.
- **Byte-for-byte parity with broker** — `canonicalize.ts` must produce identical output to the broker's receipt canonicalizer (`broker/src/routes/receipt.js`, `canonicalize`). Any drift silently breaks verification. Exported so users can verify signatures manually.
- **VerifyResult instead of throwing** — Signature and claim failures populate `result.error` rather than throwing. Only key-fetch and key-pinning failures throw (caller can't meaningfully treat those as "signature invalid").
- **Auto-detect format** — JWT string vs signed receipt JSON (as issued, or an SDK 0.3.2+ receipt's `issued` field) is detected from structure. Explicit variants (`verifyCredentialJWT`, `verifySignedReceipt`) exist for power users.
- **No W3C VCs** — the broker stopped issuing `*_vdc` fields on 2026-09-29 (they failed standard VC verification), and 0.2.0 removed VDC verification. Don't add it back; the planned standard format is an SD-JWT VC credential.
- **Pinning by key_id and/or SHA-256 thumbprint** — Optional, layered on top of `createPublicKeySource`.

## When Making Changes

- `canonicalize` is load-bearing. If you modify it, run the golden-vector tests and regenerate fixtures against the broker.
- Runtime type guards (pattern from `parafe-A2A-extension/src/verification.ts:60-77`) are required after any `jose.jwtVerify()` cast.
- Any new verification path must have both a "valid" test and a "tampered" negative test.
