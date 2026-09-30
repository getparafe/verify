# @getparafe/verify

Offline verification of [Parafe](https://parafe.ai) credentials, consent tokens, and receipts. No broker account required.

## Why this exists

Parafe is a **neutral** trust broker. The claim only holds if you can verify a Parafe-issued artifact **without** trusting Parafe for the verification step.

This package is how. Install it, fetch Parafe's public key once, and verify every credential, consent token, and receipt you receive — locally, offline, forever.

```
artifact + Parafe public key  →  Ed25519 verify  →  valid | invalid
```

No network calls after bootstrap. No account. No permission.

## Install

```bash
npm i @getparafe/verify
```

## 30-second example

```ts
import { verifyReceipt, createPublicKeySource } from '@getparafe/verify';

const key = createPublicKeySource({ brokerUrl: 'https://api.parafe.ai' });

const result = await verifyReceipt(receipt, { key });

if (result.valid) {
  console.log('Verified — signed by Parafe.', result.claims.receipt_id);
} else {
  console.error('Invalid:', result.error?.code, result.error?.message);
}
```

Same pattern for `verifyCredential(credential, { key })` and `verifyConsent(token, { key })`.

`receipt` can be the receipt exactly as the broker returned it (snake_case, with `signature`), or a receipt from `@getparafe/sdk` 0.3.2+, whose signed original sits in `receipt.issued`. SDK 0.3.1 and earlier return only a camelCase copy, which can't be verified; upgrade the SDK.

## How verification works

1. Fetch Parafe's Ed25519 public key once (from `https://api.parafe.ai/public-key` by default).
2. Cache it. Optionally pin it by `key_id` or SHA-256 thumbprint.
3. Every verification is a pure Ed25519 signature check against the cached key — no network call, no Parafe API.

Air-gapped? Paste the public key in with `staticKey()` and never touch the network.

## API reference

### Verification functions

Credentials and consent tokens are JWT strings. Receipts are signed JSON objects.

```ts
verifyCredential(input: string | object, opts: VerifyOptions): Promise<VerifyResult<CredentialClaims>>
verifyConsent   (input: string | object, opts: VerifyOptions): Promise<VerifyResult<ConsentClaims>>
verifyReceipt   (input: string | object, opts: VerifyOptions): Promise<VerifyResult<ReceiptPayload>>
```

Explicit variants exist for callers who want to skip format detection: `verifyCredentialJWT`, `verifyConsentJWT`, `verifySignedReceipt`.

**No W3C Verifiable Credentials (0.2.0).** The broker used to also return `credential_vdc`, `consent_token_vdc` and `receipt_vdc`. They didn't verify with standard W3C VC libraries, so the broker stopped issuing them on 2026-09-29 and this package no longer verifies them (`FORMAT_UNKNOWN`, with a message saying so). A standard format (the agent credential as an SD-JWT VC) is planned.

### `VerifyOptions`

```ts
interface VerifyOptions {
  key: PublicKeySource;
  expectedIssuer?: string;    // default: 'parafe-trust-broker'
  clockToleranceSec?: number; // default 0
  now?: Date;                 // override current time (tests)
}
```

### `VerifyResult<T>`

```ts
interface VerifyResult<T> {
  valid: boolean;
  claims?: T;
  format?: 'jwt' | 'receipt';
  keyId?: string;
  verifiedAt: string;
  error?: VerifyError;
}
```

### Error codes

Signature/claim failures populate `result.error` rather than throwing. Only key-fetch and key-pinning failures throw.

| Code | When |
|---|---|
| `INVALID_SIGNATURE` | Signature doesn't verify against the broker's public key |
| `EXPIRED` | Artifact past its `exp` |
| `NOT_YET_VALID` | Artifact's `nbf` is in the future |
| `ISSUER_MISMATCH` | `iss` doesn't match the expected value |
| `MALFORMED` | Required field missing or wrong type |
| `WRONG_ARTIFACT_TYPE` | e.g. consent token passed to `verifyCredential` |
| `FORMAT_UNKNOWN` | Input isn't a JWT string or a signed receipt (the message says why for W3C VC objects and pre-0.3.2 SDK receipts) |
| `KEY_FETCH_FAILED` | (throws) — broker unreachable or returned bad data |
| `KEY_PIN_MISMATCH` | (throws) — `key_id` or thumbprint doesn't match pinning |

## Key pinning and air-gapped use

```ts
import { createPublicKeySource, staticKey, pinKey } from '@getparafe/verify/keys';

// Pin the key ID
const key = createPublicKeySource({
  brokerUrl: 'https://api.parafe.ai',
  pin: { keyId: 'parafe-signing-key-v1' }
});

// Or pin by SHA-256 thumbprint of the base64 SPKI DER
const pinned = createPublicKeySource({
  pin: { thumbprintSha256: '…hex…' }
});

// Or never fetch at all
const offline = staticKey(base64SpkiDer, 'parafe-signing-key-v1');
```

## Verifying signatures yourself

The exported `canonicalize(obj)` produces the exact deterministic JSON string that Parafe signs for receipts (strip `signature`, and `receipt_vdc` on receipts issued before 2026-09-29, first). Use it with any Ed25519 library to verify signatures without this package:

```ts
import { canonicalize } from '@getparafe/verify/canonicalize';

const data = canonicalize(receiptWithoutSignature);
// feed `data` + signature + public key into your Ed25519 verifier of choice
```

## Reporting a verification disagreement

If this package says `valid: false` on an artifact that Parafe says is valid (or vice versa), that's a trust-surface bug. Open an issue at https://github.com/getparafe/verify/issues.

## License

MIT
