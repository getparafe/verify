# @getparafe/verify

Offline verification of [Parafe](https://parafe.ai) credentials, consent tokens, and receipts. No broker account required.

## Why this exists

Parafe is a **neutral** trust broker. The claim only holds if you can verify a Parafe-issued artifact **without** trusting Parafe for the verification step.

This package is how. Install it, fetch Parafe's public keys once, and verify every credential, consent token, and receipt you receive — locally, offline, forever.

```
artifact + Parafe's keys (JWKS, by kid)  →  ES256 / Ed25519 verify  →  valid | invalid
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

`receipt` can be:
- a **v2 receipt** (since 2026-09-30): the JWS string, the broker's `/session/close` response, or an `@getparafe/sdk` 0.4 receipt (its `receipt` field is the JWS). Claims come back as `ReceiptV2Payload`: participants, consent tokens with **exclusions**, a hash of each token, of the human's instruction and of the handshake context, and how the initiator proved itself (`initiator_proof`).
- a **v1 receipt** (before): the signed JSON as the broker returned it, or an SDK 0.3.2+ receipt's `issued` field. They verify forever against the retired Ed25519 key.

## How verification works

1. Fetch Parafe's keys once: the JWKS at `https://api.parafe.ai/.well-known/jwks.json` (the active ES256 key and retired keys, which stay published forever). A broker from before 2026-09-30 has only `/public-key`; that's used instead.
2. Cache them. Optionally pin by `kid` or SHA-256 thumbprint.
3. Every artifact names its key (`kid`, or no `kid` for the pre-2026-09-30 Ed25519 key). Verification is a pure signature check against the cached key — no network call, no Parafe API.

Air-gapped? Paste the JWKS in with `staticJwks()` (or, for Ed25519-only artifacts, the key with `staticKey()`) and never touch the network.

## API reference

### Verification functions

Credentials and consent tokens are JWT strings. Receipts are a JWS (v2) or signed JSON (v1).

```ts
verifyCredential(input: string | object, opts: VerifyOptions): Promise<VerifyResult<CredentialClaims>>
verifyConsent   (input: string | object, opts: VerifyOptions): Promise<VerifyResult<ConsentClaims>>
verifyReceipt   (input: string | object, opts: VerifyOptions): Promise<VerifyResult<ReceiptPayload | ReceiptV2Payload>>

// Since 0.3.0
verifyIdentityCredential(sdJwt: string, opts: VerifyOptions): Promise<VerifyResult<IdentityCredentialClaims>>
verifyPresentationProof(proof, consentToken, consentClaims, opts?): Promise<{ valid, jti?, mid?, error? }>
matchAgentKey(credentialClaims, ap2OpenMandate): Promise<boolean>
```

Explicit variants skip format detection: `verifyCredentialJWT`, `verifyConsentJWT`, `verifySignedReceipt` (v1), `verifyReceiptJWS` (v2).

**Consent tokens (v2).** Claims include `exclusions` (always set; older tokens called it `excluded`, and that is set too), `sub` (initiator), `aud` (target DID), `cnf.jkt` (the initiator key the token is bound to) and `initiator_proof` (`pop` or `credential`).

**Presentation proofs.** A key-bound consent token is only as good as the proof that comes with it. When an initiator presents a token, it attaches a short JWT signed with its key. `verifyPresentationProof` checks it against the token's `cnf.jkt` (fetching the initiator's key from its DID document, or taking `initiatorKey`), that it's for this token (`ath`) and for you (`aud`, `expectedAudience`), and fresh (5 minutes). Remember the returned `jti` for 5 minutes and refuse repeats.

**Identity credential (SD-JWT VC).** `verifyIdentityCredential` checks the broker's signature, `vct`, expiry and every disclosure; `cnf.jwk` is the agent's registered key; `owner`/`owner_id` appear only when disclosed; `org_domain` only for domain-verified orgs. `matchAgentKey(claims, mandate)` answers "does this AP2 open mandate's key belong to this Parafé-verified agent?" by RFC 7638 thumbprint. It does **not** verify the mandate itself.

**No W3C Verifiable Credentials (0.2.0).** The broker used to also return `*_vdc` fields. They didn't verify with standard W3C VC libraries, so the broker stopped issuing them on 2026-09-29 and this package no longer verifies them (`FORMAT_UNKNOWN`, with a message saying so). The standard format is now the SD-JWT VC above.

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
| `KEY_NOT_FOUND` | The artifact names a `kid` the broker doesn't publish, or an ES256 artifact met an Ed25519-only `staticKey()` |
| `PROOF_INVALID` | A presentation proof didn't check out (`verifyPresentationProof`) |
| `KEY_FETCH_FAILED` | (throws) — broker unreachable or returned bad data |
| `KEY_PIN_MISMATCH` | (throws) — `key_id` or thumbprint doesn't match pinning |

## Key pinning and air-gapped use

```ts
import { createPublicKeySource, staticKey, pinKey } from '@getparafe/verify/keys';

// Pin a key ID (a JWKS kid): only artifacts signed with that key verify
const key = createPublicKeySource({
  brokerUrl: 'https://api.parafe.ai',
  pin: { keyId: '<kid from /.well-known/jwks.json>' }
});

// Or pin by SHA-256 thumbprint of the base64 SPKI DER
const pinned = createPublicKeySource({
  pin: { thumbprintSha256: '…hex…' }
});

// Or never fetch at all
const offline = staticJwks(jwksJson);               // everything
const legacyOnly = staticKey(base64SpkiDer);        // Ed25519 artifacts from before 2026-09-30
```

## Verifying signatures yourself

v2 receipts, credentials and consent tokens are standard JWS: any JOSE library (e.g. `jose` in JS, `jwcrypto` in Python) verifies them against the broker JWKS. For v1 receipts, the exported `canonicalize(obj)` produces the exact deterministic JSON string that Parafe signed (strip `signature`, and `receipt_vdc` on receipts issued before 2026-09-29, first). Use it with any Ed25519 library to verify signatures without this package:

```ts
import { canonicalize } from '@getparafe/verify/canonicalize';

const data = canonicalize(receiptWithoutSignature);
// feed `data` + signature + public key into your Ed25519 verifier of choice
```

## Reporting a verification disagreement

If this package says `valid: false` on an artifact that Parafe says is valid (or vice versa), that's a trust-surface bug. Open an issue at https://github.com/getparafe/verify/issues.

## License

MIT
