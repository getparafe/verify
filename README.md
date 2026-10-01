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
3. Every artifact names its key (`kid`, or no `kid` for the pre-2026-09-30 Ed25519 key). Verification is a pure signature check against the cached key — no network call, no Parafe API. If an artifact names a key the cache doesn't have yet (the broker added or rotated a key), `createPublicKeySource` refetches the JWKS once and retries, at most once a minute (`minRefetchIntervalMs`).

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

// Since 0.4.0 (action receipts and the session index)
verifyActionReceipt(jws, opts?: ActionReceiptOptions): Promise<VerifyResult<ActionReceiptClaims>>
verifyIndexAck(jws, opts: VerifyOptions): Promise<VerifyResult<IndexAckClaims>>
verifySessionIndex(sessionReceiptClaims, { receipts?, acknowledgments?, key? }): Promise<SessionIndexResult>
receiptHash(jws) / consentRef(consentToken) / entryHash(seq, receiptHash, prev)

// Since 0.5.0 (AP2 v0.2 mandates)
verifyAp2Mandate(chain, opts: Ap2MandateOptions): Promise<Ap2MandateResult>
verifyAp2Chain(chain, opts: Ap2ChainOptions): Promise<Ap2ChainResult>
ap2MandateReferences(chain): { sdHash, closedJwt }
```

Explicit variants skip format detection: `verifyCredentialJWT`, `verifyConsentJWT`, `verifySignedReceipt` (v1), `verifyReceiptJWS` (v2).

**Consent tokens (v2).** Claims include `exclusions` (always set; older tokens called it `excluded`, and that is set too), `sub` (initiator), `aud` (target DID), `cnf.jkt` (the initiator key the token is bound to) and `initiator_proof` (`pop` or `credential`).

**Presentation proofs.** A key-bound consent token is only as good as the proof that comes with it. When an initiator presents a token, it attaches a short JWT signed with its key. `verifyPresentationProof` checks it against the token's `cnf.jkt` (fetching the initiator's key from its DID document, or taking `initiatorKey`), that it's for this token (`ath`) and for you (`aud`, `expectedAudience`), and fresh (5 minutes). Remember the returned `jti` for 5 minutes and refuse repeats.

**Identity credential (SD-JWT VC).** `verifyIdentityCredential` checks the broker's signature, `vct`, expiry and every disclosure; `cnf.jwk` is the agent's registered key; `owner`/`owner_id` appear only when disclosed; `org_domain` only for domain-verified orgs. `matchAgentKey(claims, mandate)` answers "does this AP2 open mandate's key belong to this Parafé-verified agent?" by RFC 7638 thumbprint. It does **not** verify the mandate itself.

**Action receipts and the session index (0.4.0).** The agent that performs or refuses an action signs an *action receipt* (a JWS with its own registered key, `typ: parafe-action-receipt+jwt`, `kid` = `<agent DID>#keys-1`) naming the action, `result` (`success` or `error`, with an error code such as `excluded`) and the consent token it acted under (`consent_ref` = base64url SHA-256 of the token). Either participant files it with the broker, which chains it per session and returns a signed *index acknowledgment* (`typ: parafe-index-ack+jwt`). The session receipt's `actions` lists every filed receipt by hash, and `chain_head` commits to the list.
- `verifyActionReceipt` checks the agent's signature with the key in its DID document (fetched from `brokerUrl`, or pass `issuerKey`); `consentToken` and `expectedSessionId` bind it to your session.
- `verifyIndexAck` checks the broker's signature and that `entry_hash` recomputes.
- `verifySessionIndex(claims, { receipts, acknowledgments, key })`, after `verifyReceipt`, recomputes `chain_head` from `actions` (`entry_hash` = base64url SHA-256 of `"<seq>|<receipt_hash>|<prev>"`, `prev` empty for the first), reports where each receipt you hold is listed (`listed[i].seq`, `null` if it isn't) and checks each acknowledgment matches its entry. A receipt you hold that isn't listed fails the check: it was never filed.

**AP2 mandates (0.5.0).** `verifyAp2Mandate(chain, opts)` verifies an AP2 v0.2 Checkout or Payment Mandate as presented: the `~~`-joined Delegate SD-JWT chain, offline, against the issuers you trust (`trustedIssuers`: your Credential Providers or Agent Providers, as public JWKs). It checks:
- the root's signature against the trust list, then every hop's signature against the previous hop's `cnf.jwk`, `sd_hash`/`issuer_jwt_hash` bindings, `typ`, and `exp`/`iat`/`nbf`;
- the terminal hop's `aud` and `nonce`: required, and equal to `expectedAudience`/`expectedNonce` when you pass them. A root-only chain (the issuer signed the closed mandate; no key-binding hop) has neither: it is valid when you expect nothing, and fails if you pass `expectedAudience` or `expectedNonce` (0.5.1). `maxPresentationAgeSec` limits the terminal hop's `iat`, or a root-only chain's own `iat`;
- the exact `vct` (`mandate.checkout.1`, `mandate.checkout.open.1`, `mandate.payment.1`, `mandate.payment.open.1`): open mandates, then one closed mandate, one family;
- claims set in an open mandate reach the closed mandate unchanged, and no constraint (or other claim of an open mandate) is withheld;
- every v0.2 constraint (`checkout.allowed_merchants`, `checkout.line_items` by maximum flow, `payment.amount_range`, `payment.budget`, `payment.agent_recurrence`, `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.execution_date`, `payment.reference`); unknown constraints fail;
- `checkout_hash` against the Checkout JWT (disclosed, or `checkoutJwt`), and a payment's `transaction_id` against the checkout (`checkoutJwt`, `checkoutHash`, or the verified checkout mandate as `checkout`, which also supplies `payment.reference`'s open checkout hashes).

A failure's `error.ap2Error` is the AP2 code for your Checkout or Payment Receipt (`invalid_credential`, `unresolved_constraint`, `invalid_mandate`); `error.reason` is more specific. `references` gives a receipt's `reference` both ways until AP2 settles it (`sdHash`, per the spec; `closedJwt`, per the AP2 SDK), even for a mandate that failed, so a rejection receipt can be issued. `payment.budget` and `payment.agent_recurrence` need `context` (`totalAmount`, `totalUses`, `lastUsedAt`), which only the verifier that tracks the mandate has. Verification is stateless: refusing a second presentation of the same closed mandate needs a record (the broker's `POST /ap2/mandates/verify` keeps one).

Stricter than the AP2 Python SDK where AP2 has open issues: merchants and payees match by `id` only (#315); instruments by `id` and `type` (#320); an empty `acceptable_items` matches nothing and quantities must be filled exactly (#298); a terminal hop without `aud`/`nonce` fails whatever you expect (#319); `checkout_hash` is always checked against the Checkout JWT presented (#358); a withheld constraint fails (#339); recurrence checks the frequency, not only the count. Checked against the AP2 SDK's own vectors, the spec's encoded examples and the golden vectors of AP2 PR #307. SD-JWT parsing and disclosure resolution use the OpenWallet Foundation's `@sd-jwt/core`; an extra strict pass records withheld digests and checks the disclosure rules itself.

**As a merchant on Parafé.** Pass your own values: `expectedAudience` is your agent's DID or agent ID (the broker accepts nothing else as a hop's `aud` at a handshake), `expectedNonce` is the nonce you issued for this purchase (e.g. the quote ID; the broker can't know it, so only you can check it), and the mandate's merchant (`merchant.id`) or payee (`payee.id`) should be your agent ID or DID, or a `merchant.website` on your org's verified domain. A mandate the issuer signed directly (root-only, AP2's human-present model) has no `aud` or `nonce`: don't pass `expectedAudience`/`expectedNonce` for it, pass `maxPresentationAgeSec` (the broker uses 300). AP2 receipts you sign in return are ES256, so your agent needs a P-256 key.

`matchAgentKey(credential, mandate)` also takes a `verifyAp2Mandate` result or a presented chain (the last open mandate's `cnf.jwk`).

Things to know:
- **One mandate per chain.** Every segment must disclose exactly one `delegate_payload` item. AP2's User Credential example delegates a checkout and a payment mandate in one hop: present each verifier only its own (drop the other item's disclosure; that still verifies).
- **No decoy digests in open mandates.** A decoy (RFC 9901 §4.2.5, the AP2 SDK's `add_decoy_claims`) can't be told from a withheld constraint, so an open mandate with an undisclosed digest anywhere but `allowed`/`acceptable_items` fails (`unresolved_constraint`). Issuers must not add decoys to open mandates.
- **Who signed the closed mandate:** `closedBy` is `issuer`, `credential_holder` (AP2's User Credential model: the holder of a trusted credential, normally the user) or `open_mandate_key` (an agent). If an issuer you trust also certifies agent keys, check `closedByKey` isn't an agent's before treating a `credential_holder` mandate as the user's. A Parafé agent identity credential is refused as a root.
- **Who signed the limits (human not present):** `openedBy` is `issuer` (the root is the open mandate) or `credential_holder` (a trusted credential's holder signed the first open mandate; `openedByKey`). The same check applies: if that key, or the issuer key, is an agent's, the agent wrote its own limits and no user signed them.
- **Size limits:** `checkout.line_items` beyond 100 requirements, 1,000 acceptable items or 100 checkout lines is `unresolved_constraint`.
- SD-JWT parsing uses `@sd-jwt/core` (≥ 0.20; the older `@sd-jwt/decode` carries GHSA-f9j6-8p6x-r9j6).

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
