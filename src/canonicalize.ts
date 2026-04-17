/**
 * Deterministic JSON canonicalization. Must produce byte-identical output to the
 * broker's canonicalizer at broker/src/crypto/vdc.js:18-25 and broker/src/routes/receipt.js:10-17.
 *
 * Rules:
 * - Object keys sorted alphabetically (localeCompare) at every level.
 * - Arrays preserved in original order, elements canonicalized recursively.
 * - Primitives untouched. `null` treated as primitive.
 * - Output is a single-line JSON string (no whitespace), UTF-8.
 *
 * Any drift from the broker's behavior silently breaks signature verification,
 * so this function is exported for users who want to build their own verifier.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
      );
    }
    return v;
  });
}

/**
 * Strip the `proof` field from a VDC and return the canonical signing input.
 * Equivalent to: canonicalize({ ...vdc, proof: undefined }) but more explicit.
 */
export function signingInputForVDC(vdc: object): string {
  const { proof: _proof, ...rest } = vdc as Record<string, unknown>;
  return canonicalize(rest);
}

/**
 * Strip `signature` and `receipt_vdc` from a receipt and return the canonical
 * signing input — mirrors broker/src/routes/receipt.js:178-180.
 */
export function signingInputForReceipt(receipt: object): string {
  const { signature: _sig, receipt_vdc: _vdc, ...rest } = receipt as Record<string, unknown>;
  return canonicalize(rest);
}
