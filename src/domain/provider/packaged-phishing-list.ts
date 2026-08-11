/**
 * Signed empty production snapshot. The one-time signing key was discarded;
 * future releases replace both data and pinned public key through review.
 */
export const PHISHING_LIST_PUBLIC_KEY_HEX =
  '47267d69d12c2228b6e851045687c4b4eada63016035a006e8b8a4738942ee31';

export const PACKAGED_PHISHING_LIST_BYTES = new TextEncoder().encode(
  '{"version":1,"issuedAtMs":1786320000000,"expiresAtMs":2051222400000,"maliciousOrigins":[],"signature":"1320e87e0fa5b3ba0ba90093c833e52cc5a90402d8a1529419dbe9673be4e75b9cecd9e29b0ae409ad700fbf163b70502539bbefcae37f72ac64eee9f87d4909"}',
);
