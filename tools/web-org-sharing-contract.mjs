// Independently authored MIT OR Apache-2.0 browser fixture contracts.
import assert from 'node:assert/strict';

export function httpsProxyPort(origin) {
  return Number(origin.port || '443');
}

// Consume only the ordinary browser sync response, never client storage or a
// fixture HTTP read. Identifiers and opaque vault payloads stay in memory.
export function assertAssignedCipher(ciphers, expected) {
  assert(expected && ['id', 'organizationId', 'collectionId'].every(
    key => typeof expected[key] === 'string' && expected[key].length > 0,
  ), 'Missing UI-created assignment identifiers');
  assert(Array.isArray(ciphers), 'Fresh browser sync has no cipher list');
  const matches = ciphers.filter(cipher => cipher.id === expected.id);
  assert(matches.length === 1, 'Fresh browser sync must contain the created cipher once');
  const cipher = matches[0];
  assert(cipher.organizationId === expected.organizationId,
    'Fresh browser sync must preserve the assigned organization');
  assert(Array.isArray(cipher.collectionIds) && cipher.collectionIds.includes(expected.collectionId),
    'Fresh browser sync must preserve the selected collection');
}
