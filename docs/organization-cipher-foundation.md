# Organization cipher foundation

This slice adds programmatic core contracts and local SQLite storage guarantees.
It adds no HTTP route or client-compatibility claim. The standalone server keeps
its existing personal-vault read, list, sync and error behavior.

The allocation-free core exposes an opt-in sharing provider. Source ownership
and revision snapshots are provider-owned handles. Sealed association and final
payload plans keep those facts available for adapter transaction rechecks.
Selection order and duplicates remain observable to the provider: a later
rejection preserves earlier successful association steps, and the payload phase
runs only after every selected association succeeds. Personal create and update
still reject organization ownership; sharing reuses only encrypted-field rules.

A separate pure access resolver requires confirmed membership in the cipher's
canonical organization before considering trusted associated collection grants.
An association may retain its actual earlier organization. Read, write and
password visibility are separate results. These results describe one consistent
snapshot and do not authorize a later mutation after its facts change.

`CipherShareRequest<N>` borrows decoded strings and lets the caller select its
JSON collection capacity. The service also accepts indexed input without that
transport cap. The no-allocator RISC-V consumer links decoding, an association
prefix failure, a successful sealed payload phase, and historical read-only
access resolution. Linking does not demonstrate execution on hardware.

SQLite stores exactly one canonical owner: a personal account, or an organization
for a cipher. Its atomic legacy-table migration preserves opaque documents,
child references, user-created indexes and triggers, and restores foreign-key
enforcement on failure. Folder/favorite annotations are keyed by cipher and viewer. Organization-owned items and other viewers' annotations survive creator
account deletion; organization deletion cascades its items. Reopening a database
preserves this state. Personal-only metadata checks reject organization ownership
through the existing ownership guard.

Local unit tests cover these contracts, migration rollback, foreign keys,
annotations, account cleanup and reopening. Full sharing transport, host access
projection, client key wrapping, groups, configured policies, notifications and
complete upstream parity remain separate work. Route and named HTTP-case counts
remain unchanged by this foundation.
