//! Account deletion for the adapter's personal accounts.
//! Upstream deletes sequentially; this adapter commits all local cleanup together.
//! Confirmed last-owner policy is checked before cleanup and inside this transaction.

use rusqlite::Connection;

pub(crate) fn delete(db: &mut Connection, owner: &str) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    // Recheck under SQLite's transaction as well as the service proof/policy guard.
    // A competing connection cannot cause us to orphan a confirmed organization.
    if crate::organizations::last_owner(&tx, owner)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    // These legacy foreign keys restrict account deletion rather than cascading.
    // Delete all item kinds: unlike a vault purge, no account-owned row survives.
    // Item FKs cascade through attachments, capabilities and archive annotations.
    tx.execute("DELETE FROM sessions WHERE owner=?1", [owner])?;
    tx.execute("DELETE FROM api_keys WHERE owner=?1", [owner])?;
    tx.execute("DELETE FROM items WHERE owner=?1", [owner])?;
    if tx.execute("DELETE FROM accounts WHERE id=?1", [owner])? != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    // Account FKs cascade through devices/push tokens, auth requests, security
    // stamps, historical access/exception authority, domains and registration.
    // The instance-wide registration signing key is deliberately preserved.
    tx.commit()
}
