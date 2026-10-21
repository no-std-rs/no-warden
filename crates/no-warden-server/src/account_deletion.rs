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
    // Shared ciphers survive their creator's account. Remove only this viewer's
    // legacy archive annotations, whose account foreign key does not cascade.
    tx.execute("DELETE FROM cipher_archives WHERE owner=?1", [owner])?;
    if tx.execute("DELETE FROM accounts WHERE id=?1", [owner])? != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    // Account FKs cascade through devices/push tokens, auth requests, security
    // stamps, historical access/exception authority, domains and registration.
    // The instance-wide registration signing key is deliberately preserved.
    tx.commit()
}

#[cfg(test)]
mod tests {
    #[test]
    fn user_deletion_preserves_organization_cipher_and_other_viewer_annotations() {
        let mut store = crate::Store::open(":memory:").unwrap();
        store.db.execute_batch(
            "INSERT INTO accounts VALUES('alice','alice@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');
             INSERT INTO accounts VALUES('bob','bob@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');
             INSERT INTO organizations VALUES('org','opaque name','billing@example.test',NULL,NULL);
             INSERT INTO organization_memberships VALUES('alice-member','org','alice','opaque wrapped key',2,2,0),('bob-member','org','bob','opaque wrapped key',0,2,1);
             INSERT INTO items(id,owner,organization_id,kind,document,revision,created)
               VALUES('shared',NULL,'org','cipher','opaque encrypted payload','revision','created');
             INSERT INTO cipher_annotations VALUES('shared','alice',NULL,1),('shared','bob',NULL,0);
             INSERT INTO cipher_archives VALUES('shared','alice','alice archive'),('shared','bob','bob archive');
             INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES('file','shared','opaque name',NULL,3,x'0001ff');",
        ).unwrap();
        super::delete(&mut store.db, "alice").unwrap();
        assert!(store.account("id", "alice").unwrap().is_none());
        let cipher: (Option<String>, String, String) = store
            .db
            .query_row(
                "SELECT owner,organization_id,document FROM items WHERE id='shared'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            cipher,
            (None, "org".into(), "opaque encrypted payload".into())
        );
        let viewer: (String, bool) = store
            .db
            .query_row("SELECT user_id,favorite FROM cipher_annotations", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(viewer, ("bob".into(), false));
        let archive: (String, String) = store
            .db
            .query_row("SELECT owner,archived_at FROM cipher_archives", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(archive, ("bob".into(), "bob archive".into()));
        let bytes: Vec<u8> = store
            .db
            .query_row("SELECT data FROM attachments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bytes, [0, 1, 255]);
        assert!(
            store
                .db
                .prepare("PRAGMA foreign_key_check")
                .unwrap()
                .query([])
                .unwrap()
                .next()
                .unwrap()
                .is_none()
        );
    }
}
