//! Canonical organization ownership and private cipher annotations.
//!
//! This migration preserves opaque documents and existing child-table references.
//! Shared ciphers have an organization owner and no artificial account owner.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

const ITEMS: &str = "
CREATE TABLE no_warden_items_migration(
 id TEXT PRIMARY KEY,
 owner TEXT REFERENCES accounts(id),
 organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
 kind TEXT NOT NULL,
 document TEXT NOT NULL,
 deleted INTEGER NOT NULL DEFAULT 0,
 revision TEXT NOT NULL,
 created TEXT NOT NULL,
 CHECK((owner IS NOT NULL AND organization_id IS NULL)
    OR (owner IS NULL AND organization_id IS NOT NULL AND kind='cipher')));
INSERT INTO no_warden_items_migration(id,owner,kind,document,deleted,revision,created)
 SELECT id,owner,kind,document,deleted,revision,created FROM items;
DROP TABLE items;
ALTER TABLE no_warden_items_migration RENAME TO items;";

const ANNOTATIONS: &str = "
CREATE INDEX IF NOT EXISTS items_organization ON items(organization_id,kind);
CREATE TABLE IF NOT EXISTS cipher_annotations(
 cipher_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 folder_id TEXT REFERENCES items(id) ON DELETE SET NULL,
 favorite INTEGER NOT NULL CHECK(favorite IN(0,1)),
 PRIMARY KEY(cipher_id,user_id));";

/// Rebuild SQLite's formerly account-only table once. Foreign-key enforcement is
/// disabled only around the atomic rebuild, then restored even on failure. Child
/// tables continue to reference `items`; foreign_key_check runs before commit.
/// Existing user-created indexes/triggers are retained without executing them
/// during the opaque document copy.
pub fn initialize(db: &mut Connection) -> rusqlite::Result<()> {
    let columns = {
        let mut statement = db.prepare("PRAGMA table_info(items)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if columns.iter().any(|name| name == "organization_id") {
        return db.execute_batch(ANNOTATIONS);
    }
    // Refuse to discard columns introduced by an unknown schema version.
    if columns
        != [
            "id", "owner", "kind", "document", "deleted", "revision", "created",
        ]
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let schema = {
        let mut statement = db.prepare(
            "SELECT sql FROM sqlite_master WHERE tbl_name='items'
             AND type IN('index','trigger') AND sql IS NOT NULL ORDER BY type,name",
        )?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let foreign_keys: bool = db.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    db.pragma_update(None, "foreign_keys", false)?;
    let result = (|| {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(ITEMS)?;
        for sql in schema {
            tx.execute_batch(&sql)?;
        }
        tx.execute_batch(ANNOTATIONS)?;
        let violation = tx
            .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
            .optional()?;
        if violation.is_some() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.commit()
    })();
    db.pragma_update(None, "foreign_keys", foreign_keys)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn legacy() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE accounts(id TEXT PRIMARY KEY);
             CREATE TABLE organizations(id TEXT PRIMARY KEY);
             CREATE TABLE items(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES accounts(id),kind TEXT NOT NULL,document TEXT NOT NULL,deleted INTEGER NOT NULL DEFAULT 0,revision TEXT NOT NULL,created TEXT NOT NULL);
             CREATE INDEX items_owner ON items(owner,kind);
             CREATE TABLE attachments(id TEXT PRIMARY KEY,cipher_id TEXT REFERENCES items(id) ON DELETE CASCADE,data BLOB);
             CREATE TABLE archive(cipher_id TEXT REFERENCES items(id) ON DELETE CASCADE,owner TEXT REFERENCES accounts(id),date TEXT);
             CREATE TABLE collection_items(collection_id TEXT,cipher_id TEXT REFERENCES items(id) ON DELETE CASCADE);
             CREATE TABLE modifications(id TEXT);
             CREATE TRIGGER remember_item AFTER UPDATE ON items BEGIN INSERT INTO modifications VALUES(NEW.id); END;
             INSERT INTO accounts VALUES('alice'),('bob');
             INSERT INTO organizations VALUES('org');
             INSERT INTO items VALUES('cipher','alice','cipher','opaque encrypted payload',1,'revision','created');
             INSERT INTO items VALUES('folder','alice','folder','opaque folder',0,'folder revision','folder created');
             INSERT INTO attachments VALUES('attachment','cipher',x'0001ff');
             INSERT INTO archive VALUES('cipher','alice','archive date');
             INSERT INTO collection_items VALUES('collection','cipher');",
        )
        .unwrap();
        db
    }

    #[test]
    fn migration_preserves_documents_children_and_schema_and_is_idempotent() {
        let mut db = legacy();
        initialize(&mut db).unwrap();
        initialize(&mut db).unwrap();
        let row: (String, String, bool, String, String, Option<String>) = db.query_row(
            "SELECT owner,document,deleted,revision,created,organization_id FROM items WHERE id='cipher'", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).unwrap();
        assert_eq!(
            row,
            (
                "alice".into(),
                "opaque encrypted payload".into(),
                true,
                "revision".into(),
                "created".into(),
                None
            )
        );
        let bytes: Vec<u8> = db
            .query_row("SELECT data FROM attachments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bytes, [0, 1, 255]);
        for table in ["archive", "collection_items"] {
            assert_eq!(
                db.query_row(
                    &format!("SELECT count(*) FROM {table} WHERE cipher_id='cipher'"),
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
                1
            );
        }
        assert_eq!(
            db.query_row("SELECT count(*) FROM modifications", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            0
        );
        db.execute("UPDATE items SET deleted=0 WHERE id='cipher'", [])
            .unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM modifications", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='items_owner'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
            1
        );
        assert!(
            db.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
                .unwrap()
        );
        db.execute("DELETE FROM items WHERE id='cipher'", [])
            .unwrap();
        for table in ["attachments", "archive", "collection_items"] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, usize>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn canonical_organization_owner_and_private_annotations_survive_creator_removal() {
        let mut db = legacy();
        initialize(&mut db).unwrap();
        db.execute(
            "UPDATE items SET owner=NULL,organization_id='org' WHERE id='cipher'",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO cipher_annotations VALUES('cipher','alice','folder',1),('cipher','bob',NULL,0)", []).unwrap();
        db.execute("DELETE FROM archive WHERE owner='alice'", [])
            .unwrap();
        db.execute("DELETE FROM items WHERE owner='alice'", [])
            .unwrap();
        db.execute("DELETE FROM accounts WHERE id='alice'", [])
            .unwrap();
        let state: (Option<String>, String) = db
            .query_row(
                "SELECT owner,organization_id FROM items WHERE id='cipher'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (None, "org".into()));
        let remaining: (String, Option<String>, bool) = db
            .query_row(
                "SELECT user_id,folder_id,favorite FROM cipher_annotations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(remaining, ("bob".into(), None, false));
        for (owner, org, kind) in [
            (Some("bob"), Some("org"), "cipher"),
            (None, None, "cipher"),
            (None, Some("org"), "folder"),
        ] {
            assert!(db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES('invalid',?1,?2,?3,'{}','r','c')",params![owner,org,kind]).is_err());
        }
        db.execute("DELETE FROM organizations WHERE id='org'", [])
            .unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM items", [], |r| r.get::<_, usize>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM cipher_annotations", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn failed_copy_rolls_back_and_restores_foreign_key_enforcement() {
        let mut db = legacy();
        db.execute_batch("PRAGMA foreign_keys=OFF;UPDATE items SET owner='missing' WHERE id='cipher';PRAGMA foreign_keys=ON;").unwrap();
        assert!(initialize(&mut db).is_err());
        assert!(
            db.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
                .unwrap()
        );
        assert_eq!(
            db.query_row("SELECT owner FROM items WHERE id='cipher'", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "missing"
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM pragma_table_info('items') WHERE name='organization_id'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='no_warden_items_migration'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn organization_ownership_and_private_annotations_survive_store_reopen() {
        struct Database(std::path::PathBuf);
        impl Drop for Database {
            fn drop(&mut self) {
                for suffix in ["", "-shm", "-wal"] {
                    let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
                }
            }
        }
        let file = Database(std::env::temp_dir().join(format!(
            "no-warden-cipher-ownership-{}.db",
            uuid::Uuid::new_v4()
        )));
        let path = file.0.to_str().unwrap();
        {
            let store = crate::Store::open(path).unwrap();
            store.db.execute_batch(
                "INSERT INTO accounts VALUES('alice','alice@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');
                 INSERT INTO accounts VALUES('bob','bob@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');
                 INSERT INTO organizations VALUES('org','opaque name','billing@example.test',NULL,NULL);
                 INSERT INTO items(id,owner,organization_id,kind,document,revision,created)
                   VALUES('shared',NULL,'org','cipher','opaque encrypted payload','revision','created');
                 INSERT INTO cipher_annotations VALUES('shared','alice',NULL,1),('shared','bob',NULL,0);",
            ).unwrap();
        }
        let store = crate::Store::open(path).unwrap();
        let owner: (Option<String>, String, String) = store
            .db
            .query_row(
                "SELECT owner,organization_id,document FROM items WHERE id='shared'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            owner,
            (None, "org".into(), "opaque encrypted payload".into())
        );
        let mut statement = store
            .db
            .prepare("SELECT user_id,favorite FROM cipher_annotations ORDER BY user_id")
            .unwrap();
        let annotations = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(annotations, [("alice".into(), true), ("bob".into(), false)]);
        assert!(
            store
                .db
                .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
                .unwrap()
        );
    }
}
