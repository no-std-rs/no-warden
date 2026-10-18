use no_warden::{
    Storage,
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub struct Store {
    pub db: Connection,
    pub pending: Value,
    owner: String,
    key_id: Option<String>,
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn revision_after(previous: &str, wall_millis: i64) -> rusqlite::Result<String> {
    let previous = chrono::DateTime::parse_from_rfc3339(previous)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .timestamp_millis();
    let next = wall_millis.max(
        previous
            .checked_add(1)
            .ok_or(rusqlite::Error::InvalidQuery)?,
    );
    Ok(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(next)
        .ok_or(rusqlite::Error::InvalidQuery)?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

// Read and advance the account clock within the transaction which mutates its
// vault. Distinct committed mutations must have distinct revisions even when
// the wall clock stays in one millisecond or moves backwards.
pub(crate) fn next_revision(db: &Connection, owner: &str) -> rusqlite::Result<String> {
    let previous: String = db.query_row(
        "SELECT revision FROM accounts WHERE id=?1",
        [owner],
        |row| row.get(0),
    )?;
    revision_after(&previous, chrono::Utc::now().timestamp_millis())
}

pub(crate) fn bump(db: &Connection, owner: &str, revision: &str) -> rusqlite::Result<()> {
    require_change(db.execute(
        "UPDATE accounts SET revision=?1,document=json_set(document,'$.revisionDate',?1) WHERE id=?2",
        params![revision, owner],
    )?)
}

fn require_change(changed: usize) -> rusqlite::Result<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}

fn item(db: &Connection, owner: &str, id: &str, kind: &str) -> rusqlite::Result<Option<Value>> {
    let document: Option<String> = db
        .query_row(
            "SELECT document FROM items WHERE owner=?1 AND id=?2 AND kind=?3",
            params![owner, id, kind],
            |r| r.get(0),
        )
        .optional()?;
    Ok(document.map(|s| serde_json::from_str(&s).expect("stored item JSON")))
}

#[cfg(unix)]
fn restrict_database_files(path: &str) -> std::io::Result<()> {
    use std::{
        fs::{OpenOptions, Permissions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    fn restrict(path: &Path, create: bool) -> std::io::Result<()> {
        // Create privately before SQLite opens the path, regardless of umask.
        // Setting permissions on the handle also repairs an existing database.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .open(path)?
            .set_permissions(Permissions::from_mode(0o600))
    }

    if path.is_empty() || path == ":memory:" {
        return Ok(());
    }
    restrict(Path::new(path), true)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        match restrict(Path::new(&format!("{path}{suffix}")), false) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            result => result?,
        }
    }
    Ok(())
}

impl Store {
    pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // URI filenames can redirect SQLite away from the path protected below.
        // This adapter accepts plain filesystem paths.
        if path.starts_with("file:") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NO_WARDEN_DB must be a filesystem path, not a SQLite URI",
            )
            .into());
        }
        #[cfg(unix)]
        restrict_database_files(path)?;
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL COLLATE NOCASE, document TEXT NOT NULL, password TEXT NOT NULL, revision TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL, document TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, revision TEXT NOT NULL, created TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS items_owner ON items(owner,kind);
            CREATE TABLE IF NOT EXISTS sessions(access TEXT PRIMARY KEY, refresh TEXT UNIQUE NOT NULL, owner TEXT NOT NULL REFERENCES accounts(id), access_expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL);")?;
        // SQLite inherits the private database mode for new sidecars. Also
        // narrow sidecars left behind by an earlier permissive installation.
        #[cfg(unix)]
        restrict_database_files(path)?;
        Ok(Self {
            db,
            pending: Value::Null,
            owner: String::new(),
            key_id: None,
        })
    }

    pub fn account(&self, field: &str, value: &str) -> rusqlite::Result<Option<Value>> {
        let query = if field == "email" {
            "SELECT document FROM accounts WHERE email=?1"
        } else {
            "SELECT document FROM accounts WHERE id=?1"
        };
        let document: Option<String> =
            self.db.query_row(query, [value], |r| r.get(0)).optional()?;
        Ok(document.map(|s| serde_json::from_str(&s).expect("stored account JSON")))
    }

    pub fn item(&self, owner: &str, id: &str, kind: &str) -> rusqlite::Result<Option<Value>> {
        item(&self.db, owner, id, kind)
    }

    pub fn items(&self, owner: &str, kind: &str) -> rusqlite::Result<Vec<Value>> {
        let mut statement = self
            .db
            .prepare("SELECT document FROM items WHERE owner=?1 AND kind=?2 ORDER BY rowid")?;
        statement
            .query_map(params![owner, kind], |r| r.get::<_, String>(0))?
            .map(|row| row.map(|s| serde_json::from_str(&s).expect("stored item JSON")))
            .collect()
    }

    fn metadata(&mut self, id: &str, kind: &str) -> rusqlite::Result<Option<ItemMetadata<'_>>> {
        let row: Option<(String, bool)> = self
            .db
            .query_row(
                "SELECT owner,deleted FROM items WHERE id=?1 AND kind=?2",
                params![id, kind],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((owner, deleted)) => {
                self.owner = owner;
                Ok(Some(ItemMetadata {
                    owner_id: &self.owner,
                    deleted,
                }))
            }
            None => Ok(None),
        }
    }

    fn save(&mut self, owner: &str, id: &str, kind: &str) -> rusqlite::Result<()> {
        let mut doc = self.pending.clone();
        let tx = self.db.transaction()?;
        let existing = item(&tx, owner, id, kind)?;
        let revision = next_revision(&tx, owner)?;
        doc["id"] = json!(id);
        doc["object"] = json!(if kind == "cipher" {
            "cipherDetails"
        } else {
            kind
        });
        doc["revisionDate"] = json!(revision);
        if kind == "cipher" {
            doc["creationDate"] = existing
                .as_ref()
                .map(|v| v["creationDate"].clone())
                .unwrap_or(json!(revision));
            doc["deletedDate"] = existing
                .as_ref()
                .map(|v| v["deletedDate"].clone())
                .unwrap_or(Value::Null);
            doc["organizationId"] = Value::Null;
            doc["collectionIds"] = json!([]);
            doc["attachments"] = Value::Null;
            doc["edit"] = json!(true);
            doc["viewPassword"] = json!(true);
            doc["organizationUseTotp"] = json!(false);
            doc["permissions"] = json!({"delete":true,"restore":true});
            doc.as_object_mut()
                .expect("validated object")
                .remove("lastKnownRevisionDate");
        }
        let deleted = doc.get("deletedDate").is_some_and(|v| !v.is_null());
        require_change(tx.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET document=excluded.document,revision=excluded.revision,deleted=excluded.deleted WHERE items.owner=excluded.owner AND items.kind=excluded.kind",
            params![id,owner,kind,doc.to_string(),deleted,revision,revision])?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }
}

impl Storage for Store {
    type Error = rusqlite::Error;

    fn user_key_id(&mut self, owner: &str) -> Result<Option<&str>, Self::Error> {
        // SQLite owns the query result only for the duration of the row callback.
        // Retain an owned copy so the returned slice borrows this adapter instead.
        self.key_id = self
            .db
            .query_row(
                "SELECT json_extract(document,'$.userKeyId') FROM accounts WHERE id=?1",
                [owner],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(self.key_id.as_deref())
    }

    fn account_exists(&mut self, email: &str) -> Result<bool, Self::Error> {
        Ok(self.account("email", email)?.is_some())
    }

    fn insert_account(&mut self, id: &str, _: &RegisterRequest<'_>) -> Result<(), Self::Error> {
        let mut document = self.pending.clone();
        let password = document["_password"]
            .as_str()
            .expect("prepared password")
            .to_owned();
        let fields = document.as_object_mut().expect("validated account");
        fields.remove("masterPasswordHash");
        fields.remove("_password");
        document["id"] = json!(id);
        document["email"] = json!(document["email"].as_str().unwrap().trim().to_lowercase());
        let revision = now();
        document["creationDate"] = json!(revision);
        document["revisionDate"] = json!(revision);
        self.db.execute(
            "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                document["email"].as_str(),
                document.to_string(),
                password,
                revision
            ],
        )?;
        Ok(())
    }

    fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
        self.metadata(id, "folder")
    }
    fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
        self.metadata(id, "cipher")
    }
    fn save_folder(
        &mut self,
        owner: &str,
        id: &str,
        _: &FolderRequest<'_>,
    ) -> Result<(), Self::Error> {
        self.save(owner, id, "folder")
    }
    fn save_cipher(
        &mut self,
        owner: &str,
        id: &str,
        _: &CipherRequest<'_>,
    ) -> Result<(), Self::Error> {
        self.save(owner, id, "cipher")
    }

    fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        // Removing a folder keeps its encrypted items and clears their folder reference.
        let tx = self.db.transaction()?;
        let revision = next_revision(&tx, owner)?;
        tx.execute("UPDATE items SET document=json_set(document,'$.folderId',NULL,'$.revisionDate',?1),revision=?1 WHERE owner=?2 AND kind='cipher' AND json_extract(document,'$.folderId')=?3",params![revision,owner,id])?;
        require_change(tx.execute(
            "DELETE FROM items WHERE owner=?1 AND id=?2 AND kind='folder'",
            params![owner, id],
        )?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }

    fn set_cipher_deleted(
        &mut self,
        owner: &str,
        id: &str,
        deleted: bool,
    ) -> Result<(), Self::Error> {
        let tx = self.db.transaction()?;
        let mut doc =
            item(&tx, owner, id, "cipher")?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let revision = next_revision(&tx, owner)?;
        doc["deletedDate"] = if deleted {
            json!(revision)
        } else {
            Value::Null
        };
        doc["revisionDate"] = json!(revision);
        require_change(tx.execute("UPDATE items SET document=?1,deleted=?2,revision=?3 WHERE id=?4 AND owner=?5 AND kind='cipher'",params![doc.to_string(),deleted,revision,id,owner])?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }

    fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        let tx = self.db.transaction()?;
        let revision = next_revision(&tx, owner)?;
        require_change(tx.execute(
            "DELETE FROM items WHERE owner=?1 AND id=?2 AND kind='cipher'",
            params![owner, id],
        )?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use no_warden::{ErrorKind, VaultService};
    use serde::Deserialize;

    const CIPHERTEXT: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn setup() -> Store {
        let store = Store::open(":memory:").unwrap();
        for owner in ["alice", "bob"] {
            let document = json!({"id":owner,"email":format!("{owner}@example.test")});
            store.db.execute(
                "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'test-verifier',?4)",
                params![owner,format!("{owner}@example.test"),document.to_string(),now()],
            ).unwrap();
        }
        store
    }

    fn save(store: &mut Store, owner: &str, id: &str, kind: &str, folder: Option<&str>) {
        store.pending = json!({
            "name": CIPHERTEXT,
            "type": 2,
            "secureNote": {"type":0},
            "folderId": folder,
        });
        store.save(owner, id, kind).unwrap();
    }

    fn snapshot(store: &Store) -> Vec<String> {
        let mut statement=store.db.prepare(
            "SELECT 'account:'||id||':'||document||':'||revision FROM accounts
             UNION ALL SELECT 'item:'||id||':'||owner||':'||document||':'||deleted||':'||revision||':'||created FROM items
             ORDER BY 1"
        ).unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn database_and_existing_sidecars_are_owner_only() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory =
            std::env::temp_dir().join(format!("no-warden-mode-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("vault.db");
        assert!(Store::open(&format!("file:{}?mode=rwc", path.display())).is_err());
        assert!(!path.exists());
        let store = Store::open(path.to_str().unwrap()).unwrap();
        let paths = [
            path.clone(),
            path.with_file_name("vault.db-wal"),
            path.with_file_name("vault.db-shm"),
        ];
        for file in &paths {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(file, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let reopened = Store::open(path.to_str().unwrap()).unwrap();
        for file in &paths {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(reopened);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn key_id_lookup_reads_current_account_and_clears_legacy_scratch() {
        let mut store = setup();
        store
            .db
            .execute(
                "UPDATE accounts SET document=json_set(document,'$.userKeyId',?1) WHERE id='alice'",
                ["opaque:key/id"],
            )
            .unwrap();
        assert_eq!(store.user_key_id("alice").unwrap(), Some("opaque:key/id"));
        assert_eq!(store.user_key_id("bob").unwrap(), None);
        assert_eq!(store.user_key_id("alice").unwrap(), Some("opaque:key/id"));
        assert_eq!(store.user_key_id("missing-account").unwrap(), None);
        store
            .db
            .execute(
                "UPDATE accounts SET document=json_set(document,'$.userKeyId',NULL) WHERE id='alice'",
                [],
            )
            .unwrap();
        assert_eq!(store.user_key_id("alice").unwrap(), None);
    }

    #[test]
    fn service_checks_persisted_key_id_before_creating_cipher() {
        let mut store = setup();
        store
            .db
            .execute(
                "UPDATE accounts SET document=json_set(document,'$.userKeyId','current-key') WHERE id='alice'",
                [],
            )
            .unwrap();
        let document = json!({
            "type": 2, "name": CIPHERTEXT, "secureNote": {"type": 0},
            "encryptedFor": "alice", "encryptedByKeyId": "wrong-key",
        });
        let request = CipherRequest::deserialize(&document).unwrap();
        store.pending = document.clone();
        let before = snapshot(&store);
        let error = VaultService::new(&mut store)
            .create_cipher("alice", "rejected-key", &request)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidRequest);
        assert_eq!(error.field, Some("encryptedByKeyId"));
        assert_eq!(snapshot(&store), before);

        for (owner, id, candidate) in [
            ("alice", "matching-key", Some("current-key")),
            ("alice", "omitted-key", None),
            ("bob", "unmigrated-account", Some("unknown-key")),
        ] {
            let mut document = json!({
                "type": 2, "name": CIPHERTEXT, "secureNote": {"type": 0},
                "encryptedFor": owner,
            });
            if let Some(candidate) = candidate {
                document["encryptedByKeyId"] = json!(candidate);
            }
            let request = CipherRequest::deserialize(&document).unwrap();
            store.pending = document.clone();
            VaultService::new(&mut store)
                .create_cipher(owner, id, &request)
                .unwrap();
            let saved = store.item(owner, id, "cipher").unwrap().unwrap();
            assert_eq!(saved["encryptedByKeyId"].as_str(), candidate);
        }
    }

    #[test]
    fn mutations_roll_back_when_account_revision_cannot_be_saved() {
        for operation in [
            "create",
            "update",
            "trash",
            "restore",
            "delete_cipher",
            "delete_folder",
        ] {
            let mut store = setup();
            save(&mut store, "alice", "folder", "folder", None);
            save(&mut store, "alice", "cipher", "cipher", Some("folder"));
            if operation == "restore" {
                store.set_cipher_deleted("alice", "cipher", true).unwrap();
            }
            let before = snapshot(&store);
            store
                .db
                .execute_batch(
                    "CREATE TRIGGER reject_account_revision BEFORE UPDATE OF revision ON accounts
                 BEGIN SELECT RAISE(ABORT,'injected revision failure'); END;",
                )
                .unwrap();
            let result = match operation {
                "create" => {
                    store.pending = json!({"name":CIPHERTEXT,"type":2,"secureNote":{"type":0}});
                    store.save("alice", "new-cipher", "cipher")
                }
                "update" => {
                    store.pending =
                        json!({"name":CIPHERTEXT,"type":2,"secureNote":{"type":0},"favorite":true});
                    store.save("alice", "cipher", "cipher")
                }
                "trash" => store.set_cipher_deleted("alice", "cipher", true),
                "restore" => store.set_cipher_deleted("alice", "cipher", false),
                "delete_cipher" => store.delete_cipher("alice", "cipher"),
                "delete_folder" => store.delete_folder("alice", "folder"),
                _ => unreachable!(),
            };
            assert!(
                result.is_err(),
                "{operation} must report the injected failure"
            );
            assert_eq!(snapshot(&store), before, "{operation} partially committed");
        }
    }

    #[test]
    fn revisions_advance_within_one_millisecond_and_after_clock_regression() {
        let first = "2026-10-18T00:00:00.000Z";
        let same_wall = chrono::DateTime::parse_from_rfc3339(first)
            .unwrap()
            .timestamp_millis();
        let second = revision_after(first, same_wall).unwrap();
        assert_eq!(second, "2026-10-18T00:00:00.001Z");
        assert_eq!(
            revision_after(&second, same_wall).unwrap(),
            "2026-10-18T00:00:00.002Z"
        );

        let mut store = setup();
        store
            .db
            .execute(
                "UPDATE accounts SET revision='2999-01-01T00:00:00.000Z' WHERE id='alice'",
                [],
            )
            .unwrap();
        save(&mut store, "alice", "cipher", "cipher", None);
        let first = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert_eq!(first["revisionDate"], "2999-01-01T00:00:00.001Z");
        save(&mut store, "alice", "cipher", "cipher", None);
        let second = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert_eq!(second["revisionDate"], "2999-01-01T00:00:00.002Z");
        assert_eq!(second["creationDate"], first["creationDate"]);
        assert_eq!(
            store.account("id", "alice").unwrap().unwrap()["revisionDate"],
            second["revisionDate"]
        );
    }

    #[test]
    fn deleting_folder_preserves_items_and_other_vaults() {
        let mut store = setup();
        save(&mut store, "alice", "folder", "folder", None);
        save(&mut store, "alice", "cipher", "cipher", Some("folder"));
        save(&mut store, "alice", "loose", "cipher", None);
        save(&mut store, "bob", "bob-folder", "folder", None);
        save(
            &mut store,
            "bob",
            "bob-cipher",
            "cipher",
            Some("bob-folder"),
        );
        let original = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        let loose = store.item("alice", "loose", "cipher").unwrap().unwrap();
        let foreign = store.item("bob", "bob-cipher", "cipher").unwrap().unwrap();
        store.delete_folder("alice", "folder").unwrap();
        assert!(store.item("alice", "folder", "folder").unwrap().is_none());
        let remaining = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert!(remaining["folderId"].is_null());
        assert_eq!(remaining["name"], original["name"]);
        assert_eq!(remaining["creationDate"], original["creationDate"]);
        assert_ne!(remaining["revisionDate"], original["revisionDate"]);
        assert_eq!(
            store.item("alice", "loose", "cipher").unwrap().unwrap(),
            loose
        );
        assert_eq!(
            store.item("bob", "bob-cipher", "cipher").unwrap().unwrap(),
            foreign
        );
    }

    #[test]
    fn server_metadata_overrides_request_fields_and_preserves_opaque_ciphertext() {
        let mut store = setup();
        store.pending = json!({
            "id":"chosen-by-client","object":"profile","revisionDate":"1900-01-01T00:00:00Z",
            "creationDate":"1900-01-01T00:00:00Z","deletedDate":"1900-01-01T00:00:00Z",
            "organizationId":"foreign","collectionIds":["foreign"],"attachments":[{"id":"foreign"}],
            "edit":false,"viewPassword":false,"permissions":{"delete":false,"restore":false},
            "lastKnownRevisionDate":"1900-01-01T00:00:00Z",
            "type":1,"name":CIPHERTEXT,"login":{"username":CIPHERTEXT,"futureClientField":{"payload":CIPHERTEXT}},
        });
        let opaque = store.pending["login"].clone();
        store.save("alice", "server-id", "cipher").unwrap();
        let first = store.item("alice", "server-id", "cipher").unwrap().unwrap();
        assert_eq!(first["id"], "server-id");
        assert_eq!(first["object"], "cipherDetails");
        assert_eq!(first["creationDate"], first["revisionDate"]);
        assert_ne!(first["revisionDate"], "1900-01-01T00:00:00Z");
        assert!(first["deletedDate"].is_null());
        assert!(first["organizationId"].is_null());
        assert_eq!(first["collectionIds"], json!([]));
        assert!(first["attachments"].is_null());
        assert_eq!(first["permissions"], json!({"delete":true,"restore":true}));
        assert_eq!(first["edit"], true);
        assert_eq!(first["viewPassword"], true);
        assert!(first.get("lastKnownRevisionDate").is_none());
        assert_eq!(first["login"], opaque);
        assert!(store.item("bob", "server-id", "cipher").unwrap().is_none());
        store.save("alice", "server-id", "cipher").unwrap();
        let second = store.item("alice", "server-id", "cipher").unwrap().unwrap();
        assert_eq!(second["creationDate"], first["creationDate"]);
        assert_ne!(second["revisionDate"], first["revisionDate"]);
        assert_eq!(second["login"], opaque);
    }
}
