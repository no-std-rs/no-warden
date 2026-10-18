use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use no_warden::{
    Storage,
    bulk::{CipherBulkOperation, CipherBulkStorage, ValidatedCipherBulk},
    identity::{ApiKeyDevice, IdentityStorage, ReauthenticationProof, Secret},
    import::{ImportData, ImportStorage, ValidatedImport},
    service::ItemMetadata,
    wire::{ApiKeyResponse, CipherRequest, FolderRequest, RegisterRequest},
};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub struct Store {
    pub db: Connection,
    pub pending: Value,
    owner: String,
    key_id: Option<String>,
    api_key_secret: Option<String>,
    api_key_revision: Option<String>,
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

fn verify_credential(encoded: Option<&str>, supplied: &str) -> rusqlite::Result<bool> {
    let Some(encoded) = encoded else {
        return Ok(false);
    };
    let hash = PasswordHash::new(encoded).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Argon2::default()
        .verify_password(supplied.as_bytes(), &hash)
        .is_ok())
}

fn item(db: &Connection, owner: &str, id: &str, kind: &str) -> rusqlite::Result<Option<Value>> {
    db.query_row(
        "SELECT i.document,a.cipher_id IS NOT NULL,a.archived_at FROM items i
             LEFT JOIN cipher_archives a ON a.cipher_id=i.id AND a.owner=i.owner
             WHERE i.owner=?1 AND i.id=?2 AND i.kind=?3",
        params![owner, id, kind],
        stored_document,
    )
    .optional()
}

fn stored_document(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let document: String = row.get(0)?;
    let mut document: Value = serde_json::from_str(&document).expect("stored item JSON");
    if row.get::<_, bool>(1)? {
        // A null annotation records an explicit unarchive, overriding raw request
        // metadata too. Cipher writes synchronize this annotation from archivedDate.
        document["archivedDate"] = json!(row.get::<_, Option<String>>(2)?);
    }
    Ok(document)
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
            CREATE TABLE IF NOT EXISTS cipher_archives(cipher_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE, owner TEXT NOT NULL REFERENCES accounts(id), archived_at TEXT, PRIMARY KEY(cipher_id,owner));
            CREATE TABLE IF NOT EXISTS api_keys(owner TEXT PRIMARY KEY REFERENCES accounts(id), secret TEXT NOT NULL, verifier TEXT NOT NULL);
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
            api_key_secret: None,
            api_key_revision: None,
        })
    }

    fn prepare_api_key(&mut self, owner: &str, rotate: bool) -> rusqlite::Result<()> {
        let tx = self.db.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM api_keys WHERE owner=?1)",
            [owner],
            |row| row.get(0),
        )?;
        if rotate || !exists {
            let secret = Alphanumeric.sample_string(&mut OsRng, 30);
            let salt = SaltString::generate(&mut OsRng);
            let verifier = Argon2::default()
                .hash_password(secret.as_bytes(), &salt)
                .map_err(|_| rusqlite::Error::InvalidQuery)?
                .to_string();
            let revision = next_revision(&tx, owner)?;
            tx.execute(
                "INSERT INTO api_keys(owner,secret,verifier) VALUES(?1,?2,?3)
                ON CONFLICT(owner) DO UPDATE SET secret=excluded.secret,verifier=excluded.verifier",
                params![owner, secret, verifier],
            )?;
            bump(&tx, owner, &revision)?;
        }
        // The key must remain recoverable for the authenticated retrieval API.
        // Its Argon2 verifier supplies constant-time credential verification.
        let (secret, revision) = tx.query_row(
            "SELECT k.secret,a.revision FROM api_keys k JOIN accounts a ON a.id=k.owner WHERE k.owner=?1",
            [owner], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        tx.commit()?;
        self.api_key_secret = Some(secret);
        self.api_key_revision = Some(revision);
        Ok(())
    }

    fn verify_authorization_hash(&self, owner: &str, supplied: &str) -> rusqlite::Result<bool> {
        let encoded: Option<String> = self
            .db
            .query_row(
                "SELECT password FROM accounts WHERE id=?1",
                [owner],
                |row| row.get(0),
            )
            .optional()?;
        verify_credential(encoded.as_deref(), supplied)
    }

    fn verify_api_secret(&self, owner: &str, supplied: &str) -> rusqlite::Result<bool> {
        let encoded: Option<String> = self
            .db
            .query_row(
                "SELECT verifier FROM api_keys WHERE owner=?1",
                [owner],
                |row| row.get(0),
            )
            .optional()?;
        verify_credential(encoded.as_deref(), supplied)
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
        let mut statement = self.db.prepare(
            "SELECT i.document,a.cipher_id IS NOT NULL,a.archived_at FROM items i
             LEFT JOIN cipher_archives a ON a.cipher_id=i.id AND a.owner=i.owner
             WHERE i.owner=?1 AND i.kind=?2 ORDER BY i.rowid",
        )?;
        statement
            .query_map(params![owner, kind], stored_document)?
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
        let tx = self.db.transaction()?;
        save_document(&tx, owner, id, kind, self.pending.clone(), true)?;
        tx.commit()
    }
}

// The caller owns the transaction. Imports use insert-only writes so a generated
// identifier collision cannot replace an existing item.
fn save_document(
    db: &Connection,
    owner: &str,
    id: &str,
    kind: &str,
    mut doc: Value,
    allow_update: bool,
) -> rusqlite::Result<()> {
    let existing = if allow_update {
        item(db, owner, id, kind)?
    } else {
        None
    };
    let revision = next_revision(db, owner)?;
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
    } else if kind == "folder" {
        // Folders have no creation or trash lifecycle in the upstream wire model.
        let fields = doc.as_object_mut().expect("validated object");
        fields.remove("creationDate");
        fields.remove("deletedDate");
    }
    let deleted = doc.get("deletedDate").is_some_and(|v| !v.is_null());
    require_change(db.execute(if allow_update { "INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET document=excluded.document,revision=excluded.revision,deleted=excluded.deleted WHERE items.owner=excluded.owner AND items.kind=excluded.kind" } else { "INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,?3,?4,?5,?6,?7)" },
            params![id,owner,kind,doc.to_string(),deleted,revision,revision])?)?;
    if kind == "cipher" {
        let archived_at = match doc.get("archivedDate") {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(date)) => chrono::NaiveDateTime::parse_from_str(date, "%+")
                .ok()
                .map(|date| {
                    Some(
                        date.and_utc()
                            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                    )
                }),
            _ => None,
        };
        if let Some(archived_at) = archived_at {
            save_archive(db, owner, id, archived_at.as_deref())?;
        } else {
            // Upstream ignores a malformed date without changing the prior state.
            // Older databases can have archive metadata only in the raw document.
            let previous = existing
                .as_ref()
                .and_then(|document| document["archivedDate"].as_str())
                .and_then(|date| chrono::NaiveDateTime::parse_from_str(date, "%+").ok())
                .map(|date| {
                    date.and_utc()
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                });
            db.execute(
                "INSERT INTO cipher_archives(cipher_id,owner,archived_at) VALUES(?1,?2,?3)
                 ON CONFLICT(cipher_id,owner) DO NOTHING",
                params![id, owner, previous],
            )?;
        }
    }
    bump(db, owner, &revision)?;
    Ok(())
}

fn save_archive(
    db: &Connection,
    owner: &str,
    id: &str,
    archived_at: Option<&str>,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO cipher_archives(cipher_id,owner,archived_at) VALUES(?1,?2,?3)
         ON CONFLICT(cipher_id,owner) DO UPDATE SET archived_at=excluded.archived_at",
        params![id, owner, archived_at],
    )?;
    Ok(())
}

impl ImportStorage for Store {
    fn commit_personal_import<'a, I: ImportData<'a> + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedImport<'_, 'a, I>,
    ) -> Result<(), Self::Error> {
        let data = plan.data();
        let mut folder_mapping = vec![None; data.cipher_count()];
        plan.fill_folder_mapping(&mut folder_mapping)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = self.db.transaction()?;
        // Resolve against the pre-import snapshot, before inserting any folders.
        // Repeated unknown IDs must create distinct folders, as upstream does.
        let mut folders = Vec::with_capacity(data.folder_count());
        let mut create = Vec::with_capacity(data.folder_count());
        for index in 0..data.folder_count() {
            let requested = data.folder(index).ok_or(rusqlite::Error::InvalidQuery)?;
            let existing = if let Some(id) = requested.id {
                item(&tx, owner, id, "folder")?.is_some()
            } else {
                false
            };
            folders.push(if existing {
                requested.id.expect("existing ID").to_owned()
            } else {
                uuid::Uuid::new_v4().to_string()
            });
            create.push(!existing);
        }
        for (index, id) in folders.iter().enumerate() {
            if create[index] {
                let document = self.pending["folders"][index].clone();
                save_document(&tx, owner, id, "folder", document, false)?;
            }
        }
        for (index, folder_index) in folder_mapping.into_iter().enumerate() {
            let folder_id = folder_index.map(|folder| folders[folder].as_str());
            let request = plan
                .cipher_for_create(index, folder_id)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let mut document = self.pending["ciphers"][index].clone();
            document["folderId"] = request.folder_id.map_or(Value::Null, |id| json!(id));
            save_document(
                &tx,
                owner,
                &uuid::Uuid::new_v4().to_string(),
                "cipher",
                document,
                false,
            )?;
        }
        // Even an empty import advances the account revision on the reference server.
        let revision = next_revision(&tx, owner)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }
}

impl IdentityStorage for Store {
    fn verify_reauthentication(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error> {
        match proof {
            ReauthenticationProof::MasterPasswordHash(secret) => {
                self.verify_authorization_hash(owner, secret.expose_secret())
            }
            // Protected-action email OTP issuance/consumption is a separate API family.
            ReauthenticationProof::ProtectedActionOtp(_) => Ok(false),
        }
    }

    fn get_or_create_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error> {
        self.prepare_api_key(owner, false)?;
        Ok(ApiKeyResponse {
            api_key: Secret::new(self.api_key_secret.as_deref().expect("prepared API key")),
            revision_date: self
                .api_key_revision
                .as_deref()
                .expect("prepared API key revision"),
        })
    }

    fn rotate_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error> {
        self.prepare_api_key(owner, true)?;
        Ok(ApiKeyResponse {
            api_key: Secret::new(self.api_key_secret.as_deref().expect("prepared API key")),
            revision_date: self
                .api_key_revision
                .as_deref()
                .expect("prepared API key revision"),
        })
    }

    fn verify_api_key(
        &mut self,
        user_id: &str,
        secret: &Secret<'_>,
        _device: ApiKeyDevice<'_>,
    ) -> Result<bool, Self::Error> {
        // This conformance host creates enabled password accounts. Disabled-account,
        // device administration and login-abuse policies remain provider responsibilities.
        self.verify_api_secret(user_id, secret.expose_secret())
    }
}

impl CipherBulkStorage for Store {
    fn commit_cipher_bulk(
        &mut self,
        owner: &str,
        plan: &ValidatedCipherBulk<'_, '_>,
    ) -> Result<(), Self::Error> {
        let tx = self.db.transaction()?;
        for id in plan.ids() {
            let mut document =
                item(&tx, owner, id, "cipher")?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            let revision = next_revision(&tx, owner)?;
            match plan.operation() {
                CipherBulkOperation::Delete => {
                    require_change(tx.execute(
                        "DELETE FROM items WHERE owner=?1 AND id=?2 AND kind='cipher'",
                        params![owner, id],
                    )?)?;
                }
                CipherBulkOperation::Trash | CipherBulkOperation::Restore => {
                    let deleted = plan.operation() == CipherBulkOperation::Trash;
                    document["deletedDate"] = if deleted {
                        json!(revision)
                    } else {
                        Value::Null
                    };
                    document["revisionDate"] = json!(revision);
                    require_change(tx.execute(
                        "UPDATE items SET document=?1,deleted=?2,revision=?3 WHERE owner=?4 AND id=?5 AND kind='cipher'",
                        params![document.to_string(), deleted, revision, owner, id],
                    )?)?;
                }
                CipherBulkOperation::Archive | CipherBulkOperation::Unarchive => {
                    let archived_at = if plan.operation() == CipherBulkOperation::Archive {
                        Some(
                            chrono::DateTime::parse_from_rfc3339(&revision)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?
                                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                        )
                    } else {
                        None
                    };
                    save_archive(&tx, owner, id, archived_at.as_deref())?;
                }
            }
            bump(&tx, owner, &revision)?;
        }
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

    #[test]
    fn api_keys_are_recoverable_stable_and_verified_independently_from_passwords() {
        let mut store = setup();
        let first = IdentityStorage::get_or_create_api_key(&mut store, "alice").unwrap();
        let key = first.api_key.expose_secret().to_owned();
        let revision = first.revision_date.to_owned();
        assert_eq!(key.len(), 30);
        assert!(key.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        let again = IdentityStorage::get_or_create_api_key(&mut store, "alice").unwrap();
        assert!(
            again.api_key.expose_secret() == key,
            "Retrieval must preserve the credential"
        );
        assert_eq!(again.revision_date, revision);
        assert!(store.verify_api_secret("alice", &key).unwrap());
        assert!(!store.verify_api_secret("bob", &key).unwrap());
        assert!(!store.verify_api_secret("alice", "wrong").unwrap());
        assert!(!store.verify_api_secret("absent", &key).unwrap());
        let rotated = IdentityStorage::rotate_api_key(&mut store, "alice").unwrap();
        let next = rotated.api_key.expose_secret().to_owned();
        assert!(next != key, "Rotation must replace the credential");
        assert_ne!(rotated.revision_date, revision);
        assert!(!store.verify_api_secret("alice", &key).unwrap());
        assert!(store.verify_api_secret("alice", &next).unwrap());
        let salt = SaltString::generate(&mut OsRng);
        let encoded = Argon2::default()
            .hash_password(b"server-authorization-hash", &salt)
            .unwrap()
            .to_string();
        store
            .db
            .execute(
                "UPDATE accounts SET password=?1 WHERE id='alice'",
                [encoded],
            )
            .unwrap();
        assert!(
            store
                .verify_authorization_hash("alice", "server-authorization-hash")
                .unwrap()
        );
        assert!(!store.verify_authorization_hash("alice", &next).unwrap());
        assert!(
            !IdentityStorage::verify_reauthentication(
                &mut store,
                "alice",
                ReauthenticationProof::ProtectedActionOtp(Secret::new("unsupported"))
            )
            .unwrap()
        );
    }

    #[test]
    fn api_key_creation_and_rotation_roll_back_with_the_account_revision() {
        for failure in ["revision", "response"] {
            for rotate in [false, true] {
                let mut store = setup();
                if rotate {
                    store.prepare_api_key("alice", false).unwrap();
                }
                let before = snapshot(&store);
                let credential = |store: &Store| {
                    store
                        .db
                        .query_row(
                            "SELECT secret,verifier FROM api_keys WHERE owner='alice'",
                            [],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                        )
                        .optional()
                        .unwrap()
                };
                let previous = credential(&store);
                let trigger = if failure == "revision" {
                    "CREATE TRIGGER reject_key_revision BEFORE UPDATE OF revision ON accounts
                BEGIN SELECT RAISE(ABORT,'injected key revision failure'); END;"
                } else {
                    // Make the response query fail after the new key and revision
                    // were written. The entire operation must still roll back.
                    "CREATE TRIGGER remove_key_before_response AFTER UPDATE OF revision ON accounts
                 BEGIN DELETE FROM api_keys WHERE owner=NEW.id; END;"
                };
                store.db.execute_batch(trigger).unwrap();
                assert!(store.prepare_api_key("alice", rotate).is_err());
                assert!(
                    credential(&store) == previous,
                    "Failed key persistence changed credentials"
                );
                assert_eq!(
                    snapshot(&store),
                    before,
                    "Failed key persistence changed the account"
                );
            }
        }
    }

    fn bulk(
        store: &mut Store,
        operation: CipherBulkOperation,
        ids: &[&str],
    ) -> Result<usize, no_warden::ApiError> {
        let mut scratch = vec![""; ids.len()];
        VaultService::new(store).bulk_ciphers("alice", operation, ids.iter().copied(), &mut scratch)
    }

    #[test]
    fn every_bulk_operation_rolls_back_late_storage_failure() {
        for operation in [
            CipherBulkOperation::Trash,
            CipherBulkOperation::Restore,
            CipherBulkOperation::Delete,
            CipherBulkOperation::Archive,
            CipherBulkOperation::Unarchive,
        ] {
            let mut store = setup();
            for id in ["a", "z"] {
                save(&mut store, "alice", id, "cipher", None);
            }
            save(&mut store, "bob", "foreign", "cipher", None);
            bulk(&mut store, CipherBulkOperation::Archive, &["a", "z"]).unwrap();
            if operation == CipherBulkOperation::Restore {
                bulk(&mut store, CipherBulkOperation::Trash, &["a", "z"]).unwrap();
            }
            let before = snapshot(&store);
            let trigger = match operation {
                CipherBulkOperation::Delete => {
                    "CREATE TRIGGER fail_bulk BEFORE DELETE ON items WHEN OLD.id='z' BEGIN SELECT RAISE(ABORT,'injected bulk failure'); END;"
                }
                CipherBulkOperation::Trash | CipherBulkOperation::Restore => {
                    "CREATE TRIGGER fail_bulk BEFORE UPDATE ON items WHEN NEW.id='z' BEGIN SELECT RAISE(ABORT,'injected bulk failure'); END;"
                }
                CipherBulkOperation::Archive | CipherBulkOperation::Unarchive => {
                    "CREATE TRIGGER fail_bulk BEFORE INSERT ON cipher_archives WHEN NEW.cipher_id='z' BEGIN SELECT RAISE(ABORT,'injected bulk failure'); END;"
                }
            };
            store.db.execute_batch(trigger).unwrap();
            assert_eq!(
                bulk(&mut store, operation, &["a", "z"]).unwrap_err().kind,
                ErrorKind::Storage
            );
            assert_eq!(
                snapshot(&store),
                before,
                "{operation:?} partially committed"
            );
        }
    }

    #[test]
    fn archive_annotations_follow_cipher_write_semantics_without_changing_action_revision() {
        let mut store = setup();
        save(&mut store, "alice", "cipher", "cipher", None);
        save(&mut store, "bob", "foreign", "cipher", None);
        let foreign = store.item("bob", "foreign", "cipher").unwrap().unwrap();
        let original = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        let revision = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
        bulk(
            &mut store,
            CipherBulkOperation::Archive,
            &["cipher", "cipher"],
        )
        .unwrap();
        let archived = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert_eq!(archived["revisionDate"], original["revisionDate"]);
        assert!(archived["archivedDate"].is_string());
        assert_ne!(
            store.account("id", "alice").unwrap().unwrap()["revisionDate"],
            revision
        );
        assert_eq!(
            store.item("bob", "foreign", "cipher").unwrap().unwrap(),
            foreign
        );

        // Invalid dates are ignored, retaining the prior annotation. No value is logged.
        store.pending =
            json!({"type":2,"name":CIPHERTEXT,"secureNote":{"type":0},"archivedDate":"invalid"});
        store.save("alice", "cipher", "cipher").unwrap();
        assert_eq!(
            store.item("alice", "cipher", "cipher").unwrap().unwrap()["archivedDate"],
            archived["archivedDate"]
        );
        // Omitted/null metadata explicitly clears archive state on ordinary writes.
        save(&mut store, "alice", "cipher", "cipher", None);
        assert!(
            store.item("alice", "cipher", "cipher").unwrap().unwrap()["archivedDate"].is_null()
        );
        store.pending = json!({"type":2,"name":CIPHERTEXT,"secureNote":{"type":0},"archivedDate":"2026-01-01T12:00:00.123456+02:00"});
        store.save("alice", "cipher", "cipher").unwrap();
        assert_eq!(
            store.item("alice", "cipher", "cipher").unwrap().unwrap()["archivedDate"],
            "2026-01-01T12:00:00.123456Z"
        );
        // Simulate the pre-annotation schema: valid archive metadata lives only
        // in the document. An invalid update must retain that effective state.
        store
            .db
            .execute("DELETE FROM cipher_archives WHERE cipher_id='cipher'", [])
            .unwrap();
        store.pending =
            json!({"type":2,"name":CIPHERTEXT,"secureNote":{"type":0},"archivedDate":"invalid"});
        store.save("alice", "cipher", "cipher").unwrap();
        assert_eq!(
            store.item("alice", "cipher", "cipher").unwrap().unwrap()["archivedDate"],
            "2026-01-01T12:00:00.123456Z"
        );
        let revision =
            store.item("alice", "cipher", "cipher").unwrap().unwrap()["revisionDate"].clone();
        bulk(&mut store, CipherBulkOperation::Unarchive, &["cipher"]).unwrap();
        let unarchived = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert!(unarchived["archivedDate"].is_null());
        assert_eq!(unarchived["revisionDate"], revision);
        bulk(&mut store, CipherBulkOperation::Delete, &["cipher"]).unwrap();
        let count: i64 = store
            .db
            .query_row(
                "SELECT count(*) FROM cipher_archives WHERE cipher_id='cipher'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "Permanent deletion must remove per-user annotations"
        );
    }

    fn import(store: &mut Store, owner: &str, document: &Value) -> Result<(), no_warden::ApiError> {
        let folders = Vec::deserialize(&document["folders"]).unwrap();
        let ciphers = Vec::deserialize(&document["ciphers"]).unwrap();
        let relationships = Vec::deserialize(&document["folderRelationships"]).unwrap();
        store.pending = document.clone();
        VaultService::new(store).import_personal(
            owner,
            &no_warden::import::ImportView {
                folders: &folders,
                ciphers: &ciphers,
                folder_relationships: &relationships,
            },
        )
    }

    #[test]
    fn a_late_import_write_failure_rolls_back_the_entire_batch() {
        let mut store = setup();
        save(&mut store, "alice", "existing", "folder", None);
        save(&mut store, "bob", "foreign", "folder", None);
        let before = snapshot(&store);
        store
            .db
            .execute_batch(
                "CREATE TRIGGER reject_second_imported_cipher BEFORE INSERT ON items
             WHEN NEW.kind='cipher' AND json_extract(NEW.document,'$.favorite')=1
             BEGIN SELECT RAISE(ABORT,'injected import failure'); END;",
            )
            .unwrap();
        let document = json!({
            "folders": [{"name": CIPHERTEXT}],
            "ciphers": [
                {"type":2,"name":CIPHERTEXT,"secureNote":{"type":0}},
                {"type":2,"name":CIPHERTEXT,"secureNote":{"type":0},"favorite":true}
            ],
            "folderRelationships": [{"key":0,"value":0},{"key":1,"value":0}]
        });
        assert_eq!(
            import(&mut store, "alice", &document).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(snapshot(&store), before);
    }

    #[test]
    fn import_uses_a_folder_snapshot_and_fresh_server_metadata() {
        let mut store = setup();
        save(&mut store, "alice", "existing", "folder", None);
        save(&mut store, "bob", "foreign", "folder", None);
        let owned = store.item("alice", "existing", "folder").unwrap().unwrap();
        let foreign = store.item("bob", "foreign", "folder").unwrap().unwrap();
        let document = json!({
            "folders": [
                {"id":"existing","name":CIPHERTEXT},
                {"id":"foreign","name":CIPHERTEXT},
                {"id":"not-present","name":CIPHERTEXT},
                {"id":"not-present","name":CIPHERTEXT,
                 "creationDate":"1900-01-01T00:00:00Z","deletedDate":"1900-01-01T00:00:00Z",
                 "futureEncryptedField":CIPHERTEXT}
            ],
            "ciphers": [{
                "id":"client-id","type":2,"name":CIPHERTEXT,"secureNote":{"type":0,"futureEncryptedField":CIPHERTEXT},
                "folderId":"foreign","deletedDate":"1900-01-01T00:00:00Z",
                "creationDate":"1900-01-01T00:00:00Z","revisionDate":"1900-01-01T00:00:00Z",
                "lastKnownRevisionDate":"1900-01-01T00:00:00Z"
            }],
            "folderRelationships": [{"key":0,"value":1}]
        });
        import(&mut store, "alice", &document).unwrap();
        let folders = store.items("alice", "folder").unwrap();
        assert_eq!(folders.len(), 4);
        for folder in &folders {
            assert!(folder.get("creationDate").is_none());
            assert!(folder.get("deletedDate").is_none());
        }
        assert!(
            folders
                .iter()
                .any(|folder| folder["futureEncryptedField"] == CIPHERTEXT)
        );
        let deleted_folders: i64 = store
            .db
            .query_row(
                "SELECT count(*) FROM items WHERE kind='folder' AND deleted != 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(deleted_folders, 0);
        assert_eq!(
            store.item("alice", "existing", "folder").unwrap().unwrap(),
            owned
        );
        assert_eq!(
            store.item("bob", "foreign", "folder").unwrap().unwrap(),
            foreign
        );
        let ciphers = store.items("alice", "cipher").unwrap();
        assert_eq!(ciphers.len(), 1);
        let cipher = &ciphers[0];
        assert_ne!(cipher["id"], "client-id");
        assert_ne!(cipher["folderId"], "foreign");
        assert!(
            folders
                .iter()
                .any(|folder| folder["id"] == cipher["folderId"])
        );
        assert!(cipher["deletedDate"].is_null());
        assert_ne!(cipher["creationDate"], "1900-01-01T00:00:00Z");
        assert_eq!(cipher["creationDate"], cipher["revisionDate"]);
        assert_eq!(cipher["secureNote"], document["ciphers"][0]["secureNote"]);
        assert!(cipher.get("lastKnownRevisionDate").is_none());
    }

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
             UNION ALL SELECT 'archive:'||cipher_id||':'||owner||':'||COALESCE(archived_at,'unarchived') FROM cipher_archives
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
