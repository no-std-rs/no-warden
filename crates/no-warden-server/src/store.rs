use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use no_warden::{
    Storage,
    account_keys::{AccountKeyState, AccountKeyStorage},
    account_profile::AccountProfileStorage,
    auth_requests::{AuthRequestContext, AuthRequestRecord, AuthRequestStorage},
    bulk::{CipherBulkOperation, CipherBulkStorage, ValidatedCipherBulk},
    device_push::{ClearedDevicePush, DevicePushState, DevicePushStorage},
    devices::{DeviceRecord, DeviceRegistration, DeviceStorage},
    domains::{DomainSettingsData, DomainSettingsStorage},
    identity::{ApiKeyDevice, IdentityStorage, ReauthenticationProof, Secret},
    import::{ImportData, ImportStorage, ValidatedImport},
    service::ItemMetadata,
    wire::{
        AccountKeys, ApiKeyResponse, AuthRequestCreateRequest, AvatarUpdateRequest, CipherRequest,
        DevicePushTokenRequest, FolderRequest, ProfileUpdateRequest, RegisterRequest,
    },
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
    pub download_base: String,
    pub(crate) pending_attachment_data: Vec<u8>,
    pub(crate) attachment_metadata_cache: Option<crate::attachments::Record>,
    owner: String,
    key_id: Option<String>,
    api_key_secret: Option<String>,
    api_key_revision: Option<String>,
    account_key_cache: Option<CachedAccountKeys>,
    public_key_cache: Option<String>,
    domain_settings_cache: crate::domains::Settings,
    device_list_cache: crate::devices::Registry,
    device_cache: Option<crate::devices::Record>,
    device_push_token_cache: Option<String>,
    auth_request_cache: Option<crate::auth_requests::Record>,
    auth_requests_cache: crate::auth_requests::Requests,
}

// Owned query results keep the optional core response borrows tied to this
// adapter. Formatting and general serialization never expose cached key data.
struct CachedAccountKeys {
    key: String,
    public_key: Option<String>,
    encrypted_private_key: Option<String>,
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
            CREATE TABLE IF NOT EXISTS account_domains(owner TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, excluded_globals TEXT NOT NULL, equivalent_domains TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE, file_name TEXT NOT NULL, key TEXT, size INTEGER NOT NULL CHECK(size>=0), data BLOB);
            CREATE INDEX IF NOT EXISTS attachments_cipher ON attachments(cipher_id);
            CREATE TABLE IF NOT EXISTS attachment_downloads(token TEXT PRIMARY KEY, attachment_id TEXT NOT NULL REFERENCES attachments(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(access TEXT PRIMARY KEY, refresh TEXT UNIQUE NOT NULL, owner TEXT NOT NULL REFERENCES accounts(id), access_expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS device_registry(owner TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, identifier TEXT NOT NULL, name TEXT NOT NULL, device_type INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY(owner,identifier));
            CREATE TABLE IF NOT EXISTS device_push_tokens(owner TEXT NOT NULL, identifier TEXT NOT NULL, token TEXT NOT NULL, PRIMARY KEY(owner,identifier), FOREIGN KEY(owner,identifier) REFERENCES device_registry(owner,identifier) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS auth_requests(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, request_device_identifier TEXT NOT NULL, device_type INTEGER NOT NULL, request_ip TEXT NOT NULL, access_code TEXT NOT NULL, public_key TEXT NOT NULL, encrypted_key TEXT, master_password_hash TEXT, approved INTEGER, creation_date TEXT NOT NULL, response_date TEXT, response_device_id TEXT, authentication_date TEXT);
            CREATE INDEX IF NOT EXISTS auth_requests_owner_device ON auth_requests(owner,request_device_identifier,creation_date DESC);
            CREATE TABLE IF NOT EXISTS session_devices(access TEXT PRIMARY KEY REFERENCES sessions(access) ON DELETE CASCADE, owner TEXT NOT NULL, identifier TEXT NOT NULL, FOREIGN KEY(owner,identifier) REFERENCES device_registry(owner,identifier) ON DELETE CASCADE);")?;
        // SQLite inherits the private database mode for new sidecars. Also
        // narrow sidecars left behind by an earlier permissive installation.
        #[cfg(unix)]
        restrict_database_files(path)?;
        Ok(Self {
            db,
            pending: Value::Null,
            download_base: String::new(),
            pending_attachment_data: Vec::new(),
            attachment_metadata_cache: None,
            owner: String::new(),
            key_id: None,
            api_key_secret: None,
            api_key_revision: None,
            account_key_cache: None,
            public_key_cache: None,
            domain_settings_cache: crate::domains::Settings::default(),
            device_list_cache: crate::devices::Registry::default(),
            device_cache: None,
            device_push_token_cache: None,
            auth_request_cache: None,
            auth_requests_cache: crate::auth_requests::Requests::default(),
        })
    }

    fn update_profile_field(
        &mut self,
        owner: &str,
        path: &'static str,
        value: Option<&str>,
    ) -> rusqlite::Result<()> {
        let tx = self.db.transaction()?;
        let revision = next_revision(&tx, owner)?;
        require_change(tx.execute(
            "UPDATE accounts SET document=json_set(document,?1,?2) WHERE id=?3",
            params![path, value, owner],
        )?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
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
        let mut document = item(&self.db, owner, id, kind)?;
        if kind == "cipher"
            && let Some(document) = &mut document
        {
            crate::attachments::enrich_cipher(&self.db, &self.download_base, document)?;
        }
        Ok(document)
    }

    pub fn items(&self, owner: &str, kind: &str) -> rusqlite::Result<Vec<Value>> {
        let mut statement = self.db.prepare(
            "SELECT i.document,a.cipher_id IS NOT NULL,a.archived_at FROM items i
             LEFT JOIN cipher_archives a ON a.cipher_id=i.id AND a.owner=i.owner
             WHERE i.owner=?1 AND i.kind=?2 ORDER BY i.rowid",
        )?;
        let mut documents = statement
            .query_map(params![owner, kind], stored_document)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if kind == "cipher" {
            for document in &mut documents {
                crate::attachments::enrich_cipher(&self.db, &self.download_base, document)?;
            }
        }
        Ok(documents)
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
        crate::attachments::rewrap(db, id, &doc)?;
        doc.as_object_mut()
            .expect("validated object")
            .remove("attachments2");
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

impl AuthRequestStorage for Store {
    type OwnerId = String;
    type Requests<'a> = &'a crate::auth_requests::Requests;
    fn auth_request_owner(&mut self, email: &str) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT id FROM accounts WHERE email=?1",
                [email.to_lowercase()],
                |row| row.get(0),
            )
            .optional()
    }
    fn create_auth_request(
        &mut self,
        owner: &str,
        request: &AuthRequestCreateRequest<'_>,
        context: &AuthRequestContext<'_>,
    ) -> rusqlite::Result<AuthRequestRecord<'_>> {
        let record = crate::auth_requests::create(&mut self.db, owner, request, context)?;
        self.auth_request_cache = Some(record);
        Ok(self
            .auth_request_cache
            .as_ref()
            .expect("Committed auth-request cache.")
            .view())
    }
    fn auth_request(
        &mut self,
        owner: &str,
        id: &str,
    ) -> rusqlite::Result<Option<AuthRequestRecord<'_>>> {
        self.auth_request_cache = crate::auth_requests::load(&self.db, owner, id)?;
        Ok(self
            .auth_request_cache
            .as_ref()
            .map(crate::auth_requests::Record::view))
    }
    fn auth_requests(&mut self, owner: &str) -> rusqlite::Result<Self::Requests<'_>> {
        self.auth_requests_cache = crate::auth_requests::list(&self.db, owner)?;
        Ok(&self.auth_requests_cache)
    }
}

impl DevicePushStorage for Store {
    type PushId = String;

    fn push_enabled(&self) -> bool {
        false
    }
    fn device_push_state(
        &mut self,
        owner: &str,
        session_identifier: &str,
    ) -> rusqlite::Result<Option<DevicePushState<'_>>> {
        self.device_cache = crate::devices::load(&self.db, owner, session_identifier)?;
        self.device_push_token_cache =
            crate::devices::push_token(&self.db, owner, session_identifier)?;
        Ok(self.device_cache.as_ref().map(|record| DevicePushState {
            owner_id: &record.owner,
            identifier: &record.identifier,
            push_token: self.device_push_token_cache.as_deref(),
        }))
    }
    fn save_device_push_token(
        &mut self,
        owner: &str,
        session_identifier: &str,
        request: &DevicePushTokenRequest<'_>,
    ) -> rusqlite::Result<()> {
        crate::devices::save_push_token(&mut self.db, owner, session_identifier, request.push_token)
    }
    fn register_device_push(
        &mut self,
        _owner: &str,
        _session_identifier: &str,
    ) -> rusqlite::Result<()> {
        // Standalone push configuration is disabled: no relay or outbound HTTP.
        Ok(())
    }
    fn clear_device_push_tokens(
        &mut self,
        _identifier: &str,
    ) -> rusqlite::Result<ClearedDevicePush<Self::PushId>> {
        // Disabled clear must return before this storage hook is invoked.
        Err(rusqlite::Error::InvalidQuery)
    }
    fn unregister_device_push(&mut self, _push_id: &str) -> rusqlite::Result<()> {
        Err(rusqlite::Error::InvalidQuery)
    }
}

impl DeviceStorage for Store {
    type Devices<'a> = &'a crate::devices::Registry;

    fn known_device(&mut self, decoded_email: &str, identifier: &str) -> rusqlite::Result<bool> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM device_registry d JOIN accounts a ON a.id=d.owner WHERE a.email=?1 AND d.identifier=?2)", params![decoded_email.to_lowercase(),identifier], |row| row.get(0))
    }
    fn devices(&mut self, owner: &str) -> rusqlite::Result<Self::Devices<'_>> {
        self.device_list_cache = crate::devices::list(&self.db, owner)?;
        Ok(&self.device_list_cache)
    }
    fn device(
        &mut self,
        owner: &str,
        identifier: &str,
    ) -> rusqlite::Result<Option<DeviceRecord<'_>>> {
        self.device_cache = crate::devices::load(&self.db, owner, identifier)?;
        Ok(self.device_cache.as_ref().map(crate::devices::Record::view))
    }
    fn register_device(
        &mut self,
        owner: &str,
        registration: &DeviceRegistration<'_>,
    ) -> rusqlite::Result<()> {
        crate::devices::register(&mut self.db, owner, registration)
    }
}

impl DomainSettingsStorage for Store {
    type Settings<'a>
        = &'a crate::domains::Settings
    where
        Self: 'a;

    fn domain_settings(&mut self, owner: &str) -> Result<Self::Settings<'_>, Self::Error> {
        let (excluded, equivalent): (String, String) = self.db.query_row(
            "SELECT COALESCE(d.excluded_globals,'[]'),COALESCE(d.equivalent_domains,'[]')
             FROM accounts a LEFT JOIN account_domains d ON d.owner=a.id WHERE a.id=?1",
            [owner],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        self.domain_settings_cache = crate::domains::Settings {
            excluded_globals: serde_json::from_str(&excluded)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            equivalent_domains: serde_json::from_str(&equivalent)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        };
        Ok(&self.domain_settings_cache)
    }

    fn update_domain_settings<D: DomainSettingsData + ?Sized>(
        &mut self,
        owner: &str,
        data: &D,
    ) -> Result<(), Self::Error> {
        let settings = crate::domains::Settings::from_data(data)?;
        let excluded = serde_json::to_string(&settings.excluded_globals)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let equivalent = serde_json::to_string(&settings.equivalent_domains)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = self.db.transaction()?;
        let revision = next_revision(&tx, owner)?;
        require_change(tx.execute(
            "INSERT INTO account_domains(owner,excluded_globals,equivalent_domains) VALUES(?1,?2,?3)
             ON CONFLICT(owner) DO UPDATE SET excluded_globals=excluded.excluded_globals,equivalent_domains=excluded.equivalent_domains",
            params![owner,excluded,equivalent],
        )?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }
}

impl AccountProfileStorage for Store {
    fn update_profile_name(
        &mut self,
        owner: &str,
        request: &ProfileUpdateRequest<'_>,
    ) -> Result<(), Self::Error> {
        self.update_profile_field(owner, "$.name", Some(request.name))
    }

    fn update_avatar_color(
        &mut self,
        owner: &str,
        request: &AvatarUpdateRequest<'_>,
    ) -> Result<(), Self::Error> {
        self.update_profile_field(owner, "$.avatarColor", request.avatar_color)
    }
}

impl AccountKeyStorage for Store {
    fn account_key_state(
        &mut self,
        owner: &str,
    ) -> Result<Option<AccountKeyState<'_>>, Self::Error> {
        self.account_key_cache = self
            .db
            .query_row(
                "SELECT COALESCE(json_extract(document,'$.key'),''),
                    json_extract(document,'$.keys.publicKey'),
                    json_extract(document,'$.keys.encryptedPrivateKey')
             FROM accounts WHERE id=?1",
                [owner],
                |row| {
                    Ok(CachedAccountKeys {
                        key: row.get(0)?,
                        public_key: row.get(1)?,
                        encrypted_private_key: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(self.account_key_cache.as_ref().map(|keys| AccountKeyState {
            key: &keys.key,
            public_key: keys.public_key.as_deref(),
            encrypted_private_key: keys.encrypted_private_key.as_deref(),
        }))
    }

    fn initialize_account_keys(
        &mut self,
        owner: &str,
        request: &AccountKeys<'_>,
    ) -> Result<(), Self::Error> {
        let tx = self.db.transaction()?;
        let encoded: String = tx.query_row(
            "SELECT document FROM accounts WHERE id=?1",
            [owner],
            |row| row.get(0),
        )?;
        let mut document: Value =
            serde_json::from_str(&encoded).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let fields = document
            .as_object_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let keys = fields.entry("keys").or_insert_with(|| json!({}));
        if keys.is_null() {
            *keys = json!({});
        }
        let keys = keys.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
        // The service checks the same condition under the host mutex. Repeat
        // it inside the transaction so this provider never replaces an existing
        // or partially initialized pair, including a present empty string.
        if ["publicKey", "encryptedPrivateKey"]
            .iter()
            .any(|key| keys.get(*key).is_some_and(|value| !value.is_null()))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        keys.insert("publicKey".into(), json!(request.public_key));
        keys.insert(
            "encryptedPrivateKey".into(),
            json!(request.encrypted_private_key),
        );
        let revision = next_revision(&tx, owner)?;
        require_change(tx.execute(
            "UPDATE accounts SET document=?1 WHERE id=?2",
            params![document.to_string(), owner],
        )?)?;
        bump(&tx, owner, &revision)?;
        tx.commit()
    }

    fn user_public_key(&mut self, user_id: &str) -> Result<Option<&str>, Self::Error> {
        self.public_key_cache = self
            .db
            .query_row(
                "SELECT json_extract(document,'$.keys.publicKey') FROM accounts WHERE id=?1",
                [user_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(self.public_key_cache.as_deref())
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
        // Registration does not authorize avatar changes. Only the dedicated
        // avatar endpoint can populate this authoritative profile field.
        document["avatarColor"] = Value::Null;
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
        // A folder association belongs to the user's view of a cipher. Removing
        // it advances the account revision without changing the cipher revision.
        let tx = self.db.transaction()?;
        let revision = next_revision(&tx, owner)?;
        tx.execute(
            "UPDATE items SET document=json_set(document,'$.folderId',NULL)
             WHERE owner=?1 AND kind='cipher' AND json_extract(document,'$.folderId')=?2",
            params![owner, id],
        )?;
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
    use no_warden::{ErrorKind, VaultService, devices::DeviceListData};
    use serde::Deserialize;

    const CIPHERTEXT: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn auth_request_fixture() -> Store {
        let mut store = profile_fixture();
        for (owner, identifier, device_type) in [
            ("alice", "Request-Device", 8),
            ("bob", "Request-Device", 8),
            ("alice", "Other-Device", 14),
            ("alice", "Unknown-Device", -7),
            ("alice", "", 14),
        ] {
            VaultService::new(&mut store)
                .register_device(
                    owner,
                    &DeviceRegistration {
                        identifier,
                        name: "Original",
                        device_type,
                    },
                )
                .unwrap();
        }
        store
    }
    fn auth_request_rows(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT id||':'||owner||':'||request_device_identifier||':'||device_type||':'||request_ip||':'||access_code||':'||public_key||':'||COALESCE(encrypted_key,'null')||':'||COALESCE(master_password_hash,'null')||':'||COALESCE(approved,'null')||':'||creation_date||':'||COALESCE(response_date,'null')||':'||COALESCE(response_device_id,'null')||':'||COALESCE(authentication_date,'null') FROM auth_requests ORDER BY id").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }
    fn create_fixture_auth_request(
        store: &mut Store,
        email: &str,
        identifier: &str,
        device_type: i32,
    ) -> Result<Value, no_warden::ApiError> {
        let context = AuthRequestContext {
            device_type,
            request_ip: "203.0.113.27",
            origin: "https://origin.example.test",
        };
        let request = AuthRequestCreateRequest {
            access_code: "NUL\0private-access-sentinel",
            device_identifier: identifier,
            email,
            public_key: "opaque-public\0café 雪",
        };
        serde_json::to_value(VaultService::new(store).create_auth_request(&request, &context)?)
            .map_err(|_| {
                no_warden::ApiError::invalid("fixture", "Auth-request serialization failed")
            })
    }
    #[test]
    fn auth_request_creation_preserves_account_authority_devices_and_private_code_projection() {
        let mut store = auth_request_fixture();
        let before = snapshot(&store);
        let authority = account_authority_snapshot(&store);
        let devices = device_rows(&store);
        let pushes = device_push_rows(&store);
        let created =
            create_fixture_auth_request(&mut store, "ALICE@EXAMPLE.TEST", "Request-Device", 8)
                .unwrap();
        assert_eq!(created.as_object().unwrap().len(), 11);
        assert!(
            created["requestApproved"] == false
                && created["requestDeviceType"] == "Linux"
                && created["requestIpAddress"] == "203.0.113.27"
                && created["origin"] == "https://origin.example.test"
        );
        assert!(
            created["publicKey"] == "opaque-public\0café 雪"
                && created["key"].is_null()
                && created["masterPasswordHash"].is_null()
                && created["responseDate"].is_null()
        );
        assert!(uuid::Uuid::parse_str(created["id"].as_str().unwrap()).is_ok());
        assert!(
            chrono::DateTime::parse_from_rfc3339(created["creationDate"].as_str().unwrap()).is_ok()
        );
        assert!(!created.to_string().contains("private-access-sentinel"));
        let id = created["id"].as_str().unwrap();
        let read = serde_json::to_value(
            VaultService::new(&mut store)
                .get_auth_request("alice", id, "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        let mut expected = created.clone();
        expected["requestApproved"] = Value::Null;
        assert!(read == expected && !read.to_string().contains("private-access-sentinel"));
        assert!(
            VaultService::new(&mut store)
                .get_auth_request("bob", id, "https://origin.example.test")
                .is_err()
        );
        let state = AuthRequestStorage::auth_request(&mut store, "alice", id)
            .unwrap()
            .unwrap();
        assert!(
            state.access_code == "NUL\0private-access-sentinel"
                && state.approved.is_none()
                && state.request_device_identifier == "Request-Device"
        );
        assert!(
            snapshot(&store) == before
                && account_authority_snapshot(&store) == authority
                && device_rows(&store) == devices
                && device_push_rows(&store) == pushes,
            "Auth-request creation changed unrelated stored state."
        );
        assert_eq!(auth_request_rows(&store).len(), 1);
        let unknown =
            create_fixture_auth_request(&mut store, "alice@example.test", "Unknown-Device", -7)
                .unwrap();
        assert!(unknown["requestDeviceType"] == "Unknown Browser");
        let empty = create_fixture_auth_request(&mut store, "alice@example.test", "", 14).unwrap();
        assert!(empty["requestDeviceType"] == "Unknown Browser");
    }
    #[test]
    fn auth_request_verification_rejections_and_failed_insert_or_commit_preserve_state() {
        let mut store = auth_request_fixture();
        let before = snapshot(&store);
        let devices = device_rows(&store);
        for (email, id, kind) in [
            (" alice@example.test", "Request-Device", 8),
            ("alice@example.test ", "Request-Device", 8),
            ("missing@example.test", "Request-Device", 8),
            ("alice@example.test", "request-device", 8),
            ("alice@example.test", "Request-Device", 14),
            ("bob@example.test", "Other-Device", 14),
        ] {
            assert!(create_fixture_auth_request(&mut store, email, id, kind).is_err());
            assert!(
                auth_request_rows(&store).is_empty()
                    && snapshot(&store) == before
                    && device_rows(&store) == devices
            );
        }
        store
            .db
            .execute(
                "UPDATE accounts SET email='śnieg@example.test' WHERE id='alice'",
                [],
            )
            .unwrap();
        assert!(
            create_fixture_auth_request(&mut store, "ŚNIEG@EXAMPLE.TEST", "Request-Device", 8)
                .is_ok()
        );
        for trigger in [
            "CREATE TRIGGER reject_auth_request AFTER INSERT ON auth_requests BEGIN UPDATE accounts SET revision='corrupt' WHERE id=NEW.owner; SELECT RAISE(FAIL,'injected auth-request insert failure'); END;",
            "CREATE TABLE failed_auth_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_auth_request_commit AFTER INSERT ON auth_requests BEGIN INSERT INTO failed_auth_commit(owner) VALUES('missing'); END;",
        ] {
            let mut store = auth_request_fixture();
            let before = snapshot(&store);
            let authority = account_authority_snapshot(&store);
            let devices = device_rows(&store);
            store.db.execute_batch(trigger).unwrap();
            assert!(
                create_fixture_auth_request(&mut store, "alice@example.test", "Request-Device", 8)
                    .is_err()
            );
            assert!(
                auth_request_rows(&store).is_empty()
                    && snapshot(&store) == before
                    && account_authority_snapshot(&store) == authority
                    && device_rows(&store) == devices,
                "Failed auth-request create changed persisted state."
            );
            assert!(store.db.is_autocommit());
        }
    }
    #[test]
    fn auth_request_pending_list_filters_approval_and_devices_show_latest_owned_request_only() {
        let mut store = auth_request_fixture();
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                create_fixture_auth_request(&mut store, "alice@example.test", "Request-Device", 8)
                    .unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let foreign =
            create_fixture_auth_request(&mut store, "bob@example.test", "Request-Device", 8)
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
        for (index, id) in ids.iter().enumerate() {
            store
                .db
                .execute(
                    "UPDATE auth_requests SET creation_date=?1 WHERE id=?2",
                    params![format!("2026-10-18T00:00:0{index}.000000Z"), id],
                )
                .unwrap();
        }
        store
            .db
            .execute(
                "UPDATE auth_requests SET creation_date='2026-10-18T00:00:09.000000Z' WHERE id=?1",
                [&foreign],
            )
            .unwrap();
        let list = serde_json::to_value(
            VaultService::new(&mut store)
                .list_auth_requests("alice", "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list["data"].as_array().unwrap().len(), 3);
        assert!(
            list["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["requestApproved"].is_null() && item["id"] != foreign)
        );
        let projected =
            serde_json::to_value(VaultService::new(&mut store).list_devices("alice").unwrap())
                .unwrap();
        let device = projected["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "Request-Device")
            .unwrap();
        assert!(
            device["devicePendingAuthRequest"]
                == json!({"id":ids[2],"creationDate":"2026-10-18T00:00:02.000000Z"})
        );
        assert_eq!(device.as_object().unwrap().len(), 10);
        assert_eq!(
            device["devicePendingAuthRequest"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        store.db.execute("UPDATE auth_requests SET approved=0,encrypted_key='opaque-key',master_password_hash='opaque-hash',response_date='2026-10-18T00:00:10.000000Z' WHERE id=?1",[&ids[2]]).unwrap();
        store
            .db
            .execute("UPDATE auth_requests SET approved=1 WHERE id=?1", [&ids[1]])
            .unwrap();
        let list = serde_json::to_value(
            VaultService::new(&mut store)
                .list_auth_requests("alice", "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        assert!(list["data"].as_array().unwrap().len() == 1 && list["data"][0]["id"] == ids[0]);
        let read = serde_json::to_value(
            VaultService::new(&mut store)
                .get_auth_request("alice", &ids[2], "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        assert!(
            read["requestApproved"] == false
                && read["key"] == "opaque-key"
                && read["masterPasswordHash"] == "opaque-hash"
                && read["responseDate"] == "2026-10-18T00:00:10.000000Z"
        );
        let projected =
            serde_json::to_value(VaultService::new(&mut store).list_devices("alice").unwrap())
                .unwrap();
        let device = projected["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "Request-Device")
            .unwrap();
        assert!(device["devicePendingAuthRequest"]["id"] == ids[0]);
        let single = serde_json::to_value(
            VaultService::new(&mut store)
                .get_device("alice", "Request-Device")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(single.as_object().unwrap().len(), 7);
        assert!(single.get("devicePendingAuthRequest").is_none());
    }
    #[test]
    fn auth_request_private_state_survives_reopen_and_document_extras_have_no_authority() {
        let directory =
            std::env::temp_dir().join(format!("no-warden-auth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("vault.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test','{\"authRequests\":[{\"id\":\"forged\"}]}','preserved',?1)",[now()]).unwrap();
        let before = serde_json::to_value(
            VaultService::new(&mut store)
                .list_auth_requests("alice", "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        assert!(before["data"].as_array().unwrap().is_empty());
        let registration = json!({"email":"new-auth@example.test","name":"fixture","key":CIPHERTEXT,"masterPasswordHash":"fixture-hash","_password":"prepared-fixture-verifier","authRequests":[{"id":"forged-registration-request"}],"devices":[{"identifier":"forged-registration-device"}]});
        let request = RegisterRequest::deserialize(&registration).unwrap();
        store.pending = registration.clone();
        Storage::insert_account(&mut store, "new-auth-account", &request).unwrap();
        let registered = serde_json::to_value(
            VaultService::new(&mut store)
                .list_auth_requests("new-auth-account", "https://origin.example.test")
                .unwrap(),
        )
        .unwrap();
        assert!(registered["data"].as_array().unwrap().is_empty());
        assert!(
            !DeviceStorage::known_device(
                &mut store,
                "new-auth@example.test",
                "forged-registration-device"
            )
            .unwrap()
        );
        VaultService::new(&mut store)
            .register_device(
                "alice",
                &DeviceRegistration {
                    identifier: "Request-Device",
                    name: "Original",
                    device_type: 8,
                },
            )
            .unwrap();
        let created =
            create_fixture_auth_request(&mut store, "alice@example.test", "Request-Device", 8)
                .unwrap();
        let records = auth_request_rows(&store);
        let authority = snapshot(&store);
        drop(store);
        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        assert!(auth_request_rows(&reopened) == records && snapshot(&reopened) == authority);
        let read = serde_json::to_value(
            VaultService::new(&mut reopened)
                .get_auth_request(
                    "alice",
                    created["id"].as_str().unwrap(),
                    "https://origin.example.test",
                )
                .unwrap(),
        )
        .unwrap();
        assert!(read["publicKey"] == created["publicKey"] && read["requestApproved"].is_null());
        let devices = serde_json::to_value(
            VaultService::new(&mut reopened)
                .list_devices("alice")
                .unwrap(),
        )
        .unwrap();
        assert!(devices["data"][0]["devicePendingAuthRequest"]["id"] == created["id"]);
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn device_push_rows(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT owner||':'||identifier||':'||token FROM device_push_tokens ORDER BY owner,identifier").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }
    fn set_fixture_push(
        store: &mut Store,
        owner: &str,
        identifier: &str,
        token: &str,
    ) -> Result<(), no_warden::ApiError> {
        VaultService::new(store).set_device_push_token(
            owner,
            identifier,
            &DevicePushTokenRequest { push_token: token },
        )
    }
    #[test]
    fn device_push_changes_only_token_and_activity_and_exact_repeat_performs_no_write() {
        let mut store = profile_fixture();
        for (owner, identifier) in [
            ("alice", "Shared-Device"),
            ("bob", "Shared-Device"),
            ("alice", "Other-Device"),
        ] {
            VaultService::new(&mut store)
                .register_device(
                    owner,
                    &DeviceRegistration {
                        identifier,
                        name: "Original",
                        device_type: 1,
                    },
                )
                .unwrap();
        }
        let before = snapshot(&store);
        let authority = account_authority_snapshot(&store);
        let initial = crate::devices::load(&store.db, "alice", "Shared-Device")
            .unwrap()
            .unwrap();
        let foreign = device_rows(&store)
            .into_iter()
            .filter(|row| !row.starts_with("alice:Shared-Device:"))
            .collect::<Vec<_>>();
        for token in ["", "opaque-raw-device-push-secret", "NUL\0café 雪\r\n"] {
            store.db.execute("UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z' WHERE owner='alice' AND identifier='Shared-Device'",[]).unwrap();
            set_fixture_push(&mut store, "alice", "Shared-Device", token).unwrap();
            assert!(
                crate::devices::push_token(&store.db, "alice", "Shared-Device")
                    .unwrap()
                    .as_deref()
                    == Some(token)
            );
            let state = device_rows(&store);
            let rows = device_push_rows(&store);
            let changes = store.db.total_changes();
            store.db.execute_batch("CREATE TRIGGER reject_repeated_push_insert BEFORE INSERT ON device_push_tokens BEGIN SELECT RAISE(ABORT,'repeated push insert'); END; CREATE TRIGGER reject_repeated_push_update BEFORE UPDATE ON device_push_tokens BEGIN SELECT RAISE(ABORT,'repeated push update'); END; CREATE TRIGGER reject_repeated_device_update BEFORE UPDATE ON device_registry BEGIN SELECT RAISE(ABORT,'repeated device activity'); END;").unwrap();
            set_fixture_push(&mut store, "alice", "Shared-Device", token).unwrap();
            assert_eq!(store.db.total_changes(), changes);
            assert!(device_rows(&store) == state && device_push_rows(&store) == rows);
            store.db.execute_batch("DROP TRIGGER reject_repeated_push_insert; DROP TRIGGER reject_repeated_push_update; DROP TRIGGER reject_repeated_device_update;").unwrap();
            let updated:String=store.db.query_row("SELECT updated FROM device_registry WHERE owner='alice' AND identifier='Shared-Device'",[],|row|row.get(0)).unwrap();
            assert!(updated != "2000-01-01T00:00:00.000000Z");
            let record = crate::devices::load(&store.db, "alice", "Shared-Device")
                .unwrap()
                .unwrap();
            assert!(
                record.name == initial.name
                    && record.device_type == initial.device_type
                    && record.created == initial.created
            );
            assert!(
                snapshot(&store) == before && account_authority_snapshot(&store) == authority,
                "Push token update changed account authority, revision or vault data."
            );
            assert!(
                device_rows(&store)
                    .into_iter()
                    .filter(|row| !row.starts_with("alice:Shared-Device:"))
                    .collect::<Vec<_>>()
                    == foreign
            );
        }
        let list =
            serde_json::to_value(VaultService::new(&mut store).list_devices("alice").unwrap())
                .unwrap();
        let single = serde_json::to_value(
            VaultService::new(&mut store)
                .get_device("alice", "Shared-Device")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list["data"][0].as_object().unwrap().len(), 10);
        assert_eq!(single.as_object().unwrap().len(), 7);
        assert!(
            !list.to_string().contains("raw-device-push-secret")
                && !single.to_string().contains("raw-device-push-secret")
        );
        let rows = device_push_rows(&store);
        assert!(set_fixture_push(&mut store, "bob", "Other-Device", "untrusted").is_err());
        assert!(set_fixture_push(&mut store, "missing", "Shared-Device", "untrusted").is_err());
        assert!(device_push_rows(&store) == rows);
    }

    #[test]
    fn device_push_storage_failures_roll_back_token_activity_and_unrelated_state() {
        for existing in [false, true] {
            for failure in ["token", "activity", "commit"] {
                let mut store = profile_fixture();
                VaultService::new(&mut store)
                    .register_device(
                        "alice",
                        &DeviceRegistration {
                            identifier: "Atomic-Device",
                            name: "Original",
                            device_type: 1,
                        },
                    )
                    .unwrap();
                if existing {
                    set_fixture_push(&mut store, "alice", "Atomic-Device", "original").unwrap();
                }
                let before = snapshot(&store);
                let authority = account_authority_snapshot(&store);
                let devices = device_rows(&store);
                let tokens = device_push_rows(&store);
                let trigger = match failure {
                    "token" => {
                        "CREATE TRIGGER reject_push_insert BEFORE INSERT ON device_push_tokens BEGIN SELECT RAISE(ABORT,'injected token write'); END;"
                    }
                    "activity" => {
                        "CREATE TRIGGER reject_push_activity BEFORE UPDATE OF updated ON device_registry BEGIN SELECT RAISE(ABORT,'injected activity write'); END;"
                    }
                    "commit" => {
                        "CREATE TABLE failed_push_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_push_commit AFTER UPDATE OF updated ON device_registry BEGIN INSERT INTO failed_push_commit(owner) VALUES('missing'); END;"
                    }
                    _ => unreachable!(),
                };
                store.db.execute_batch(trigger).unwrap();
                assert!(
                    set_fixture_push(&mut store, "alice", "Atomic-Device", "replacement").is_err()
                );
                assert!(
                    snapshot(&store) == before
                        && account_authority_snapshot(&store) == authority
                        && device_rows(&store) == devices
                        && device_push_rows(&store) == tokens,
                    "Failed push token save changed persisted state."
                );
                assert!(store.db.is_autocommit());
            }
        }
    }

    #[test]
    fn device_push_disabled_clear_skips_lookup_storage_and_relay_for_all_identifiers() {
        let mut store = setup();
        for owner in ["alice", "bob"] {
            VaultService::new(&mut store)
                .register_device(
                    owner,
                    &DeviceRegistration {
                        identifier: "Shared-Clear",
                        name: "Original",
                        device_type: 1,
                    },
                )
                .unwrap();
            set_fixture_push(&mut store, owner, "Shared-Clear", "preserved").unwrap();
        }
        let before = snapshot(&store);
        let devices = device_rows(&store);
        let tokens = device_push_rows(&store);
        let changes = store.db.total_changes();
        assert!(!DevicePushStorage::push_enabled(&store));
        for identifier in ["Shared-Clear", "Missing", "", "opaque-雪"] {
            VaultService::new(&mut store)
                .clear_device_push_token(identifier)
                .unwrap();
        }
        assert_eq!(store.db.total_changes(), changes);
        assert!(
            snapshot(&store) == before
                && device_rows(&store) == devices
                && device_push_rows(&store) == tokens
        );
    }

    #[test]
    fn device_push_tokens_survive_relogin_reopen_and_follow_composite_foreign_key_cleanup() {
        let directory =
            std::env::temp_dir().join(format!("no-warden-push-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("vault.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        for owner in ["alice", "bob"] {
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,'{}','preserved-verifier',?3)",params![owner,format!("{owner}@example.test"),now()]).unwrap();
            VaultService::new(&mut store)
                .register_device(
                    owner,
                    &DeviceRegistration {
                        identifier: "Restart-Device",
                        name: "Original",
                        device_type: 1,
                    },
                )
                .unwrap();
            set_fixture_push(
                &mut store,
                owner,
                "Restart-Device",
                if owner == "alice" {
                    "NUL\0persisted-雪"
                } else {
                    "foreign"
                },
            )
            .unwrap();
        }
        let before = device_push_rows(&store);
        let authority = snapshot(&store);
        drop(store);
        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        assert!(device_push_rows(&reopened) == before && snapshot(&reopened) == authority);
        VaultService::new(&mut reopened)
            .register_device(
                "alice",
                &DeviceRegistration {
                    identifier: "Restart-Device",
                    name: "Replacement",
                    device_type: 99,
                },
            )
            .unwrap();
        assert!(device_push_rows(&reopened) == before);
        assert!(
            crate::devices::load(&reopened.db, "alice", "Restart-Device")
                .unwrap()
                .unwrap()
                .name
                == "Original"
        );
        reopened
            .db
            .execute(
                "DELETE FROM device_registry WHERE owner='alice' AND identifier='Restart-Device'",
                [],
            )
            .unwrap();
        assert!(
            crate::devices::push_token(&reopened.db, "alice", "Restart-Device")
                .unwrap()
                .is_none()
        );
        assert!(
            crate::devices::push_token(&reopened.db, "bob", "Restart-Device")
                .unwrap()
                .as_deref()
                == Some("foreign")
        );
        assert!(snapshot(&reopened) == authority);
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn device_rows(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT owner||':'||identifier||':'||name||':'||device_type||':'||created||':'||updated FROM device_registry ORDER BY owner,identifier").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    #[test]
    fn device_registry_preserves_metadata_credentials_vault_revisions_and_foreign_state() {
        let mut store = profile_fixture();
        let before = snapshot(&store);
        let authority = account_authority_snapshot(&store);
        for owner in ["alice", "bob"] {
            let registration = DeviceRegistration {
                identifier: "Shared-Device",
                name: if owner == "alice" { "NUL\0雪" } else { "Bob" },
                device_type: if owner == "alice" { i32::MIN } else { i32::MAX },
            };
            VaultService::new(&mut store)
                .register_device(owner, &registration)
                .unwrap();
        }
        let original = crate::devices::load(&store.db, "alice", "Shared-Device")
            .unwrap()
            .unwrap();
        let foreign = device_rows(&store)
            .into_iter()
            .filter(|row| row.starts_with("bob:"))
            .collect::<Vec<_>>();
        store.db.execute("UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z' WHERE owner='alice'", []).unwrap();
        let changed = DeviceRegistration {
            identifier: "Shared-Device",
            name: "replacement",
            device_type: 14,
        };
        VaultService::new(&mut store)
            .register_device("alice", &changed)
            .unwrap();
        let retained = crate::devices::load(&store.db, "alice", "Shared-Device")
            .unwrap()
            .unwrap();
        assert!(
            retained.name == original.name
                && retained.device_type == original.device_type
                && retained.created == original.created
        );
        let updated: String = store
            .db
            .query_row(
                "SELECT updated FROM device_registry WHERE owner='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(updated != "2000-01-01T00:00:00.000000Z");
        assert!(chrono::DateTime::parse_from_rfc3339(&retained.created).is_ok());
        assert_eq!(retained.created.split('.').nth(1).unwrap().len(), 7);
        assert!(
            snapshot(&store) == before && account_authority_snapshot(&store) == authority,
            "Device registration changed account authority, revision or vault state."
        );
        assert!(
            device_rows(&store)
                .into_iter()
                .filter(|row| row.starts_with("bob:"))
                .collect::<Vec<_>>()
                == foreign
        );
        for (email, identifier, expected) in [
            ("ALICE@EXAMPLE.TEST", "Shared-Device", true),
            (" alice@example.test", "Shared-Device", false),
            ("alice@example.test ", "Shared-Device", false),
            ("alice@example.test", "shared-device", false),
            ("missing@example.test", "Shared-Device", false),
        ] {
            assert_eq!(
                DeviceStorage::known_device(&mut store, email, identifier).unwrap(),
                expected
            );
        }
        let single = serde_json::to_value(
            VaultService::new(&mut store)
                .get_device("alice", "Shared-Device")
                .unwrap(),
        )
        .unwrap();
        let list =
            serde_json::to_value(VaultService::new(&mut store).list_devices("alice").unwrap())
                .unwrap();
        assert_eq!(single.as_object().unwrap().len(), 7);
        assert_eq!(list["data"][0].as_object().unwrap().len(), 10);
        assert!(
            list["data"][0]["devicePendingAuthRequest"].is_null()
                && list["data"][0]["encryptedPublicKey"].is_null()
                && list["data"][0]["encryptedUserKey"].is_null()
        );
        assert!(
            single["name"] == "NUL\0雪"
                && single["type"] == i32::MIN
                && single["isTrusted"] == false
        );
        assert!(
            VaultService::new(&mut store)
                .get_device("bob", "missing")
                .is_err()
        );
    }

    #[test]
    fn device_registry_ignores_document_extensions_and_rolls_back_provider_failures() {
        for trigger in [
            "CREATE TRIGGER reject_device_write AFTER INSERT ON device_registry BEGIN UPDATE accounts SET revision='corrupt' WHERE id=NEW.owner; SELECT RAISE(FAIL,'injected registry failure'); END;",
            "CREATE TABLE failed_device_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_device_commit AFTER INSERT ON device_registry BEGIN INSERT INTO failed_device_commit(owner) VALUES('missing'); END;",
        ] {
            let mut store = setup();
            store.db.execute("UPDATE accounts SET document=json_set(document,'$.devices',json('[{\"identifier\":\"forged\"}]'),'$.deviceIdentifier','forged') WHERE id='alice'", []).unwrap();
            assert!(
                !DeviceStorage::known_device(&mut store, "alice@example.test", "forged").unwrap()
            );
            assert_eq!(
                DeviceStorage::devices(&mut store, "alice").unwrap().len(),
                0
            );
            let before = snapshot(&store);
            let authority = account_authority_snapshot(&store);
            store.db.execute_batch(trigger).unwrap();
            let registration = DeviceRegistration {
                identifier: "new-device",
                name: "fixture",
                device_type: 8,
            };
            assert!(
                VaultService::new(&mut store)
                    .register_device("alice", &registration)
                    .is_err()
            );
            assert!(
                device_rows(&store).is_empty()
                    && snapshot(&store) == before
                    && account_authority_snapshot(&store) == authority,
                "Failed device registration changed persisted state."
            );
            assert!(store.db.is_autocommit());
        }
        let mut store = setup();
        let registration = DeviceRegistration {
            identifier: "",
            name: "",
            device_type: 14,
        };
        VaultService::new(&mut store)
            .register_device("alice", &registration)
            .unwrap();
        assert!(DeviceStorage::known_device(&mut store, "alice@example.test", "").unwrap());
        assert!(
            VaultService::new(&mut store)
                .register_device("missing", &registration)
                .is_err()
        );
    }

    #[test]
    fn device_registry_and_session_bindings_survive_private_database_reopen() {
        let directory =
            std::env::temp_dir().join(format!("no-warden-devices-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("vault.db");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test','{}','preserved-verifier',?1)", [now()]).unwrap();
        let registration = DeviceRegistration {
            identifier: "Restart-Device",
            name: "Original",
            device_type: 8,
        };
        VaultService::new(&mut store)
            .register_device("alice", &registration)
            .unwrap();
        store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,'synthetic-refresh','alice',4000000000,4000000000)", [crate::digest("synthetic-access")]).unwrap();
        crate::devices::bind(&store.db, "alice", "Restart-Device", "synthetic-access").unwrap();
        let before = device_rows(&store);
        drop(store);
        let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
        assert!(device_rows(&reopened) == before);
        assert!(
            DeviceStorage::known_device(&mut reopened, "ALICE@EXAMPLE.TEST", "Restart-Device")
                .unwrap()
        );
        assert!(
            crate::devices::refresh_binding(&reopened.db, "synthetic-refresh", "alice")
                .unwrap()
                .as_deref()
                == Some("Restart-Device")
        );
        assert!(
            crate::devices::refresh_binding(&reopened.db, "synthetic-refresh", "bob")
                .unwrap()
                .is_none()
        );
        reopened.db.execute("DELETE FROM sessions", []).unwrap();
        assert!(
            crate::devices::refresh_binding(&reopened.db, "synthetic-refresh", "alice")
                .unwrap()
                .is_none()
        );
        assert_eq!(device_rows(&reopened).len(), 1);
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn domain_rows(store: &Store) -> Vec<(String, String, String)> {
        store.db.prepare("SELECT owner,excluded_globals,equivalent_domains FROM account_domains ORDER BY owner").unwrap()
            .query_map([],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    #[test]
    fn domain_defaults_ignore_untrusted_registration_and_legacy_account_extensions() {
        let mut store = setup();
        store.db.execute("UPDATE accounts SET document=json_set(document,'$.equivalentDomains',json('[\"untrusted\"]'),'$.excludedGlobalEquivalentDomains',json('[2]'),'$.domains',json('{\"untrusted\":true}')) WHERE id='alice'",[]).unwrap();
        let document = json!({"email":"new-domain@example.test","name":"fixture","key":CIPHERTEXT,"masterPasswordHash":"fixture-hash","_password":"prepared-fixture-verifier","equivalentDomains":[["untrusted"]],"excludedGlobalEquivalentDomains":[2],"domains":{"untrusted":true}});
        let request = RegisterRequest::deserialize(&document).unwrap();
        store.pending = document.clone();
        Storage::insert_account(&mut store, "new-domain-account", &request).unwrap();
        for owner in ["alice", "new-domain-account"] {
            let before = store.account("id", owner).unwrap().unwrap();
            let settings = DomainSettingsStorage::domain_settings(&mut store, owner).unwrap();
            assert!(settings.excluded_globals.is_empty());
            assert!(settings.equivalent_domains.is_empty());
            assert!(
                store.account("id", owner).unwrap().unwrap() == before,
                "Reading defaults changed stored account extensions."
            );
        }
        assert!(domain_rows(&store).is_empty());
        assert!(DomainSettingsStorage::domain_settings(&mut store, "missing").is_err());
    }

    #[test]
    fn domain_writes_preserve_both_arrays_authority_vault_and_foreign_state() {
        let mut store = profile_fixture();
        let foreign = crate::domains::Settings {
            excluded_globals: vec![3],
            equivalent_domains: vec![vec!["foreign".into()]],
        };
        VaultService::new(&mut store)
            .update_domain_settings("bob", &foreign)
            .unwrap();
        let authority = account_authority_snapshot(&store);
        let other = snapshot(&store)
            .into_iter()
            .filter(|row| !row.starts_with("account:alice:"))
            .collect::<Vec<_>>();
        let data = crate::domains::Settings {
            excluded_globals: vec![i32::MIN, 2, 2, i32::MAX],
            equivalent_domains: vec![
                vec![],
                vec![
                    "".into(),
                    "NUL\0café 🔐".into(),
                    "duplicate".into(),
                    "duplicate".into(),
                ],
            ],
        };
        let empty = crate::domains::Settings::default();
        for input in [&data, &data, &empty, &empty] {
            let mut expected = store.account("id", "alice").unwrap().unwrap();
            let previous: String = store
                .db
                .query_row(
                    "SELECT revision FROM accounts WHERE id='alice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let response = VaultService::new(&mut store)
                .update_domain_settings("alice", input)
                .unwrap();
            assert!(serde_json::to_value(response).unwrap() == json!({}));
            let revision: String = store
                .db
                .query_row(
                    "SELECT revision FROM accounts WHERE id='alice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                revision > previous,
                "Every successful domain write must advance the account revision."
            );
            expected["revisionDate"] = json!(revision);
            assert!(
                store.account("id", "alice").unwrap().unwrap() == expected,
                "Domain write changed unrelated account fields."
            );
            let saved = DomainSettingsStorage::domain_settings(&mut store, "alice").unwrap();
            assert!(saved.excluded_globals == input.excluded_globals);
            assert!(saved.equivalent_domains == input.equivalent_domains);
            let saved = DomainSettingsStorage::domain_settings(&mut store, "bob").unwrap();
            assert!(
                saved.excluded_globals == foreign.excluded_globals
                    && saved.equivalent_domains == foreign.equivalent_domains,
                "Domain write changed a foreign user's settings."
            );
            assert!(
                account_authority_snapshot(&store) == authority,
                "Domain write changed credentials, sessions, or attachment data."
            );
            assert!(
                snapshot(&store)
                    .into_iter()
                    .filter(|row| !row.starts_with("account:alice:"))
                    .collect::<Vec<_>>()
                    == other,
                "Domain write changed vault or foreign account state."
            );
        }
    }

    #[test]
    fn domain_insert_and_replacement_roll_back_write_revision_and_commit_failures() {
        for existing in [false, true] {
            for failure in ["write", "revision", "commit"] {
                let mut store = profile_fixture();
                if existing {
                    VaultService::new(&mut store)
                        .update_domain_settings(
                            "alice",
                            &crate::domains::Settings {
                                excluded_globals: vec![3],
                                equivalent_domains: vec![vec!["preserved".into()]],
                            },
                        )
                        .unwrap();
                }
                let before = snapshot(&store);
                let settings = domain_rows(&store);
                let authority = account_authority_snapshot(&store);
                let trigger = match failure {
                    "write" => {
                        "CREATE TRIGGER reject_domain_write BEFORE INSERT ON account_domains BEGIN SELECT RAISE(ABORT,'injected domain write failure'); END;"
                    }
                    "revision" => {
                        "CREATE TRIGGER reject_domain_revision BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'injected domain revision failure'); END;"
                    }
                    "commit" => {
                        "CREATE TABLE failed_domain_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_domain_commit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO failed_domain_commit(owner) VALUES('missing-owner'); END;"
                    }
                    _ => unreachable!(),
                };
                store.db.execute_batch(trigger).unwrap();
                let request = crate::domains::Settings {
                    excluded_globals: vec![2],
                    equivalent_domains: vec![vec!["replacement".into()]],
                };
                assert!(
                    VaultService::new(&mut store)
                        .update_domain_settings("alice", &request)
                        .is_err(),
                    "Injected {failure} failure must be reported."
                );
                assert!(
                    domain_rows(&store) == settings,
                    "Injected {failure} failure partially saved domain settings."
                );
                assert!(
                    snapshot(&store) == before,
                    "Injected {failure} failure changed account or vault state."
                );
                assert!(
                    account_authority_snapshot(&store) == authority,
                    "Injected {failure} failure changed existing authority."
                );
            }
        }
    }

    #[test]
    fn equivalent_domain_settings_survive_private_database_reopen() {
        let directory = std::env::temp_dir().join(format!(
            "no-warden-domain-persistence-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let database = directory.join("vault.db");
        let path = database.to_str().unwrap();
        let data = crate::domains::Settings {
            excluded_globals: vec![2, -1, 2],
            equivalent_domains: vec![vec![], vec!["".into(), "NUL\0café".into()]],
        };
        let account;
        {
            let mut store = Store::open(path).unwrap();
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test','{\"id\":\"alice\"}','test',?1)",[now()]).unwrap();
            VaultService::new(&mut store)
                .update_domain_settings("alice", &data)
                .unwrap();
            account = store.account("id", "alice").unwrap().unwrap();
        }
        {
            let mut store = Store::open(path).unwrap();
            assert!(store.account("id", "alice").unwrap().unwrap() == account);
            let saved = DomainSettingsStorage::domain_settings(&mut store, "alice").unwrap();
            assert!(saved.excluded_globals == data.excluded_globals);
            assert!(saved.equivalent_domains == data.equivalent_domains);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn profile_fixture() -> Store {
        let mut store = setup();
        save(&mut store, "alice", "profile-folder", "folder", None);
        save(
            &mut store,
            "alice",
            "profile-cipher",
            "cipher",
            Some("profile-folder"),
        );
        save(&mut store, "bob", "profile-foreign", "cipher", None);
        let mut account = store.account("id", "alice").unwrap().unwrap();
        account["name"] = json!("original name");
        account["avatarColor"] = json!("initial");
        account["key"] = json!("preserved-wrapped-key");
        account["keys"] =
            json!({"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"});
        account["userKeyId"] = json!("preserved-key-id");
        account["securityStamp"] = json!("preserved-stamp");
        account["futureField"] = json!({"nested":["preserved",null,7]});
        store
            .db
            .execute(
                "UPDATE accounts SET document=?1 WHERE id='alice'",
                [account.to_string()],
            )
            .unwrap();
        store.db.execute("INSERT INTO api_keys(owner,secret,verifier) VALUES('alice','preserved-secret','preserved-verifier')",[]).unwrap();
        store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES('profile-access','profile-refresh','alice',4000000000,4000000000)",[]).unwrap();
        let bytes: Vec<u8> = (0..=255).collect();
        store.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES('profile-attachment','profile-cipher',?1,?1,256,?2)",params![CIPHERTEXT,bytes]).unwrap();
        store.db.execute("INSERT INTO attachment_downloads(token,attachment_id,expires) VALUES('profile-capability','profile-attachment',4000000000)",[]).unwrap();
        store
    }

    fn mutate_profile(
        store: &mut Store,
        field: &str,
        value: Option<&str>,
    ) -> Result<(), no_warden::ApiError> {
        match field {
            "name" => VaultService::new(store).update_profile(
                "alice",
                &ProfileUpdateRequest {
                    name: value.expect("Name is required in this fixture."),
                },
            ),
            "avatarColor" => VaultService::new(store).update_avatar(
                "alice",
                &AvatarUpdateRequest {
                    avatar_color: value,
                },
            ),
            _ => unreachable!(),
        }
    }

    #[test]
    fn profile_mutations_preserve_unrelated_state_and_bump_revisions_for_repeated_values() {
        let mut store = profile_fixture();
        let authority = account_authority_snapshot(&store);
        let other = snapshot(&store)
            .into_iter()
            .filter(|row| !row.starts_with("account:alice:"))
            .collect::<Vec<_>>();
        let fifty_byte_name = "é".repeat(25);
        for (field, value) in [
            ("name", Some(fifty_byte_name.as_str())),
            ("name", Some(fifty_byte_name.as_str())),
            ("name", Some("")),
            ("name", Some("control\0\nname")),
            ("avatarColor", Some("éabcde")),
            ("avatarColor", Some("éabcde")),
            ("avatarColor", None),
            ("avatarColor", None),
        ] {
            let mut expected = store.account("id", "alice").unwrap().unwrap();
            let before: String = store
                .db
                .query_row(
                    "SELECT revision FROM accounts WHERE id='alice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            mutate_profile(&mut store, field, value).unwrap();
            let revision: String = store
                .db
                .query_row(
                    "SELECT revision FROM accounts WHERE id='alice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                revision > before,
                "Every successful profile write must advance the account revision."
            );
            expected[field] = json!(value);
            expected["revisionDate"] = json!(revision);
            assert!(
                store.account("id", "alice").unwrap().unwrap() == expected,
                "Profile write changed unrelated account fields."
            );
            assert!(
                account_authority_snapshot(&store) == authority,
                "Profile write changed credentials, sessions, or attachment data."
            );
            assert!(
                snapshot(&store)
                    .into_iter()
                    .filter(|row| !row.starts_with("account:alice:"))
                    .collect::<Vec<_>>()
                    == other,
                "Profile write changed vault or foreign account state."
            );
        }
        let before = snapshot(&store);
        let too_long = "é".repeat(26);
        for (field, value) in [
            ("name", Some(too_long.as_str())),
            ("avatarColor", Some("")),
            ("avatarColor", Some("🔐🔐")),
        ] {
            let error = mutate_profile(&mut store, field, value).unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert!(
                snapshot(&store) == before,
                "Invalid UTF-8 byte length changed persisted state."
            );
        }
    }

    #[test]
    fn profile_mutations_roll_back_document_revision_and_commit_failures() {
        for field in ["name", "avatarColor"] {
            for failure in ["document", "revision", "commit"] {
                let mut store = profile_fixture();
                let before = snapshot(&store);
                let authority = account_authority_snapshot(&store);
                let trigger = match failure {
                    "document" => {
                        "CREATE TRIGGER reject_profile_document BEFORE UPDATE OF document ON accounts BEGIN SELECT RAISE(ABORT,'injected profile document failure'); END;"
                    }
                    "revision" => {
                        "CREATE TRIGGER reject_profile_revision BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'injected profile revision failure'); END;"
                    }
                    "commit" => {
                        "CREATE TABLE failed_profile_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_profile_commit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO failed_profile_commit(owner) VALUES('missing-owner'); END;"
                    }
                    _ => unreachable!(),
                };
                store.db.execute_batch(trigger).unwrap();
                assert!(
                    mutate_profile(&mut store, field, Some("changed")).is_err(),
                    "Injected {failure} failure must be reported."
                );
                assert!(
                    snapshot(&store) == before,
                    "Injected {failure} failure partially committed profile metadata or revision."
                );
                assert!(
                    account_authority_snapshot(&store) == authority,
                    "Injected {failure} failure changed existing authority."
                );
            }
        }
    }

    #[test]
    fn registration_cannot_prefill_authoritative_avatar_metadata() {
        for supplied in [
            json!("#abcdef"),
            json!({"injected":true}),
            json!(7),
            Value::Null,
        ] {
            let mut store = setup();
            let document = json!({
                "email":"new@example.test","name":"initial name","key":CIPHERTEXT,
                "masterPasswordHash":"fixture-hash","_password":"prepared-fixture-verifier",
                "avatarColor":supplied,"futureRegistrationField":{"preserved":true},
            });
            let request = RegisterRequest::deserialize(&document).unwrap();
            store.pending = document.clone();
            Storage::insert_account(&mut store, "new-account", &request).unwrap();
            let saved = store.account("id", "new-account").unwrap().unwrap();
            assert!(saved["avatarColor"].is_null());
            assert!(crate::protocol::profile(&saved)["avatarColor"].is_null());
            assert!(saved["futureRegistrationField"] == document["futureRegistrationField"]);
            assert!(saved["name"] == document["name"]);
            assert!(saved.get("_password").is_none());
            assert!(saved.get("masterPasswordHash").is_none());
        }
    }

    #[test]
    fn profile_metadata_survives_private_database_reopen() {
        let directory = std::env::temp_dir().join(format!(
            "no-warden-profile-persistence-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let database = directory.join("vault.db");
        let path = database.to_str().unwrap();
        let expected;
        {
            let mut store = Store::open(path).unwrap();
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test','{\"id\":\"alice\",\"name\":\"initial\",\"avatarColor\":null,\"keys\":{\"publicKey\":\"preserved\",\"encryptedPrivateKey\":\"preserved\"}}','test',?1)",[now()]).unwrap();
            mutate_profile(&mut store, "name", Some("")).unwrap();
            mutate_profile(&mut store, "avatarColor", Some("éabcde")).unwrap();
            expected = store.account("id", "alice").unwrap().unwrap();
        }
        {
            let store = Store::open(path).unwrap();
            let saved = store.account("id", "alice").unwrap().unwrap();
            assert!(
                saved == expected,
                "Profile metadata changed across database reopen."
            );
            let profile = crate::protocol::profile(&saved);
            assert!(profile["name"] == "");
            assert!(profile["avatarColor"] == "éabcde");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn account_key_presence_distinguishes_absence_partial_pairs_and_present_empty_strings() {
        for (public, private) in [
            (None, None),
            (Some("public"), None),
            (None, Some("private")),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
            (Some("public"), Some("wrapped-private")),
        ] {
            let mut store = setup();
            store.db.execute("UPDATE accounts SET document=json_set(document,'$.key','','$.keys',json(?1)) WHERE id='alice'",
                [json!({"publicKey":public,"encryptedPrivateKey":private}).to_string()]).unwrap();
            let state = AccountKeyStorage::account_key_state(&mut store, "alice")
                .unwrap()
                .unwrap();
            assert!(state.key.is_empty());
            assert!(state.public_key == public);
            assert!(state.encrypted_private_key == private);
            let mut service = VaultService::new(&mut store);
            let result = service.get_account_keys("alice");
            if public.is_some() && private.is_some() {
                let response = result.unwrap();
                assert!(response.key.is_none());
                assert!(Some(response.public_key) == public);
                assert!(Some(response.private_key.expose_secret()) == private);
            } else {
                let Err(error) = result else {
                    panic!("Incomplete key pair was returned.");
                };
                assert_eq!(error.status_code(), 404);
            }
            assert!(AccountKeyStorage::user_public_key(&mut store, "alice").unwrap() == public);
            if public.is_some() || private.is_some() {
                let before = snapshot(&store);
                let request = AccountKeys {
                    encrypted_private_key: "replacement-private",
                    public_key: "replacement-public",
                };
                let result =
                    VaultService::new(&mut store).initialize_account_keys("alice", &request);
                let Err(error) = result else {
                    panic!("Existing or partial pair was replaced.");
                };
                assert_eq!(error.status_code(), 400);
                assert!(
                    AccountKeyStorage::initialize_account_keys(&mut store, "alice", &request)
                        .is_err()
                );
                assert!(
                    snapshot(&store) == before,
                    "Rejected initialization changed existing keys or state."
                );
            }
        }
        let mut store = setup();
        assert!(
            AccountKeyStorage::account_key_state(&mut store, "missing")
                .unwrap()
                .is_none()
        );
        assert!(
            AccountKeyStorage::user_public_key(&mut store, "missing")
                .unwrap()
                .is_none()
        );
        assert!(
            AccountKeyStorage::user_public_key(&mut store, "bob")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn account_key_initialization_changes_only_the_pair_and_owner_revision() {
        let mut store = setup();
        save(&mut store, "alice", "folder", "folder", None);
        save(&mut store, "alice", "cipher", "cipher", Some("folder"));
        save(&mut store, "bob", "foreign", "cipher", None);
        let mut document = store.account("id", "alice").unwrap().unwrap();
        document["key"] = json!("preserved-wrapped-user-key");
        document["userKeyId"] = json!("preserved-user-key-id");
        document["securityStamp"] = json!("preserved-security-stamp");
        document["futureAccountField"] = json!({"nested":["preserved",null,7]});
        document["keys"] = json!({"futureKeyMetadata":{"preserved":true}});
        store
            .db
            .execute(
                "UPDATE accounts SET document=?1 WHERE id='alice'",
                [document.to_string()],
            )
            .unwrap();
        store.db.execute("INSERT INTO api_keys(owner,secret,verifier) VALUES('alice','preserved-api-secret','preserved-api-verifier')",[]).unwrap();
        store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES('preserved-access','preserved-refresh','alice',4000000000,4000000000)",[]).unwrap();
        let bytes: Vec<u8> = (0..=255).collect();
        store.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES('preserved-attachment','cipher',?1,?1,256,?2)",params![CIPHERTEXT,bytes]).unwrap();
        store.db.execute("INSERT INTO attachment_downloads(token,attachment_id,expires) VALUES('preserved-capability','preserved-attachment',4000000000)",[]).unwrap();
        let authority = account_authority_snapshot(&store);
        let other_state = snapshot(&store)
            .into_iter()
            .filter(|row| !row.starts_with("account:alice:"))
            .collect::<Vec<_>>();
        let previous_revision: String = store
            .db
            .query_row(
                "SELECT revision FROM accounts WHERE id='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let request = AccountKeys {
            encrypted_private_key: "opaque private \" café 🔐",
            public_key: "",
        };
        let response = VaultService::new(&mut store)
            .initialize_account_keys("alice", &request)
            .unwrap();
        assert!(response.public_key.is_empty());
        assert!(response.private_key.expose_secret() == request.encrypted_private_key);
        let after = store.account("id", "alice").unwrap().unwrap();
        let revision: String = store
            .db
            .query_row(
                "SELECT revision FROM accounts WHERE id='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            revision > previous_revision,
            "Initialization must advance the account revision."
        );
        document["keys"]["publicKey"] = json!(request.public_key);
        document["keys"]["encryptedPrivateKey"] = json!(request.encrypted_private_key);
        document["revisionDate"] = json!(revision);
        assert!(
            after == document,
            "Initialization changed unrelated account fields."
        );
        assert!(
            account_authority_snapshot(&store) == authority,
            "Initialization changed credentials, sessions, or attachment data."
        );
        assert!(
            snapshot(&store)
                .into_iter()
                .filter(|row| !row.starts_with("account:alice:"))
                .collect::<Vec<_>>()
                == other_state,
            "Initialization changed vault or foreign account state."
        );
        let mut service = VaultService::new(&mut store);
        let get = service.get_account_keys("alice").unwrap();
        assert!(
            get.key
                .is_some_and(|key| key.expose_secret() == "preserved-wrapped-user-key")
        );
        assert!(get.public_key.is_empty());
        assert!(get.private_key.expose_secret() == request.encrypted_private_key);
    }

    #[test]
    fn account_key_initialization_rolls_back_document_revision_and_commit_failures() {
        for failure in ["document", "revision", "commit"] {
            let mut store = setup();
            store.db.execute("UPDATE accounts SET document=json_set(document,'$.key','preserved-user-key','$.keys',NULL) WHERE id='alice'",[]).unwrap();
            let before = snapshot(&store);
            let authority = account_authority_snapshot(&store);
            let trigger = match failure {
                "document" => {
                    "CREATE TRIGGER reject_pair_document BEFORE UPDATE OF document ON accounts BEGIN SELECT RAISE(ABORT,'injected pair document failure'); END;"
                }
                "revision" => {
                    "CREATE TRIGGER reject_pair_revision BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'injected pair revision failure'); END;"
                }
                "commit" => {
                    "CREATE TABLE failed_pair_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_pair_commit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO failed_pair_commit(owner) VALUES('missing-owner'); END;"
                }
                _ => unreachable!(),
            };
            store.db.execute_batch(trigger).unwrap();
            let request = AccountKeys {
                encrypted_private_key: "opaque-private",
                public_key: "opaque-public",
            };
            assert!(
                VaultService::new(&mut store)
                    .initialize_account_keys("alice", &request)
                    .is_err(),
                "Injected {failure} failure must be reported."
            );
            assert!(
                snapshot(&store) == before,
                "Injected {failure} failure partially committed keys or revision."
            );
            assert!(
                account_authority_snapshot(&store) == authority,
                "Injected {failure} failure changed authority."
            );
            let state = AccountKeyStorage::account_key_state(&mut store, "alice")
                .unwrap()
                .unwrap();
            assert!(state.public_key.is_none() && state.encrypted_private_key.is_none());
        }
    }

    #[test]
    fn present_empty_account_keys_survive_private_database_reopen() {
        let directory = std::env::temp_dir().join(format!(
            "no-warden-key-persistence-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let database = directory.join("vault.db");
        let path = database.to_str().unwrap();
        let revision;
        {
            let mut store = Store::open(path).unwrap();
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test','{\"id\":\"alice\",\"key\":\"\",\"keys\":null}','test',?1)",[now()]).unwrap();
            VaultService::new(&mut store)
                .initialize_account_keys(
                    "alice",
                    &AccountKeys {
                        encrypted_private_key: "",
                        public_key: "",
                    },
                )
                .unwrap();
            revision = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
        }
        {
            let mut store = Store::open(path).unwrap();
            assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] == revision);
            let mut service = VaultService::new(&mut store);
            let response = service.get_account_keys("alice").unwrap();
            assert!(response.key.is_none());
            assert!(response.public_key.is_empty());
            assert!(response.private_key.expose_secret().is_empty());
            assert!(AccountKeyStorage::user_public_key(&mut store, "alice").unwrap() == Some(""));
            assert!(
                VaultService::new(&mut store)
                    .initialize_account_keys(
                        "alice",
                        &AccountKeys {
                            encrypted_private_key: "replacement",
                            public_key: "replacement"
                        }
                    )
                    .is_err()
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

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

    fn account_authority_snapshot(store: &Store) -> Vec<String> {
        store.db.prepare(
            "SELECT 'password:'||id||':'||password FROM accounts
             UNION ALL SELECT 'session:'||access||':'||refresh||':'||owner||':'||access_expires||':'||refresh_expires FROM sessions
             UNION ALL SELECT 'api-key:'||owner||':'||secret||':'||verifier FROM api_keys
             UNION ALL SELECT 'attachment:'||id||':'||cipher_id||':'||file_name||':'||COALESCE(key,'null')||':'||size||':'||COALESCE(hex(data),'null') FROM attachments
             UNION ALL SELECT 'download:'||token||':'||attachment_id||':'||expires FROM attachment_downloads ORDER BY 1",
        ).unwrap().query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
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
    fn folder_deletion_preserves_cipher_metadata_archives_and_attachment_bytes() {
        let mut store = setup();
        save(&mut store, "alice", "folder", "folder", None);
        save(&mut store, "bob", "bob-folder", "folder", None);
        for (owner, id, folder, trashed) in [
            ("alice", "active", Some("folder"), false),
            ("alice", "trashed", Some("folder"), true),
            ("alice", "loose", None, false),
            ("bob", "foreign", Some("bob-folder"), false),
        ] {
            store.pending = json!({
                "type": 1, "name": CIPHERTEXT, "notes": CIPHERTEXT,
                "folderId": folder, "favorite": true,
                "login": {"username": CIPHERTEXT, "password": CIPHERTEXT},
                "fields": [{"name": CIPHERTEXT, "value": CIPHERTEXT, "type": 0}],
                "updated": "2026-01-02T03:04:05.123456Z",
                "futureClientField": {"nested": [CIPHERTEXT, null, 7]},
                "archivedDate": "2026-01-03T04:05:06.123456Z",
            });
            store.save(owner, id, "cipher").unwrap();
            if trashed {
                store.set_cipher_deleted(owner, id, true).unwrap();
            }
            let bytes: Vec<u8> = (0..=255).collect();
            store.db.execute(
                "INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,?3,?3,?4,?5)",
                params![format!("attachment-{id}"), id, CIPHERTEXT, bytes.len(), bytes],
            ).unwrap();
            store.db.execute(
                "INSERT INTO attachment_downloads(token,attachment_id,expires) VALUES(?1,?2,?3)",
                params![format!("fixture-token-{id}"), format!("attachment-{id}"), 4_000_000_000_i64],
            ).unwrap();
        }
        let records = |store: &Store| {
            store.db.prepare("SELECT id,owner,document,deleted,revision,created FROM items WHERE kind='cipher' ORDER BY id")
                .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, bool>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        let attachments = |store: &Store| {
            store
                .db
                .prepare("SELECT id,cipher_id,file_name,key,size,data FROM attachments ORDER BY id")
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let mut expected = records(&store);
        for (id, owner, document, _, _, _) in &mut expected {
            if owner == "alice" && matches!(id.as_str(), "active" | "trashed") {
                let mut value: Value = serde_json::from_str(document).unwrap();
                value["folderId"] = Value::Null;
                *document = value.to_string();
            }
        }
        let original_attachments = attachments(&store);
        let original_annotations = snapshot(&store)
            .into_iter()
            .filter(|row| row.starts_with("archive:"))
            .collect::<Vec<_>>();
        let original_downloads = store
            .db
            .prepare("SELECT token,attachment_id,expires FROM attachment_downloads ORDER BY token")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let alice_before = store.account("id", "alice").unwrap().unwrap();
        let foreign_before = snapshot(&store)
            .into_iter()
            .filter(|row| {
                row.starts_with("account:bob:")
                    || row.starts_with("item:bob-folder:")
                    || row.starts_with("item:foreign:")
            })
            .collect::<Vec<_>>();

        store.delete_folder("alice", "folder").unwrap();

        assert!(store.item("alice", "folder", "folder").unwrap().is_none());
        assert!(
            records(&store) == expected,
            "Folder deletion changed cipher data beyond its folder association."
        );
        assert!(
            attachments(&store) == original_attachments,
            "Folder deletion changed attachment metadata or encrypted bytes."
        );
        assert_eq!(
            snapshot(&store)
                .into_iter()
                .filter(|row| row.starts_with("archive:"))
                .collect::<Vec<_>>(),
            original_annotations
        );
        let downloads = store
            .db
            .prepare("SELECT token,attachment_id,expires FROM attachment_downloads ORDER BY token")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            downloads == original_downloads,
            "Folder deletion changed existing attachment download grants."
        );
        assert_eq!(
            snapshot(&store)
                .into_iter()
                .filter(|row| row.starts_with("account:bob:")
                    || row.starts_with("item:bob-folder:")
                    || row.starts_with("item:foreign:"))
                .collect::<Vec<_>>(),
            foreign_before
        );
        let alice_after = store.account("id", "alice").unwrap().unwrap();
        assert_ne!(alice_after["revisionDate"], alice_before["revisionDate"]);
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
        assert_eq!(remaining["revisionDate"], original["revisionDate"]);
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
