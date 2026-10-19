//! Opaque attachment bytes and capability URLs for the local conformance adapter.
//! Transport parsing, randomness, clocks and storage remain outside the core.
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use no_warden::{
    attachment::{AttachmentAction, AttachmentMetadata, AttachmentStorage, ValidatedAttachment},
    identity::Secret,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::Value;

use crate::{Failure, digest, invalid, missing, random_token};

pub(crate) fn new_id() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl AttachmentStorage for crate::store::Store {
    fn attachment_metadata(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<AttachmentMetadata<'_>>> {
        self.attachment_metadata_cache = load(&self.db, id)?;
        Ok(self
            .attachment_metadata_cache
            .as_ref()
            .map(|record| AttachmentMetadata {
                cipher_id: &record.cipher_id,
                file_size: record.size as u64,
            }))
    }

    fn commit_attachment(
        &mut self,
        owner: &str,
        plan: &ValidatedAttachment<'_>,
    ) -> rusqlite::Result<()> {
        let bytes = std::mem::take(&mut self.pending_attachment_data);
        let tx = self.db.transaction()?;
        let require = |changed| {
            if changed == 1 {
                Ok(())
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows)
            }
        };
        match plan.action() {
            AttachmentAction::Reserve
            | AttachmentAction::Legacy
            | AttachmentAction::ReplaceLegacy => {
                if let Some(replaced) = plan.replaced_attachment_id() {
                    require(tx.execute(
                        "DELETE FROM attachments WHERE id=lower(?1) AND cipher_id=?2",
                        params![replaced, plan.cipher_id()],
                    )?)?;
                }
                let write = plan.write().ok_or(rusqlite::Error::InvalidQuery)?;
                let size =
                    i64::try_from(write.file_size).map_err(|_| rusqlite::Error::InvalidQuery)?;
                let data = if plan.action() == AttachmentAction::Reserve {
                    None
                } else {
                    Some(bytes.as_slice())
                };
                if data.is_some_and(|bytes| bytes.len() as u64 != write.file_size) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                tx.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![plan.attachment_id(), plan.cipher_id(), write.file_name, write.key, size, data])?;
            }
            AttachmentAction::Upload => {
                let write = plan.write().ok_or(rusqlite::Error::InvalidQuery)?;
                let size =
                    i64::try_from(write.file_size).map_err(|_| rusqlite::Error::InvalidQuery)?;
                if bytes.len() as u64 != write.file_size {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                require(tx.execute(
                    "UPDATE attachments SET data=?1,size=?2 WHERE id=lower(?3) AND cipher_id=?4",
                    params![bytes, size, plan.attachment_id(), plan.cipher_id()],
                )?)?;
            }
            AttachmentAction::Delete | AttachmentAction::DiscardMismatch => {
                require(tx.execute(
                    "DELETE FROM attachments WHERE id=lower(?1) AND cipher_id=?2",
                    params![plan.attachment_id(), plan.cipher_id()],
                )?)?;
            }
            AttachmentAction::UpdateMetadata => {
                let write = plan.write().ok_or(rusqlite::Error::InvalidQuery)?;
                require(tx.execute("UPDATE attachments SET file_name=?1,key=?2 WHERE id=lower(?3) AND cipher_id=?4",
                    params![write.file_name, write.key, plan.attachment_id(), plan.cipher_id()])?)?;
            }
        }
        if matches!(
            plan.action(),
            AttachmentAction::Upload
                | AttachmentAction::Legacy
                | AttachmentAction::ReplaceLegacy
                | AttachmentAction::Delete
        ) {
            let revision = crate::store::next_revision(&tx, owner)?;
            crate::store::bump(&tx, owner, &revision)?;
        }
        tx.commit()
    }

    fn verify_attachment_download(
        &mut self,
        cipher_id: &str,
        attachment_id: &str,
        token: &Secret<'_>,
    ) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM attachment_downloads d JOIN attachments a ON a.id=d.attachment_id
             WHERE d.token=?1 AND d.expires>?2 AND a.id=?3 AND a.cipher_id=?4 AND a.data IS NOT NULL)",
            params![digest(token.expose_secret()), chrono::Utc::now().timestamp(), attachment_id, cipher_id],
            |row| row.get(0),
        )
    }
}

pub(crate) struct Upload {
    pub key: Option<String>,
    pub file_name: Option<String>,
    pub data: Vec<u8>,
}

pub(crate) async fn parse_upload(headers: &HeaderMap, body: Bytes) -> Result<Upload, Failure> {
    let mut request = Request::new(Body::from(body));
    *request.headers_mut() = headers.clone();
    DefaultBodyLimit::max(crate::MAX_REQUEST_BYTES).apply(&mut request);
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|_| invalid())?;
    let mut key = None;
    let mut file_name = None;
    let mut data = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| invalid())? {
        match field.name() {
            Some("data") if data.is_none() => {
                file_name = field.file_name().map(str::to_owned);
                data = Some(field.bytes().await.map_err(|_| invalid())?.to_vec());
            }
            Some("key") if key.is_none() => {
                key = Some(field.text().await.map_err(|_| invalid())?);
            }
            _ => return Err(invalid()),
        }
    }
    Ok(Upload {
        key,
        file_name,
        data: data.ok_or_else(invalid)?,
    })
}

pub(crate) struct Record {
    pub id: String,
    pub cipher_id: String,
    pub file_name: String,
    pub key: Option<String>,
    pub size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rewrap<'a> {
    file_name: &'a str,
    key: &'a str,
}

pub(crate) fn validate_rewrap(document: &Value) -> Result<(), Failure> {
    if let Some(value) = document
        .get("attachments2")
        .filter(|value| !value.is_null())
    {
        let entries = value.as_object().ok_or_else(invalid)?;
        for value in entries.values() {
            Rewrap::deserialize(value).map_err(|_| invalid())?;
        }
    }
    Ok(())
}

// Called inside the cipher provider's transaction, after the service authorized
// the owner. Match upstream's missing-entry skip and foreign-cipher stop rules.
pub(crate) fn rewrap(db: &Connection, cipher_id: &str, document: &Value) -> rusqlite::Result<()> {
    if let Some(entries) = document.get("attachments2").and_then(Value::as_object) {
        for (id, value) in entries {
            let Some(record) = load(db, id)? else {
                continue;
            };
            if record.cipher_id != cipher_id {
                break;
            }
            let update = Rewrap::deserialize(value).map_err(|_| rusqlite::Error::InvalidQuery)?;
            db.execute(
                "UPDATE attachments SET file_name=?1,key=?2 WHERE id=lower(?3) AND cipher_id=?4",
                params![update.file_name, update.key, id, cipher_id],
            )?;
        }
    }
    Ok(())
}

fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        cipher_id: row.get(1)?,
        file_name: row.get(2)?,
        key: row.get(3)?,
        size: row.get(4)?,
    })
}

pub(crate) fn load(db: &Connection, id: &str) -> rusqlite::Result<Option<Record>> {
    db.query_row(
        "SELECT id,cipher_id,file_name,key,size FROM attachments WHERE id=lower(?1)",
        [id],
        record,
    )
    .optional()
}

pub(crate) fn display_size(size: i64) -> String {
    let units = ["bytes", "KB", "MB", "GB", "TB", "PB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value > 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", units[unit])
}

pub(crate) fn wire(db: &Connection, base: &str, record: &Record) -> rusqlite::Result<Value> {
    let now = chrono::Utc::now().timestamp();
    db.execute("DELETE FROM attachment_downloads WHERE expires<=?1", [now])?;
    let token = random_token();
    db.execute(
        "INSERT INTO attachment_downloads(token,attachment_id,expires) VALUES(?1,?2,?3)",
        params![digest(&token), record.id, now + 60],
    )?;
    let url = format!(
        "{base}/attachments/{}/{}?token={token}",
        record.cipher_id, record.id
    );
    let size = record.size.to_string();
    let size_name = display_size(record.size);
    serde_json::to_value(no_warden::wire::AttachmentResponse {
        id: &record.id,
        url: Secret::new(&url),
        file_name: &record.file_name,
        key: record.key.as_deref(),
        size: &size,
        size_name: &size_name,
    })
    .map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn enrich_cipher(
    db: &Connection,
    base: &str,
    document: &mut Value,
) -> rusqlite::Result<()> {
    let id = document["id"]
        .as_str()
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let records = db.prepare(
        "SELECT id,cipher_id,file_name,key,size FROM attachments WHERE cipher_id=?1 ORDER BY rowid",
    )?
    .query_map([id], record)?
    .collect::<rusqlite::Result<Vec<_>>>()?;
    document["attachments"] = if records.is_empty() {
        Value::Null
    } else {
        Value::Array(
            records
                .iter()
                .map(|record| wire(db, base, record))
                .collect::<rusqlite::Result<_>>()?,
        )
    };
    Ok(())
}

pub(crate) fn download(
    store: &mut crate::store::Store,
    cipher_id: &str,
    attachment_id: &str,
    query: Option<&str>,
) -> Result<Response, Failure> {
    let query: Vec<(String, String)> =
        serde_urlencoded::from_str(query.unwrap_or_default()).map_err(|_| missing())?;
    let mut tokens = query.iter().filter(|(key, _)| key == "token");
    let token = tokens.next().map(|(_, value)| value).ok_or(Failure(
        StatusCode::UNPROCESSABLE_ENTITY,
        "A download token is required",
    ))?;
    if tokens.next().is_some() {
        return Err(missing());
    }
    let grant = no_warden::VaultService::new(&mut *store).authorize_attachment_download(
        cipher_id,
        attachment_id,
        &Secret::new(token),
    )?;
    let bytes: Option<Vec<u8>> = store
        .db
        .query_row(
            "SELECT data FROM attachments WHERE id=?1 AND cipher_id=?2 AND data IS NOT NULL",
            params![grant.attachment_id(), grant.cipher_id()],
            |row| row.get(0),
        )
        .optional()?;
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        bytes.ok_or_else(missing)?,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use no_warden::{VaultService, wire::AttachmentRequest};

    fn fixture() -> crate::store::Store {
        let store = crate::store::Store::open(":memory:").unwrap();
        for owner in ["alice", "bob"] {
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?1,'{}','test','2026-01-01T00:00:00.000Z')", [owner]).unwrap();
        }
        for (id, owner) in [("cipher", "alice"), ("other", "bob")] {
            store.db.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher',?3,0,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
                params![id, owner, serde_json::json!({"id":id,"revisionDate":"2026-01-01T00:00:00.000Z"}).to_string()]).unwrap();
        }
        store
    }

    fn revision(store: &crate::store::Store) -> String {
        store
            .db
            .query_row(
                "SELECT revision FROM accounts WHERE id='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn reserve(store: &mut crate::store::Store, id: &str, size: i64) {
        VaultService::new(store)
            .reserve_attachment(
                "alice",
                "cipher",
                id,
                &AttachmentRequest {
                    key: "opaque-key",
                    file_name: "opaque-name",
                    file_size: size,
                    admin_request: None,
                },
            )
            .unwrap();
    }

    fn upload(
        store: &mut crate::store::Store,
        id: &str,
        bytes: &[u8],
    ) -> Result<(), no_warden::ApiError> {
        store.pending_attachment_data = bytes.to_vec();
        VaultService::new(store).upload_attachment("alice", "cipher", id, bytes.len() as u64)
    }

    #[test]
    fn attachment_bytes_revisions_and_cipher_cleanup_are_authoritative() {
        let mut store = fixture();
        let before = revision(&store);
        reserve(&mut store, "attachment", 0);
        assert_eq!(revision(&store), before);
        assert!(load(&store.db, "attachment").unwrap().is_some());
        let bytes = [0, 255, 128, 13, 10];
        upload(&mut store, "attachment", &bytes).unwrap();
        assert!(revision(&store) != before);
        let record = load(&store.db, "attachment").unwrap().unwrap();
        assert_eq!(record.size, bytes.len() as i64);
        let cipher = store.item("alice", "cipher", "cipher").unwrap().unwrap();
        assert_eq!(cipher["revisionDate"], "2026-01-01T00:00:00.000Z");
        assert_eq!(cipher["attachments"].as_array().unwrap().len(), 1);
        let data: Vec<u8> = store
            .db
            .query_row(
                "SELECT data FROM attachments WHERE id='attachment'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(data == bytes);
        no_warden::Storage::delete_cipher(&mut store, "alice", "cipher").unwrap();
        assert!(load(&store.db, "attachment").unwrap().is_none());
        let capabilities: u64 = store
            .db
            .query_row("SELECT COUNT(*) FROM attachment_downloads", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(capabilities, 0);
    }

    #[test]
    fn mismatch_discards_only_the_authorized_slot_without_revision_change() {
        let mut store = fixture();
        reserve(&mut store, "attachment", 2 * 1024 * 1024);
        let before = revision(&store);
        assert!(
            VaultService::new(&mut store)
                .upload_attachment("bob", "other", "attachment", 0)
                .is_err()
        );
        assert!(load(&store.db, "attachment").unwrap().is_some());
        let error = upload(&mut store, "attachment", &[]).unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert!(load(&store.db, "attachment").unwrap().is_none());
        assert_eq!(revision(&store), before);
    }

    #[test]
    fn capability_checks_scope_expiry_and_deletion_without_a_bearer() {
        let mut store = fixture();
        reserve(&mut store, "attachment", 3);
        upload(&mut store, "attachment", &[0, 255, 1]).unwrap();
        assert_eq!(
            download(&mut store, "cipher", "attachment", None)
                .err()
                .unwrap()
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            download(&mut store, "cipher", "attachment", Some("token=forged"))
                .err()
                .unwrap()
                .0,
            StatusCode::NOT_FOUND
        );
        let record = load(&store.db, "attachment").unwrap().unwrap();
        let metadata = wire(&store.db, "http://localhost", &record).unwrap();
        let url = metadata["url"].as_str().unwrap();
        let token = url.split_once("?token=").unwrap().1;
        let authorized = |store: &mut crate::store::Store, cipher, id, token| {
            VaultService::new(store)
                .authorize_attachment_download(cipher, id, &Secret::new(token))
                .is_ok()
        };
        assert!(authorized(&mut store, "cipher", "attachment", token));
        assert!(!authorized(&mut store, "other", "attachment", token));
        assert!(!authorized(&mut store, "cipher", "other", token));
        assert!(!authorized(&mut store, "cipher", "attachment", "forged"));
        store
            .db
            .execute("UPDATE attachment_downloads SET expires=0", [])
            .unwrap();
        assert!(!authorized(&mut store, "cipher", "attachment", token));
        let metadata = wire(&store.db, "http://localhost", &record).unwrap();
        let token = metadata["url"]
            .as_str()
            .unwrap()
            .split_once("?token=")
            .unwrap()
            .1;
        VaultService::new(&mut store)
            .delete_attachment("alice", "cipher", "attachment")
            .unwrap();
        assert!(!authorized(&mut store, "cipher", "attachment", token));
    }

    #[test]
    fn failed_revision_writes_roll_back_upload_delete_and_legacy_replacement() {
        let mut store = fixture();
        reserve(&mut store, "attachment", 3);
        upload(&mut store, "attachment", &[0, 1, 2]).unwrap();
        let before = revision(&store);
        store.db.execute_batch("CREATE TRIGGER fail_attachment_revision BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(upload(&mut store, "attachment", &[3, 4, 5]).is_err());
        assert!(
            VaultService::new(&mut store)
                .delete_attachment("alice", "cipher", "attachment")
                .is_err()
        );
        store.pending_attachment_data = vec![9];
        assert!(
            VaultService::new(&mut store)
                .replace_legacy_attachment(
                    "alice",
                    "cipher",
                    "attachment",
                    "replacement",
                    &no_warden::wire::LegacyAttachmentRequest {
                        file_name: Some("new-name"),
                        key: Some("new-key"),
                        file_size: 1,
                    }
                )
                .is_err()
        );
        assert!(load(&store.db, "replacement").unwrap().is_none());
        assert_eq!(revision(&store), before);
        let bytes: Vec<u8> = store
            .db
            .query_row(
                "SELECT data FROM attachments WHERE id='attachment'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(bytes == [0, 1, 2]);
    }

    #[test]
    fn attachment_sizes_use_upstream_boundary_formatting() {
        assert_eq!(display_size(0), "0.00 bytes");
        assert_eq!(display_size(1024), "1024.00 bytes");
        assert_eq!(display_size(1025), "1.00 KB");
        assert_eq!(display_size(1024 * 1024), "1024.00 KB");
    }
}
