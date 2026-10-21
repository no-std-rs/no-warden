//! Opt-in shared attachment reservation, byte upload and deletion.
//! Core attachment plans and WRITE decisions remain allocation free; this host
//! owns opaque bytes, resource policy, transactions and current-reader fanout.
use crate::{
    Failure, Store, attachments, organization_attachment_read as reads,
    organization_cipher_archive as archive, organization_cipher_sharing as sharing, store,
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    ApiError, Storage, VaultService,
    attachment::{AttachmentAction, AttachmentMetadata, AttachmentStorage, ValidatedAttachment},
    bulk::CipherAccess,
    identity::Secret,
    organization_cipher_bulk_sharing::resolve_bulk_cipher_source_write_access,
    organization_cipher_sharing::{CipherSharingMembership, CipherSharingSource},
    service::ItemMetadata,
    wire::{AttachmentRequest, CipherRequest, FolderRequest, RegisterRequest},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

// Local adapter policy, not a native capacity or a limit of the core service.
const MAX_ROWS: usize = 4096;
const MAX_MATERIAL: usize = 8 * 1024 * 1024;
const BUSINESS_ERROR: &str = "Shared attachment operation unavailable";

const JSON_SYNTAX_ERROR: &str = "Invalid attachment JSON syntax";

pub fn error_scope(method: &axum::http::Method, path: &str) -> bool {
    no_warden::route::Method::parse(method.as_str())
        .and_then(|method| no_warden::route::classify(method, path))
        .is_some_and(|route| {
            matches!(
                route,
                no_warden::route::Route::AttachmentReserve(_)
                    | no_warden::route::Route::AttachmentUpload(..)
                    | no_warden::route::Route::AttachmentDelete(..)
            )
        })
}

pub fn render_error(error: Failure) -> Response {
    if matches!(
        error.0,
        StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY
    ) || error.1 == JSON_SYNTAX_ERROR
    {
        // Only the measured outer key and its object type are asserted. Do not
        // serialize request fragments or opaque encrypted fields in errors.
        return (
            error.0,
            Json(json!({"error":{"message":"Invalid request"}})),
        )
            .into_response();
    }
    if error.0 == StatusCode::BAD_REQUEST {
        return crate::password_login::error_response(error.0, error.1);
    }
    error.into_response()
}

pub fn json_syntax_error(_: serde_json::Error) -> Failure {
    Failure(StatusCode::BAD_REQUEST, JSON_SYNTAX_ERROR)
}

/// The pinned native version has no GET metadata/admin handler. Preserve its
/// measured one-field 404 envelope without classifying the request as a read.
pub fn unsupported_admin_read(method: &axum::http::Method, path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    method == axum::http::Method::GET
        && path.ends_with("/admin")
        && matches!(
            no_warden::route::classify(no_warden::route::Method::Delete, path),
            Some(no_warden::route::Route::AttachmentDelete(..))
        )
}
fn business() -> Failure {
    Failure(StatusCode::BAD_REQUEST, BUSINESS_ERROR)
}
fn core_error(error: ApiError) -> Failure {
    if error.status_code() == 400 {
        business()
    } else {
        error.into()
    }
}

/// This routing test confers no authority. The separate provider rechecks source
/// ownership and current core WRITE authority before every durable operation.
pub fn shared(db: &Connection, cipher: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM items WHERE id=?1 AND kind='cipher' AND organization_id IS NOT NULL)",
        [cipher],
        |r| r.get(0),
    )
}

// Return both existing row count and total charged UTF-8 material so a new
// reservation cannot exceed the local policy after passing a pre-write check.
fn material(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<(usize, usize)> {
    let base = archive::material(db, actor, cipher)?.ok_or(rusqlite::Error::InvalidQuery)?;
    let (count, attachments): (usize, usize) = db.query_row(
        "SELECT count(*),coalesce(sum(128+length(CAST(id AS BLOB))+length(CAST(cipher_id AS BLOB))+length(CAST(file_name AS BLOB))+coalesce(length(CAST(key AS BLOB)),0)),0) FROM (SELECT id,cipher_id,file_name,key FROM attachments WHERE cipher_id=?1 LIMIT ?2)",
        params![cipher, MAX_ROWS + 1],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (readers, reader_bytes): (usize, usize) = db.query_row(
        "SELECT count(*),coalesce(sum(128+length(CAST(user_id AS BLOB))),0) FROM (SELECT m.user_id FROM organization_memberships m JOIN items i ON i.organization_id=m.organization_id WHERE i.id=?1 AND i.kind='cipher' AND m.status=2 LIMIT ?2)",
        params![cipher, MAX_ROWS + 1],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let total = base
        .checked_add(attachments)
        .and_then(|total| total.checked_add(reader_bytes))
        .ok_or(rusqlite::Error::InvalidQuery)?;
    if count > MAX_ROWS || readers > MAX_ROWS || total > MAX_MATERIAL {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok((count, total))
}

fn access(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<Option<CipherAccess>> {
    let Some(read) = reads::access(db, actor, cipher)? else {
        return Ok(None);
    };
    if !read.readable {
        return Ok(Some(read));
    }
    // READ's negative candidate filter runs before any owned source/fact loading.
    material(db, actor, cipher)?;
    let source = sharing::source(db, cipher)?.ok_or(rusqlite::Error::InvalidQuery)?;
    let member = source
        .organization_id
        .as_deref()
        .map(|org| sharing::membership(db, actor, org))
        .transpose()?
        .flatten();
    let facts = archive::facts(db, actor, &source)?;
    let writable = resolve_bulk_cipher_source_write_access(
        actor,
        source
            .ownership()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        member.as_ref().map(CipherSharingMembership::view),
        &facts,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Some(CipherAccess {
        readable: read.readable,
        writable,
    }))
}

fn project(store: &Store, actor: &str, cipher: &str) -> Result<Value, Failure> {
    let mut response = archive::project(&store.db, actor, cipher)?;
    attachments::enrich_cipher(&store.db, &store.download_base, &mut response)?;
    Ok(response)
}

pub fn reserve(
    store: &mut Store,
    actor: &str,
    cipher: &str,
    request: &AttachmentRequest<'_>,
) -> Result<Response, Failure> {
    let id = attachments::new_id();
    let provider = Provider::new(store, actor, cipher, Vec::new())?;
    VaultService::new(provider)
        .reserve_attachment(actor, cipher, &id, request)
        .map_err(core_error)?;
    let response = no_warden::wire::AttachmentUploadResponse::direct(
        &id,
        Secret::new(""),
        project(store, actor, cipher)?,
        request.admin_request.unwrap_or(false),
    );
    // Keep the URL in adapter-owned storage until response serialization.
    let url = format!("/ciphers/{cipher}/attachment/{id}");
    let mut response = serde_json::to_value(response).map_err(|_| crate::invalid())?;
    response["url"] = json!(url);
    Ok(crate::json_response(response))
}

pub fn upload(
    store: &mut Store,
    actor: &str,
    cipher: &str,
    attachment: &str,
    bytes: Vec<u8>,
) -> Result<Response, Failure> {
    let size = bytes.len() as u64;
    let provider = Provider::new(store, actor, cipher, bytes)?;
    VaultService::new(provider)
        .upload_attachment(actor, cipher, attachment, size)
        .map_err(core_error)?;
    Ok(StatusCode::OK.into_response())
}

pub fn delete(
    store: &mut Store,
    actor: &str,
    cipher: &str,
    attachment: &str,
) -> Result<Response, Failure> {
    let provider = Provider::new(store, actor, cipher, Vec::new())?;
    VaultService::new(provider)
        .delete_attachment(actor, cipher, attachment)
        .map_err(core_error)?;
    Ok(Json(json!({"cipher":project(store,actor,cipher)?})).into_response())
}

struct Provider<'a> {
    store: &'a mut Store,
    actor: String,
    source: CipherSharingSource<String>,
    metadata: Option<(String, u64)>,
    expected_file: Option<attachments::Record>,
    bytes: Vec<u8>,
}
impl<'a> Provider<'a> {
    fn new(
        store: &'a mut Store,
        actor: &str,
        cipher: &str,
        bytes: Vec<u8>,
    ) -> Result<Self, Failure> {
        if !access(&store.db, actor, cipher)?.is_some_and(|a| a.readable && a.writable) {
            return Err(business());
        }
        let source = sharing::source(&store.db, cipher)?.ok_or_else(business)?;
        if source.organization_id.is_none() || source.owner_id.is_some() {
            return Err(business());
        }
        Ok(Self {
            store,
            actor: actor.to_owned(),
            source,
            metadata: None,
            expected_file: None,
            bytes,
        })
    }
}

// Unrelated base-storage operations retain the existing adapter implementation.
// Only this private wrapper opts the measured three shared attachment actions in.
impl Storage for Provider<'_> {
    type Error = rusqlite::Error;
    fn map_error(error: Self::Error) -> ApiError {
        Store::map_error(error)
    }
    fn user_key_id(&mut self, owner: &str) -> rusqlite::Result<Option<&str>> {
        self.store.user_key_id(owner)
    }
    fn account_exists(&mut self, email: &str) -> rusqlite::Result<bool> {
        self.store.account_exists(email)
    }
    fn insert_account(&mut self, id: &str, request: &RegisterRequest<'_>) -> rusqlite::Result<()> {
        self.store.insert_account(id, request)
    }
    fn folder_metadata(&mut self, id: &str) -> rusqlite::Result<Option<ItemMetadata<'_>>> {
        self.store.folder_metadata(id)
    }
    fn save_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> rusqlite::Result<()> {
        self.store.save_folder(owner, id, request)
    }
    fn delete_folder(&mut self, owner: &str, id: &str) -> rusqlite::Result<()> {
        self.store.delete_folder(owner, id)
    }
    fn cipher_metadata(&mut self, id: &str) -> rusqlite::Result<Option<ItemMetadata<'_>>> {
        self.store.cipher_metadata(id)
    }
    fn save_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> rusqlite::Result<()> {
        self.store.save_cipher(owner, id, request)
    }
    fn set_cipher_deleted(&mut self, owner: &str, id: &str, deleted: bool) -> rusqlite::Result<()> {
        self.store.set_cipher_deleted(owner, id, deleted)
    }
    fn delete_cipher(&mut self, owner: &str, id: &str) -> rusqlite::Result<()> {
        self.store.delete_cipher(owner, id)
    }
}
impl AttachmentStorage for Provider<'_> {
    fn attachment_access(
        &mut self,
        actor: &str,
        cipher: &str,
    ) -> rusqlite::Result<Option<CipherAccess>> {
        if actor != self.actor || cipher != self.source.id {
            return Ok(None);
        }
        access(&self.store.db, actor, cipher)
    }
    fn attachment_metadata(
        &mut self,
        attachment: &str,
    ) -> rusqlite::Result<Option<AttachmentMetadata<'_>>> {
        // Read only minimal foreign scope/size facts. Loading another cipher's
        // opaque filename or wrapped key is unnecessary for the core's rejection.
        let minimal: Option<(String, i64)> = self
            .store
            .db
            .query_row(
                "SELECT cipher_id,size FROM attachments WHERE id=lower(?1)",
                [attachment],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        self.metadata = minimal
            .map(|(cipher, size)| {
                u64::try_from(size)
                    .map(|size| (cipher, size))
                    .map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?;
        self.expected_file = if self
            .metadata
            .as_ref()
            .is_some_and(|(cipher, _)| cipher == &self.source.id)
        {
            material(&self.store.db, &self.actor, &self.source.id)?;
            attachments::load(&self.store.db, attachment)?
        } else {
            None
        };
        Ok(self
            .metadata
            .as_ref()
            .map(|(cipher, size)| AttachmentMetadata {
                cipher_id: cipher,
                file_size: *size,
            }))
    }
    fn commit_attachment(
        &mut self,
        actor: &str,
        plan: &ValidatedAttachment<'_>,
    ) -> rusqlite::Result<()> {
        if actor != self.actor || plan.cipher_id() != self.source.id {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (attachment_count, charged_material) = material(&tx, actor, plan.cipher_id())?;
        let current =
            sharing::source(&tx, plan.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
        if current.id != self.source.id
            || current.owner_id != self.source.owner_id
            || current.organization_id != self.source.organization_id
            || current.revision != self.source.revision
            || !access(&tx, actor, plan.cipher_id())?.is_some_and(|a| a.readable && a.writable)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let live_file = attachments::load(&tx, plan.attachment_id())?;
        if plan.action() == AttachmentAction::Reserve {
            if live_file.is_some() {
                return Err(rusqlite::Error::InvalidQuery);
            }
        } else {
            let expected = self
                .expected_file
                .as_ref()
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let live = live_file.as_ref().ok_or(rusqlite::Error::InvalidQuery)?;
            if live.id != expected.id
                || live.cipher_id != plan.cipher_id()
                || live.cipher_id != expected.cipher_id
                || live.file_name != expected.file_name
                || live.key != expected.key
                || live.size != expected.size
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let readers = if matches!(
            plan.action(),
            AttachmentAction::Upload | AttachmentAction::Delete
        ) {
            archive::readers(&tx, actor, &current)?
        } else {
            Vec::new()
        };
        match plan.action() {
            AttachmentAction::Reserve => {
                let write = plan.write().ok_or(rusqlite::Error::InvalidQuery)?;
                let extra = [
                    128,
                    plan.attachment_id().len(),
                    plan.cipher_id().len(),
                    write.file_name.len(),
                    write.key.map_or(0, str::len),
                ]
                .into_iter()
                .try_fold(0usize, usize::checked_add)
                .ok_or(rusqlite::Error::InvalidQuery)?;
                if attachment_count >= MAX_ROWS
                    || charged_material
                        .checked_add(extra)
                        .is_none_or(|total| total > MAX_MATERIAL)
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let size =
                    i64::try_from(write.file_size).map_err(|_| rusqlite::Error::InvalidQuery)?;
                tx.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,?3,?4,?5,NULL)",params![plan.attachment_id(),plan.cipher_id(),write.file_name,write.key,size])?;
            }
            AttachmentAction::Upload => {
                let write = plan.write().ok_or(rusqlite::Error::InvalidQuery)?;
                if self.bytes.len() as u64 != write.file_size {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let size =
                    i64::try_from(write.file_size).map_err(|_| rusqlite::Error::InvalidQuery)?;
                if tx.execute(
                    "UPDATE attachments SET data=?1,size=?2 WHERE id=lower(?3) AND cipher_id=?4",
                    params![self.bytes, size, plan.attachment_id(), plan.cipher_id()],
                )? != 1
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            AttachmentAction::Delete | AttachmentAction::DiscardMismatch => {
                if tx.execute(
                    "DELETE FROM attachments WHERE id=lower(?1) AND cipher_id=?2",
                    params![plan.attachment_id(), plan.cipher_id()],
                )? != 1
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            _ => return Err(rusqlite::Error::InvalidQuery),
        }
        for reader in readers {
            let revision = store::next_revision(&tx, &reader)?;
            store::bump(&tx, &reader, &revision)?;
        }
        tx.commit()
    }
    fn verify_attachment_download(
        &mut self,
        cipher: &str,
        attachment: &str,
        token: &Secret<'_>,
    ) -> rusqlite::Result<bool> {
        self.store
            .verify_attachment_download(cipher, attachment, token)
    }
}

#[cfg(test)]
mod tests;
