//! Independently authored ordinary organization-cipher update adapter.
//! Canonical ownership selects this opt-in path; opaque JSON stays in the host.
use crate::{Failure, Store, json_guard_error, organization_cipher_sharing as sharing, store};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_bulk_sharing::resolve_bulk_cipher_source_write_access,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource,
    },
    organization_cipher_update::{
        OrganizationCipherUpdateData, OrganizationCipherUpdateStorage,
        ValidatedOrganizationCipherUpdate,
    },
    wire::{CipherRequest, OrganizationCipherUpdateRequest},
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};

const SCHEMA_ERROR: &str = "Invalid organization cipher update request";
fn schema_error(error: serde_json::Error) -> Failure {
    Failure(json_guard_error(error).0, SCHEMA_ERROR)
}
pub fn render_error(error: Failure) -> Response {
    if error.1 == SCHEMA_ERROR {
        return (error.0, Json(json!({"error":"Invalid request"}))).into_response();
    }
    if error.0 == StatusCode::BAD_REQUEST {
        return crate::password_login::error_response(error.0, error.1);
    }
    error.into_response()
}
pub struct Input {
    document: Value,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let document: Value = serde_json::from_slice(body).map_err(schema_error)?;
        let view = OrganizationCipherUpdateRequest::deserialize(&document).map_err(schema_error)?;
        // This bounded slice implements attachment-free secure-note updates.
        // Other item families and attachment rewrapping stay separate work.
        if view.kind != 2
            || document
                .get("attachments2")
                .is_some_and(|v| !v.is_null() && !v.as_object().is_some_and(|v| v.is_empty()))
        {
            return Err(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR));
        }
        // Native secure-note data is presence-checked after authorization and
        // scope/revision/folder guards. Non-null values such as a string or an
        // empty object normalize to subtype zero rather than schema rejection.
        let mut shape = document.clone();
        let fields = shape
            .as_object_mut()
            .ok_or(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR))?;
        fields.remove("secureNote");
        if fields.get("favorite").is_some_and(Value::is_null) {
            fields.remove("favorite");
        }
        CipherRequest::deserialize(&shape).map_err(schema_error)?;
        Ok(Self { document })
    }
    pub fn execute(&self, store: &mut Store, owner: &str, id: &str) -> Result<(), Failure> {
        let request =
            OrganizationCipherUpdateRequest::deserialize(&self.document).map_err(schema_error)?;
        store.pending = self.document.clone();
        let result = VaultService::new(&mut *store).update_organization_cipher(owner, id, &request);
        store.pending = Value::Null;
        result.map_err(Into::into)
    }
}
pub struct Access {
    organization: Option<String>,
    rows: Vec<CipherSharingCollection<String>>,
}
impl CipherCollectionAccessData for Access {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        self.rows
            .get(index)
            .map(|row| CipherCollectionAccessRecord {
                cipher_organization_id: self.organization.as_deref(),
                collection: row.view(),
            })
    }
}
fn older(stored: &str, requested: Option<&str>) -> bool {
    requested
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .zip(chrono::DateTime::parse_from_rfc3339(stored).ok())
        .is_some_and(|(requested, stored)| requested < stored)
}
fn recheck(
    db: &Connection,
    user: &str,
    id: &str,
    org: &str,
    revision: &str,
) -> rusqlite::Result<()> {
    let source = sharing::source(db, id)?.ok_or(rusqlite::Error::InvalidQuery)?;
    if source.revision != revision
        || source.organization_id.as_deref() != Some(org)
        || source.owner_id.is_some()
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let member = sharing::membership(db, user, org)?;
    let rows = sharing::associated_collections(db, user, id)?;
    let writable = resolve_bulk_cipher_source_write_access(
        user,
        source
            .ownership()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        member.as_ref().map(CipherSharingMembership::view),
        &sharing::AccessData {
            cipher_org: Some(org),
            records: &rows,
        },
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if !writable {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
impl OrganizationCipherUpdateStorage for Store {
    type UpdateId = String;
    type UpdateAccess = Access;
    fn organization_cipher_update_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, id)
    }
    fn organization_cipher_update_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, user, org)
    }
    fn organization_cipher_update_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<Access> {
        Ok(Access {
            organization: source.organization_id.clone(),
            rows: sharing::associated_collections(&self.db, user, &source.id)?,
        })
    }
    fn organization_cipher_update_revision_is_older(
        &mut self,
        source: &CipherSharingSource<String>,
        requested: Option<&str>,
    ) -> rusqlite::Result<bool> {
        Ok(older(&source.revision, requested))
    }
    fn commit_organization_cipher_update<D: OrganizationCipherUpdateData + ?Sized>(
        &mut self,
        plan: &ValidatedOrganizationCipherUpdate<'_, D>,
    ) -> rusqlite::Result<()> {
        let mut document = self.pending.clone();
        let typed = OrganizationCipherUpdateRequest::deserialize(&document)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let request = plan.view();
        if typed.organization_id != Some(plan.organization_id())
            || typed.folder_id != request.folder_id
            || typed.last_known_revision_date != request.last_known_revision_date
            || typed.secure_note.is_some() != request.secure_note_present
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let favorite = typed.favorite;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        recheck(
            &tx,
            plan.owner(),
            plan.cipher_id(),
            plan.organization_id(),
            plan.source_revision(),
        )?;
        if older(plan.source_revision(), request.last_known_revision_date) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if let Some(folder) = request.folder_id {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE id=?1 AND owner=?2 AND kind='folder')",
                params![folder, plan.owner()],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let has_attachments: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM attachments WHERE cipher_id=?1)",
            [plan.cipher_id()],
            |r| r.get(0),
        )?;
        if has_attachments {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let original: String = tx.query_row(
            "SELECT document FROM items WHERE id=?1 AND kind='cipher'",
            [plan.cipher_id()],
            |r| r.get(0),
        )?;
        let original: Value =
            serde_json::from_str(&original).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let favorite: bool = match favorite { Some(value)=>value, None=>tx.query_row("SELECT COALESCE((SELECT favorite FROM cipher_annotations WHERE cipher_id=?1 AND user_id=?2),0)",params![plan.cipher_id(), plan.owner()],|r|r.get(0))? };
        let revision = store::next_revision(&tx, plan.owner())?;
        let fields = document
            .as_object_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?;
        for name in ["lastKnownRevisionDate", "attachments2"] {
            fields.remove(name);
        }
        document["id"] = json!(plan.cipher_id());
        document["organizationId"] = json!(plan.organization_id());
        document["object"] = json!("cipherDetails");
        document["creationDate"] = original["creationDate"].clone();
        document["deletedDate"] = original["deletedDate"].clone();
        document["revisionDate"] = json!(revision);
        document["folderId"] = Value::Null;
        document["favorite"] = json!(false);
        document["archivedDate"] = Value::Null;
        tx.execute("INSERT INTO cipher_annotations(cipher_id,user_id,folder_id,favorite) VALUES(?1,?2,?3,?4) ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite",params![plan.cipher_id(),plan.owner(),request.folder_id,favorite])?;
        let changed=tx.execute("UPDATE items SET document=?1,revision=?2 WHERE id=?3 AND kind='cipher' AND owner IS NULL AND organization_id=?4 AND revision=?5",params![document.to_string(),revision,plan.cipher_id(),plan.organization_id(),plan.source_revision()])?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        sharing::advance_cipher(
            &tx,
            plan.owner(),
            plan.cipher_id(),
            Some(plan.organization_id()),
        )?;
        tx.commit()
    }
}
#[cfg(test)]
mod tests;
