//! Single shared lifecycle operations; opaque payloads and private annotations
//! remain in the adapter. The generic selected lifecycle APIs stay separate.
use crate::{
    Failure, Store, cipher_reads, organization_cipher_archive as archive,
    organization_cipher_sharing as sharing, store,
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_lifecycle::{
        CipherLifecycleOperation, CipherLifecycleStorage, ValidatedCipherLifecycle,
    },
    organization_cipher_sharing::{CipherSharingMembership, CipherSharingSource},
    route::Route,
};
use rusqlite::{TransactionBehavior, params};
use serde_json::{Value, json};

pub fn render_error(error: Failure) -> Response {
    if matches!(
        error.0,
        StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return (error.0, Json(json!({"error":"Invalid request"}))).into_response();
    }
    if error.0 == StatusCode::BAD_REQUEST {
        return crate::password_login::error_response(error.0, error.1);
    }
    error.into_response()
}

pub fn dispatch(route: Route<'_>, actor: &str, s: &mut Store) -> Result<Response, Failure> {
    let (raw, operation) = match route {
        Route::CipherSoftDelete(id) => (id, CipherLifecycleOperation::Trash),
        Route::CipherRestore(id) => (id, CipherLifecycleOperation::Restore),
        Route::CipherDelete(id) => (id, CipherLifecycleOperation::PermanentDelete),
        _ => return Err(crate::missing()),
    };
    let id = cipher_reads::path_id(raw)?;
    archive::preflight(&s.db, actor, &[id.as_str()])?;
    VaultService::new(&mut *s).mutate_cipher_lifecycle(actor, &id, operation)?;
    if operation == CipherLifecycleOperation::Restore {
        Ok(crate::json_response(archive::project(&s.db, actor, &id)?))
    } else {
        Ok(StatusCode::OK.into_response())
    }
}

impl CipherLifecycleStorage for Store {
    type LifecycleId = String;
    type LifecycleAccess = archive::Access;

    fn cipher_lifecycle_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, id)
    }
    fn cipher_lifecycle_membership(
        &mut self,
        actor: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, actor, org)
    }
    fn cipher_lifecycle_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<archive::Access> {
        archive::facts(&self.db, actor, source)
    }
    fn commit_cipher_lifecycle(
        &mut self,
        plan: &ValidatedCipherLifecycle<'_>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Bound material before loading the owned source/document or grant facts.
        archive::preflight(&tx, plan.actor(), &[plan.cipher_id()])
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let source =
            sharing::source(&tx, plan.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
        let member = source
            .organization_id
            .as_deref()
            .map(|org| sharing::membership(&tx, plan.actor(), org))
            .transpose()?
            .flatten();
        let facts = archive::facts(&tx, plan.actor(), &source)?;
        plan.validate_live(
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &facts,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        // Resolve notification recipients while the live source/links still exist.
        let readers = archive::readers(&tx, plan.actor(), &source)?;
        let revision = store::next_revision(&tx, plan.actor())?;
        match plan.operation() {
            CipherLifecycleOperation::Trash | CipherLifecycleOperation::Restore => {
                let raw: String = tx.query_row(
                    "SELECT document FROM items WHERE id=?1 AND kind='cipher'",
                    [plan.cipher_id()],
                    |r| r.get(0),
                )?;
                let mut document: Value =
                    serde_json::from_str(&raw).map_err(|_| rusqlite::Error::InvalidQuery)?;
                let fields = document
                    .as_object_mut()
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let deleted = plan.operation() == CipherLifecycleOperation::Trash;
                fields.insert(
                    "deletedDate".to_owned(),
                    if deleted {
                        Value::String(revision.clone())
                    } else {
                        Value::Null
                    },
                );
                fields.insert("revisionDate".to_owned(), Value::String(revision.clone()));
                let changed = tx.execute("UPDATE items SET document=?1,deleted=?2,revision=?3 WHERE id=?4 AND kind='cipher'", params![document.to_string(), deleted, revision, plan.cipher_id()])?;
                if changed != 1 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            CipherLifecycleOperation::PermanentDelete => {
                // Foreign keys remove only this cipher's associations, private
                // annotations, archives and attachment metadata/download state.
                if tx.execute(
                    "DELETE FROM items WHERE id=?1 AND kind='cipher'",
                    [plan.cipher_id()],
                )? != 1
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
        }
        for user in readers {
            let next = if user == plan.actor() {
                revision.clone()
            } else {
                store::next_revision(&tx, &user)?
            };
            store::bump(&tx, &user, &next)?;
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests;
