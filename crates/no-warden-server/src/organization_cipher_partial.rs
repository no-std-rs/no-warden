//! Actor-private annotations, including readable readonly organization ciphers.
use crate::{Failure, Store, json_guard_error, organization_cipher_sharing as sharing, store};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_partial::{
        CipherPartialFolder, CipherPartialStorage, CipherPartialView, ValidatedCipherPartial,
    },
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource,
    },
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};

// Local host policies, not native capacity limits or intrinsic core limits.
// SQL counts/charges precede owned association allocation, including the live
// reload in the IMMEDIATE transaction. UTF-8 bytes and each repeated actor ID
// are charged with fixed row overhead, rather than character lengths.
const MAX_ASSOCIATIONS: usize = 4096;
const MAX_FACT_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA_ERROR: &str = "Invalid cipher partial request";
fn schema(error: serde_json::Error) -> Failure {
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
// Deliberately owned: ordinary escaped JSON folder IDs must decode correctly.
// Only the measured camelCase fields are recognized. Field order also admits
// native [folderId, favorite] tuples; serde categories distinguish extra elements
// from wrong field types without interpreting diagnostic text.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    folder_id: Option<String>,
    favorite: bool,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        serde_json::from_slice(body).map_err(schema)
    }
    pub fn execute(&self, s: &mut Store, actor: &str, cipher: &str) -> Result<Value, Failure> {
        if !within_budget(&s.db, actor, cipher)? {
            return Err(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR));
        }
        VaultService::new(&mut *s).update_cipher_private_annotations(
            actor,
            cipher,
            CipherPartialView {
                folder_id: self.folder_id.as_deref(),
                favorite: self.favorite,
            },
        )?;
        let mut value =
            sharing::project(&s.db, actor, cipher, true)?.ok_or(rusqlite::Error::InvalidQuery)?;
        // This route's measured response is the known ordinary 30-field shape.
        // Preserve all opaque nested values and the entire stored raw document;
        // do not change unrelated personal GET's unknown-field behavior.
        value
            .as_object_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .retain(|name, _| {
                matches!(
                    name.as_str(),
                    "archivedDate"
                        | "attachments"
                        | "bankAccount"
                        | "card"
                        | "collectionIds"
                        | "creationDate"
                        | "deletedDate"
                        | "driversLicense"
                        | "edit"
                        | "favorite"
                        | "fields"
                        | "folderId"
                        | "id"
                        | "identity"
                        | "key"
                        | "login"
                        | "name"
                        | "notes"
                        | "object"
                        | "organizationId"
                        | "organizationUseTotp"
                        | "passport"
                        | "passwordHistory"
                        | "permissions"
                        | "reprompt"
                        | "revisionDate"
                        | "secureNote"
                        | "sshKey"
                        | "type"
                        | "viewPassword"
                )
            });
        Ok(value)
    }
}
fn confirmed(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<bool> {
    // Negative load optimization only. The core still verifies canonical
    // membership, source identity and every effective grant. Never load/count
    // foreign associated facts for a missing or unconfirmed canonical member.
    db.query_row("SELECT EXISTS(SELECT 1 FROM items i JOIN organization_memberships m ON m.organization_id=i.organization_id WHERE i.id=?1 AND i.kind='cipher' AND m.user_id=?2 AND m.status=2)",params![cipher,actor],|r|r.get(0))
}
fn within_budget(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<bool> {
    // Foreign/unconfirmed sources skip fact loading and let core admission
    // reject them. Actor-owned personal sources are charged too: the ordinary
    // response projector reads their associated rows, even though core READ
    // authority for personal ownership requires none.
    let scope:Option<(usize,bool)> = db.query_row("SELECT coalesce(length(CAST(i.organization_id AS BLOB)),0),coalesce((i.owner=?2 AND i.organization_id IS NULL) OR EXISTS(SELECT 1 FROM organization_memberships m WHERE m.organization_id=i.organization_id AND m.user_id=?2 AND m.status=2),0) FROM items i WHERE i.id=?1 AND i.kind='cipher'",params![cipher,actor],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((org_bytes, true)) = scope else {
        return Ok(true);
    };
    // For admitted membership snapshots, oversized facts are rejected before
    // per-collection READ evaluation. Native precedence above local limits is
    // unclaimed; the core remains the final authority within those limits.
    let count: usize = db.query_row("SELECT count(*) FROM (SELECT 1 FROM organization_collection_ciphers WHERE cipher_id=?1 LIMIT ?2)", params![cipher, MAX_ASSOCIATIONS + 1], |r|r.get(0))?;
    if count > MAX_ASSOCIATIONS {
        return Ok(false);
    }
    let bytes: usize = db.query_row("SELECT coalesce(sum(128+length(CAST(c.id AS BLOB))+length(CAST(c.organization_id AS BLOB))+?2),0) FROM organization_collection_ciphers l JOIN organization_collections c ON c.id=l.collection_id WHERE l.cipher_id=?1", params![cipher,actor.len()], |r|r.get(0))?;
    Ok(bytes
        .checked_add(org_bytes)
        .is_some_and(|n| n <= MAX_FACT_BYTES))
}
pub struct PartialAccess {
    canonical: Option<String>,
    rows: Vec<CipherSharingCollection<String>>,
}
impl CipherCollectionAccessData for PartialAccess {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        self.rows
            .get(index)
            .map(|row| CipherCollectionAccessRecord {
                cipher_organization_id: self.canonical.as_deref(),
                collection: row.view(),
            })
    }
}
fn facts(
    db: &Connection,
    actor: &str,
    source: &CipherSharingSource<String>,
) -> rusqlite::Result<PartialAccess> {
    if !within_budget(db, actor, &source.id)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(PartialAccess {
        canonical: source.organization_id.clone(),
        rows: if source.organization_id.is_some() && confirmed(db, actor, &source.id)? {
            sharing::associated_collections(db, actor, &source.id)?
        } else {
            Vec::new()
        },
    })
}
fn folder(db: &Connection, id: &str) -> rusqlite::Result<Option<CipherPartialFolder<String>>> {
    db.query_row(
        "SELECT id,owner FROM items WHERE id=?1 AND kind='folder' AND owner IS NOT NULL",
        [id],
        |r| {
            Ok(CipherPartialFolder {
                id: r.get(0)?,
                owner_id: r.get(1)?,
            })
        },
    )
    .optional()
}
impl CipherPartialStorage for Store {
    type PartialId = String;
    type PartialAccess = PartialAccess;
    fn cipher_partial_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, id)
    }
    fn cipher_partial_membership(
        &mut self,
        actor: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, actor, org)
    }
    fn cipher_partial_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<PartialAccess> {
        facts(&self.db, actor, source)
    }
    fn cipher_partial_folder(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherPartialFolder<String>>> {
        folder(&self.db, id)
    }
    fn commit_cipher_partial(&mut self, plan: &ValidatedCipherPartial<'_>) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source =
            sharing::source(&tx, plan.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
        let member = match source.organization_id.as_deref() {
            Some(org) => sharing::membership(&tx, plan.actor(), org)?,
            None => None,
        };
        let access = facts(&tx, plan.actor(), &source)?;
        let target = plan
            .folder_id()
            .map(|id| folder(&tx, id))
            .transpose()?
            .flatten();
        plan.validate_live(
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &access,
            target.as_ref().map(CipherPartialFolder::view),
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if source.organization_id.is_some() {
            tx.execute("INSERT INTO cipher_annotations(cipher_id,user_id,folder_id,favorite) VALUES(?1,?2,?3,?4) ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite",params![plan.cipher_id(),plan.actor(),plan.folder_id(),plan.favorite()])?;
        } else {
            // Read CURRENT raw JSON after acquiring the write lock. Replacing a
            // pre-transaction document snapshot would discard concurrent opaque
            // updates even if the observed SQL source revision had not changed.
            let text: String = tx.query_row(
                "SELECT document FROM items WHERE id=?1 AND kind='cipher'",
                [plan.cipher_id()],
                |r| r.get(0),
            )?;
            let mut value: Value =
                serde_json::from_str(&text).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let fields = value.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
            fields.insert("folderId".into(), json!(plan.folder_id()));
            fields.insert("favorite".into(), json!(plan.favorite()));
            if tx.execute(
                "UPDATE items SET document=?1 WHERE id=?2 AND kind='cipher'",
                params![value.to_string(), plan.cipher_id()],
            )? != 1
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        }
        let revision = store::next_revision(&tx, plan.actor())?;
        store::bump(&tx, plan.actor(), &revision)?;
        tx.commit()
    }
}
#[cfg(test)]
mod tests;
