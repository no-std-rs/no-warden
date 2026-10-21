//! Private archive annotations with distinct single/selected revision effects.
use crate::{
    Failure, Store, cipher_reads, json_guard_error, organization_cipher_sharing as sharing, store,
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_archive::{
        CipherArchiveOperation, CipherArchiveRevisionEffect, CipherArchiveStorage,
        ValidatedCipherArchive,
    },
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource,
    },
    route::Route,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use serde_json::{Value, json};

// Adapter policies, not native limits or capacities of the allocation-free core.
const MAX_IDS: usize = 4096;
const MAX_ASSOCIATIONS: usize = 4096;
const MAX_READERS: usize = 4096;
const MAX_MATERIAL: usize = 8 * 1024 * 1024;
const SCHEMA_ERROR: &str = "Invalid archive selection";
fn schema(error: serde_json::Error) -> Failure {
    Failure(json_guard_error(error).0, SCHEMA_ERROR)
}
fn capacity() -> Failure {
    Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR)
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
struct Ids(Vec<String>);
impl<'de> Deserialize<'de> for Ids {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Rows;
        impl<'de> Visitor<'de> for Rows {
            type Value = Ids;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded list of cipher IDs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ids, A::Error> {
                let mut rows = Vec::new();
                let mut bytes = 0usize;
                while let Some(id) = seq.next_element::<String>()? {
                    bytes = bytes
                        .checked_add(id.len())
                        .ok_or_else(|| de::Error::custom("ID budget"))?;
                    if rows.len() == MAX_IDS || bytes > MAX_MATERIAL {
                        return Err(de::Error::custom("ID budget"));
                    }
                    rows.push(id);
                }
                Ok(Ids(rows))
            }
        }
        decoder.deserialize_seq(Rows)
    }
}
#[derive(Deserialize)]
struct SelectedInput {
    ids: Ids,
}

pub fn dispatch(
    route: Route<'_>,
    actor: &str,
    body: &[u8],
    s: &mut Store,
) -> Result<Response, Failure> {
    let operation = match route {
        Route::CipherArchive(_) | Route::CipherBulkArchive => CipherArchiveOperation::Archive,
        Route::CipherUnarchive(_) | Route::CipherBulkUnarchive => CipherArchiveOperation::Unarchive,
        _ => return Err(crate::missing()),
    };
    match route {
        Route::CipherArchive(raw) | Route::CipherUnarchive(raw) => {
            let id = cipher_reads::path_id(raw)?;
            preflight(&s.db, actor, &[id.as_str()])?;
            VaultService::new(&mut *s).archive_cipher(actor, &id, operation)?;
            Ok(crate::json_response(project(&s.db, actor, &id)?))
        }
        _ => {
            let input: SelectedInput = serde_json::from_slice(body).map_err(schema)?;
            let mut ids: Vec<&str> = input.ids.0.iter().map(String::as_str).collect();
            ids.sort_unstable();
            ids.dedup();
            preflight(&s.db, actor, &ids)?;
            let mut scratch = vec![""; ids.len()];
            let mut seen = vec![false; ids.len()];
            let count = VaultService::new(&mut *s).archive_selected_ciphers(
                actor,
                operation,
                ids.iter().copied(),
                &mut scratch,
                &mut seen,
            )?;
            let rows = scratch[..count]
                .iter()
                .map(|id| project(&s.db, actor, id))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(crate::json_response(
                json!({"object":"list","data":rows,"continuationToken":null}),
            ))
        }
    }
}

pub(crate) fn project(db: &Connection, actor: &str, id: &str) -> Result<Value, Failure> {
    let mut value = sharing::project(db, actor, id, true)?.ok_or(rusqlite::Error::InvalidQuery)?;
    // The measured response has these known 30 fields; unknown nested encrypted
    // extensions and the entire stored document remain intact.
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
fn confirmed(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM items i JOIN organization_memberships m ON m.organization_id=i.organization_id WHERE i.id=?1 AND i.kind='cipher' AND m.user_id=?2 AND m.status=2)",params![cipher,actor],|r|r.get(0))
}
fn material(db: &Connection, actor: &str, cipher: &str) -> rusqlite::Result<Option<usize>> {
    // Negative load optimization only. Missing/foreign/unconfirmed sources skip
    // owned fact/document loading and receive independent core admission checks.
    let row: Option<(bool, usize)> = db.query_row("SELECT coalesce((i.owner=?2 AND i.organization_id IS NULL) OR EXISTS(SELECT 1 FROM organization_memberships m WHERE m.organization_id=i.organization_id AND m.user_id=?2 AND m.status=2),0),128+length(CAST(i.id AS BLOB))+coalesce(length(CAST(i.owner AS BLOB)),0)+coalesce(length(CAST(i.organization_id AS BLOB)),0)+length(CAST(i.revision AS BLOB))+length(CAST(i.document AS BLOB)) FROM items i WHERE i.id=?1 AND i.kind='cipher'",params![cipher,actor],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((true, base)) = row else {
        return Ok(Some(0));
    };
    let count: usize = db.query_row("SELECT count(*) FROM (SELECT 1 FROM organization_collection_ciphers WHERE cipher_id=?1 LIMIT ?2)",params![cipher,MAX_ASSOCIATIONS+1],|r|r.get(0))?;
    if count > MAX_ASSOCIATIONS {
        return Ok(None);
    }
    let bytes: usize = db.query_row("SELECT coalesce(sum(128+length(CAST(c.id AS BLOB))+length(CAST(c.organization_id AS BLOB))+?2),0) FROM organization_collection_ciphers l JOIN organization_collections c ON c.id=l.collection_id WHERE l.cipher_id=?1",params![cipher,actor.len()],|r|r.get(0))?;
    Ok(base
        .checked_add(bytes)
        .filter(|total| *total <= MAX_MATERIAL))
}
pub(crate) fn preflight(db: &Connection, actor: &str, ids: &[&str]) -> Result<(), Failure> {
    let mut bytes = 0usize;
    for id in ids {
        bytes = bytes
            .checked_add(material(db, actor, id)?.ok_or_else(capacity)?)
            .filter(|n| *n <= MAX_MATERIAL)
            .ok_or_else(capacity)?;
    }
    Ok(())
}
pub struct Access {
    canonical: Option<String>,
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
                cipher_organization_id: self.canonical.as_deref(),
                collection: row.view(),
            })
    }
}
pub(crate) fn facts(
    db: &Connection,
    actor: &str,
    source: &CipherSharingSource<String>,
) -> rusqlite::Result<Access> {
    material(db, actor, &source.id)?.ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(Access {
        canonical: source.organization_id.clone(),
        rows: if source.organization_id.is_some() && confirmed(db, actor, &source.id)? {
            sharing::associated_collections(db, actor, &source.id)?
        } else {
            Vec::new()
        },
    })
}
pub(crate) fn readers(
    db: &Connection,
    actor: &str,
    source: &CipherSharingSource<String>,
) -> rusqlite::Result<Vec<String>> {
    let Some(org) = source.organization_id.as_deref() else {
        return Ok(vec![actor.to_owned()]);
    };
    let (count, bytes): (usize, usize) = db.query_row("SELECT count(*),coalesce(sum(128+length(CAST(user_id AS BLOB))),0) FROM (SELECT user_id FROM organization_memberships WHERE organization_id=?1 AND status=2 LIMIT ?2)",params![org,MAX_READERS+1],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if count > MAX_READERS || bytes > MAX_MATERIAL {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut statement = db.prepare(
        "SELECT user_id FROM organization_memberships WHERE organization_id=?1 AND status=2",
    )?;
    let candidates = statement
        .query_map([org], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for user in candidates {
        // Check material before the ordinary pure access projector loads facts.
        material(db, &user, &source.id)?.ok_or(rusqlite::Error::InvalidQuery)?;
        if sharing::access(db, &user, &source.id)?.is_some_and(|a| a.readable()) {
            result.push(user);
        }
    }
    // The actor has already been admitted by the sealed target's live check.
    result.push(actor.to_owned());
    result.sort();
    result.dedup();
    Ok(result)
}
impl CipherArchiveStorage for Store {
    type ArchiveId = String;
    type ArchiveAccess = Access;
    type ArchiveOrder = Vec<usize>;
    fn cipher_archive_order(
        &mut self,
        _actor: &str,
        _operation: CipherArchiveOperation,
        sorted_unique_ids: &[&str],
    ) -> rusqlite::Result<Vec<usize>> {
        // An operation-owned order, never a client-provided permission. Native
        // fixed-ID comparisons show unstable processing and durable eligible
        // subsets on later admission failure. No exact order or distribution is
        // claimed; the core validates this complete permutation before writes.
        Ok((0..sorted_unique_ids.len())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect())
    }

    fn cipher_archive_source(
        &mut self,
        cipher: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, cipher)
    }
    fn cipher_archive_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, actor, organization)
    }
    fn cipher_archive_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<Access> {
        facts(&self.db, actor, source)
    }
    // One sealed target per commit. A selected request can complete earlier
    // atomic steps before a later READ check or step fails; never wrap those
    // independently durable steps in an outer transaction.
    fn commit_cipher_archive(
        &mut self,
        plan: &ValidatedCipherArchive<'_, String>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut bytes = 0usize;
        let mut revisions = vec![plan.actor().to_owned()];
        for index in 0..plan.len() {
            let target = plan.target(index).ok_or(rusqlite::Error::InvalidQuery)?;
            let source =
                sharing::source(&tx, target.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
            bytes = bytes
                .checked_add(
                    material(&tx, plan.actor(), &source.id)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                )
                .filter(|n| *n <= MAX_MATERIAL)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let member = source
                .organization_id
                .as_deref()
                .map(|org| sharing::membership(&tx, plan.actor(), org))
                .transpose()?
                .flatten();
            let access = facts(&tx, plan.actor(), &source)?;
            target
                .validate_live(
                    &source,
                    member.as_ref().map(CipherSharingMembership::view),
                    &access,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            if plan.revision_effect() == CipherArchiveRevisionEffect::CurrentReaders {
                revisions = readers(&tx, plan.actor(), &source)?;
            }
        }
        if plan.is_empty() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let actor_revision = store::next_revision(&tx, plan.actor())?;
        let archived = (plan.operation() == CipherArchiveOperation::Archive)
            .then_some(actor_revision.as_str());
        for index in 0..plan.len() {
            let target = plan.target(index).ok_or(rusqlite::Error::InvalidQuery)?;
            tx.execute("INSERT INTO cipher_archives(cipher_id,owner,archived_at) VALUES(?1,?2,?3) ON CONFLICT(cipher_id,owner) DO UPDATE SET archived_at=excluded.archived_at",params![target.cipher_id(),plan.actor(),archived])?;
        }
        for user in revisions {
            let revision = if user == plan.actor() {
                actor_revision.clone()
            } else {
                store::next_revision(&tx, &user)?
            };
            store::bump(&tx, &user, &revision)?;
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests;
