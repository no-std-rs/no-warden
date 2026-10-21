//! Native collections_v2 only: durable unordered additions then protected removal.
use crate::{Failure, Store, json_guard_error, organization_cipher_sharing as sharing, store};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_collections::{
        OrganizationCipherCollectionsStorage, ValidatedCipherCollectionAdd,
        ValidatedCipherCollectionsFinish,
    },
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherShareIdsData,
        CipherSharingCollection, CipherSharingMembership, CipherSharingSource,
    },
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::collections::HashMap;

// Local resource policies, not native capacity or ordering claims. Core scans and
// every successful association can fan out revisions, so count-only caps do not
// suffice. All policy checks precede the first write under the Store mutex.
const MAX_IDS: usize = 4096;
const MAX_ASSOCIATIONS: usize = 4096;
const MAX_MEMBERS: usize = 4096;
const MAX_SELECTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPARISON_WORK: usize = 64 * 1024 * 1024;
const SCHEMA_ERROR: &str = "Invalid cipher collection request";
fn budget() -> Failure {
    Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR)
}
fn schema(error: serde_json::Error) -> Failure {
    let error = json_guard_error(error);
    Failure(error.0, SCHEMA_ERROR)
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
fn selected_ids<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct Ids;
    impl<'de> Visitor<'de> for Ids {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("collection IDs within the local selection budget")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            let mut ids = Vec::new();
            let mut charge = 0usize;
            loop {
                if ids.len() == MAX_IDS {
                    return if seq.next_element::<IgnoredAny>()?.is_some() {
                        Err(de::Error::custom("Local selection count exceeded"))
                    } else {
                        Ok(ids)
                    };
                }
                let Some(id) = seq.next_element::<String>()? else {
                    return Ok(ids);
                };
                charge = charge
                    .checked_add(id.len())
                    .and_then(|n| n.checked_add(128))
                    .filter(|&n| n <= MAX_SELECTION_BYTES)
                    .ok_or_else(|| de::Error::custom("Local selection material exceeded"))?;
                ids.push(id);
            }
        }
    }
    d.deserialize_seq(Ids)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(alias = "CollectionIds", deserialize_with = "selected_ids")]
    collection_ids: Vec<String>,
}
impl CipherShareIdsData for Input {
    fn len(&self) -> usize {
        self.collection_ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.collection_ids.get(index).map(String::as_str)
    }
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        serde_json::from_slice(body).map_err(schema)
    }
    fn order(&self) -> Vec<usize> {
        // Independently chosen operation-owned unique order. It is NOT a claim
        // about upstream's hash/RNG, request-prefix behavior or distribution.
        let mut indices = HashMap::new();
        for (index, id) in self.collection_ids.iter().enumerate() {
            indices.entry(id.as_str()).or_insert(index);
        }
        indices.into_values().collect()
    }
    fn check_work(
        &self,
        db: &Connection,
        actor: &str,
        cipher: &str,
        unique: usize,
    ) -> Result<(), Failure> {
        let associated:usize=db.query_row("SELECT count(*) FROM (SELECT 1 FROM organization_collection_ciphers WHERE cipher_id=?1 LIMIT ?2)",params![cipher,MAX_ASSOCIATIONS+1],|r|r.get(0))?;
        let members:usize=db.query_row("SELECT count(*) FROM (SELECT 1 FROM organization_memberships WHERE organization_id=(SELECT organization_id FROM items WHERE id=?1 AND kind='cipher') LIMIT ?2)",params![cipher,MAX_MEMBERS+1],|r|r.get(0))?;
        if associated > MAX_ASSOCIATIONS || members > MAX_MEMBERS {
            return Err(budget());
        }
        let stored_key:usize=db.query_row("SELECT coalesce(max(length(CAST(c.id AS BLOB))+length(CAST(c.organization_id AS BLOB))),0) FROM organization_collection_ciphers l JOIN organization_collections c ON c.id=l.collection_id WHERE l.cipher_id=?1",[cipher],|r|r.get(0))?;
        let selected_key = self
            .collection_ids
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(0);
        let key_bytes = 128usize
            .checked_add(stored_key.max(selected_key))
            .and_then(|n| n.checked_add(actor.len()))
            .and_then(|n| n.checked_add(cipher.len()))
            .ok_or_else(budget)?;
        let grown = associated.checked_add(unique).ok_or_else(budget)?;
        let source_scans = grown
            .checked_mul(grown)
            .and_then(|n| n.checked_add(grown))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| {
                unique
                    .checked_mul(6)
                    .and_then(|u| u.checked_add(6))
                    .and_then(|u| n.checked_mul(u))
            })
            .ok_or_else(budget)?;
        let work = self
            .len()
            .checked_mul(unique)
            .and_then(|n| n.checked_add(source_scans))
            .and_then(|n| n.checked_mul(key_bytes))
            .and_then(|n| {
                unique
                    .checked_add(1)
                    .and_then(|u| members.checked_add(1).and_then(|m| u.checked_mul(m)))
                    .and_then(|f| grown.checked_add(1).and_then(|g| f.checked_mul(g)))
                    .and_then(|f| f.checked_mul(key_bytes))
                    .and_then(|f| f.checked_mul(2))
                    .and_then(|f| n.checked_add(f))
            })
            .ok_or_else(budget)?;
        if work > MAX_COMPARISON_WORK {
            return Err(budget());
        }
        Ok(())
    }
    pub fn execute(&self, s: &mut Store, actor: &str, cipher: &str) -> Result<Value, Failure> {
        let order = self.order();
        self.check_work(&s.db, actor, cipher, order.len())?;
        let scope = VaultService::new(&mut *s).reassign_cipher_collections(
            actor,
            cipher,
            self,
            order.as_slice(),
        )?;
        // Ordinary Store::item would deny the legitimate response after losing
        // read access. Only the successful sealed scope admits this projection.
        let cipher = sharing::project_reassignment(&s.db, &scope)?;
        Ok(json!({"object":"optionalCipherDetails","cipher":cipher,"unavailable":false}))
    }
}
/// Independent owned snapshots survive mutable provider/cache reads.
pub struct SourceAccess {
    canonical: Option<String>,
    rows: Vec<CipherSharingCollection<String>>,
}
impl CipherCollectionAccessData for SourceAccess {
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
) -> rusqlite::Result<SourceAccess> {
    Ok(SourceAccess {
        canonical: source.organization_id.clone(),
        rows: sharing::associated_collections(db, actor, &source.id)?,
    })
}
fn mapped(_: no_warden::ApiError) -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}
fn readable_users(db: &Connection, cipher: &str, org: &str) -> rusqlite::Result<Vec<String>> {
    let users = {
        let mut q =
            db.prepare("SELECT user_id FROM organization_memberships WHERE organization_id=?1")?;
        q.query_map([org], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut readable = Vec::new();
    for user in users {
        if sharing::access(db, &user, cipher)?.is_some_and(|a| a.readable()) {
            readable.push(user);
        }
    }
    Ok(readable)
}
fn advance(
    db: &Connection,
    caller: &str,
    cipher: &str,
    org: &str,
    mut prior: Vec<String>,
) -> rusqlite::Result<()> {
    // Both newly visible and removed accounts must discard stale cached links.
    // Canonical membership and the same core ACL determine both snapshots.
    prior.extend(readable_users(db, cipher, org)?);
    prior.push(caller.to_owned());
    prior.sort();
    prior.dedup();
    for user in prior {
        let revision = store::next_revision(db, &user)?;
        store::bump(db, &user, &revision)?;
    }
    Ok(())
}
impl OrganizationCipherCollectionsStorage for Store {
    type CollectionId = String;
    type CollectionAccess = SourceAccess;
    fn collection_reassignment_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, id)
    }
    fn collection_reassignment_membership(
        &mut self,
        actor: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, actor, org)
    }
    fn collection_reassignment_associations(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<SourceAccess> {
        facts(&self.db, actor, source)
    }
    fn collection_reassignment_target(
        &mut self,
        actor: &str,
        org: &str,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingCollection<String>>> {
        sharing::selected_collection(&self.db, actor, org, id)
    }
    fn add_cipher_collection(
        &mut self,
        plan: &ValidatedCipherCollectionAdd<'_>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source =
            sharing::source(&tx, plan.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
        let member = sharing::membership(&tx, plan.actor(), plan.organization_id())?;
        let associated = facts(&tx, plan.actor(), &source)?;
        let target = sharing::selected_collection(
            &tx,
            plan.actor(),
            plan.organization_id(),
            plan.collection_id(),
        )?
        .ok_or(rusqlite::Error::InvalidQuery)?;
        plan.validate_live(
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &associated,
            target.view(),
        )
        .map_err(mapped)?;
        let prior = readable_users(&tx, plan.cipher_id(), plan.organization_id())?;
        tx.execute("INSERT OR IGNORE INTO organization_collection_ciphers(collection_id,cipher_id) VALUES(?1,?2)",params![plan.collection_id(),plan.cipher_id()])?;
        advance(
            &tx,
            plan.actor(),
            plan.cipher_id(),
            plan.organization_id(),
            prior,
        )?;
        tx.commit()
    }
    fn finish_cipher_collections<D: CipherShareIdsData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherCollectionsFinish<'_, D, SourceAccess>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source =
            sharing::source(&tx, plan.cipher_id())?.ok_or(rusqlite::Error::InvalidQuery)?;
        let member = sharing::membership(&tx, plan.actor(), plan.organization_id())?;
        let associated = facts(&tx, plan.actor(), &source)?;
        plan.validate_live(
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &associated,
        )
        .map_err(mapped)?;
        let prior = readable_users(&tx, plan.cipher_id(), plan.organization_id())?;
        for index in 0..plan.associated_len() {
            if let Some(id) = plan.removal(index).map_err(mapped)? {
                tx.execute("DELETE FROM organization_collection_ciphers WHERE cipher_id=?1 AND collection_id=?2",params![plan.cipher_id(),id])?;
            }
        }
        advance(
            &tx,
            plan.actor(),
            plan.cipher_id(),
            plan.organization_id(),
            prior,
        )?;
        tx.commit()
    }
}
#[cfg(test)]
mod tests;
