//! Independently authored native bulk sharing. Opaque JSON remains adapter-owned.
use crate::{Failure, Store, json_guard_error, organization_cipher_sharing as sharing, store};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    organization_cipher_bulk_sharing::{
        CipherBulkShareItem, CipherBulkSharingData, OrganizationCipherBulkSharingStorage,
        ValidatedCipherBulkShare, ValidatedCipherBulkShareAssociation,
        resolve_bulk_cipher_source_write_access,
    },
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource,
    },
    wire::{CipherBulkShareItemRequest, CipherRequest},
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use serde_json::{Value, json};

// Host resource policy, not an upstream API limit or a cap in the reusable core.
// Each association is durable and performs revision fanout. Bound the product too,
// rather than allowing two individually bounded lists to produce millions of TXs.
const MAX_BULK_CIPHERS: usize = 4096;
const MAX_BULK_COLLECTIONS: usize = 4096;
const MAX_BULK_ASSOCIATIONS: usize = 8192;
const SCHEMA_ERROR: &str = "Invalid bulk cipher sharing request";
/// Keep the native bulk error shape at the socket boundary. Direct dispatcher
/// callers retain typed Err results, and unrelated personal/single routes retain
/// their established rendering even when they use the same public error text.
pub fn render_error(error: Failure) -> Response {
    if error.1 == SCHEMA_ERROR {
        return (error.0, Json(json!({"error":"Invalid request"}))).into_response();
    }
    if error.0 == StatusCode::BAD_REQUEST
        && matches!(
            error.1,
            "You must select at least one cipher."
                | "You must select at least one collection."
                | "Request missing ids field"
                | "Cipher doesn't exist"
                | "Cipher is not write accessible"
                | "Organization mismatch. Please resync the client before updating the cipher"
                | "No rights to modify the collection"
                | "Invalid collection ID provided"
                | "Invalid folder"
        )
    {
        return crate::password_login::error_response(error.0, error.1);
    }
    error.into_response()
}
fn schema_error(error: serde_json::Error) -> Failure {
    // Classify the decoder's error category, never text supplied in a field.
    // Streaming positional overflow is already a syntax error (400), while
    // field-type errors remain data errors (422) regardless of their value.
    let failure = json_guard_error(error);
    Failure(failure.0, SCHEMA_ERROR)
}
fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const N: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Items<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Items<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an array within the bulk host work budget")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            let mut result = Vec::new();
            loop {
                if result.len() == N {
                    return if seq.next_element::<IgnoredAny>()?.is_some() {
                        Err(de::Error::custom("Bulk host count budget exceeded"))
                    } else {
                        Ok(result)
                    };
                }
                match seq.next_element()? {
                    Some(row) => result.push(row),
                    None => return Ok(result),
                }
            }
        }
    }
    d.deserialize_seq(Items::<T, N>(std::marker::PhantomData))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(deserialize_with = "bounded_vec::<'de, _, Value, MAX_BULK_CIPHERS>")]
    ciphers: Vec<Value>,
    #[serde(deserialize_with = "bounded_vec::<'de, _, String, MAX_BULK_COLLECTIONS>")]
    collection_ids: Vec<String>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let input: Self = serde_json::from_slice(body).map_err(schema_error)?;
        // Validate every known typed structure before any provider write. The
        // original Value still owns all opaque extension fields byte-for-byte as
        // strings; no narrow DTO serialization replaces the submitted document.
        for item in &input.ciphers {
            CipherBulkShareItemRequest::deserialize(item).map_err(schema_error)?;
            if item.get("favorite").is_some_and(Value::is_null) {
                // Bulk's optional favorite differs from the personal request
                // model. Validate the other fields without narrowing the opaque
                // original or turning null into a requested false annotation.
                let mut shape = item.clone();
                shape
                    .as_object_mut()
                    .ok_or(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR))?
                    .remove("favorite");
                CipherRequest::deserialize(&shape).map_err(schema_error)?;
            } else {
                CipherRequest::deserialize(item).map_err(schema_error)?;
            }
            crate::attachments::validate_rewrap(item)?;
        }
        // Global native ID-presence failure precedes item processing. The core
        // independently enforces the same rule for every other input provider.
        if input
            .ciphers
            .iter()
            .any(|row| row.get("id").is_none_or(Value::is_null))
        {
            return Err(Failure(
                StatusCode::BAD_REQUEST,
                "Request missing ids field",
            ));
        }
        if input
            .ciphers
            .len()
            .checked_mul(input.collection_ids.len())
            .is_none_or(|n| n > MAX_BULK_ASSOCIATIONS)
        {
            return Err(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR));
        }
        Ok(input)
    }
    pub fn execute(&self, store: &mut Store, owner: &str) -> Result<(), Failure> {
        // Stage the complete native wrapper, not one cached initial source. Every
        // duplicate reloads current ownership/revision through the core service.
        store.pending = json!({"ciphers":self.ciphers});
        let result = VaultService::new(&mut *store).bulk_share_ciphers(owner, self);
        store.pending = Value::Null;
        result.map_err(Into::into)
    }
}
impl CipherBulkSharingData for Input {
    fn ciphers_len(&self) -> usize {
        self.ciphers.len()
    }
    fn cipher(&self, index: usize) -> Option<CipherBulkShareItem<'_>> {
        let row = self.ciphers.get(index)?;
        Some(CipherBulkShareItem {
            id: row.get("id").and_then(Value::as_str),
            cipher_type: i32::try_from(row.get("type")?.as_i64()?).ok()?,
            name: row.get("name")?.as_str()?,
            organization_id: row.get("organizationId").and_then(Value::as_str),
            folder_id: row.get("folderId").and_then(Value::as_str),
        })
    }
    fn collections_len(&self) -> usize {
        self.collection_ids.len()
    }
    fn collection(&self, index: usize) -> Option<&str> {
        self.collection_ids.get(index).map(String::as_str)
    }
}
/// Owned identifiers and collection rows survive all subsequent Store calls.
pub struct SourceAccess {
    canonical_org: Option<String>,
    records: Vec<CipherSharingCollection<String>>,
}
impl CipherCollectionAccessData for SourceAccess {
    fn len(&self) -> usize {
        self.records.len()
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        self.records
            .get(index)
            .map(|row| CipherCollectionAccessRecord {
                cipher_organization_id: self.canonical_org.as_deref(),
                collection: row.view(),
            })
    }
}
fn recheck_source(
    db: &Connection,
    user: &str,
    id: &str,
    revision: &str,
    owner: Option<&str>,
    org: Option<&str>,
) -> rusqlite::Result<()> {
    let source = sharing::source(db, id)?.ok_or(rusqlite::Error::InvalidQuery)?;
    if source.revision != revision
        || source.owner_id.as_deref() != owner
        || source.organization_id.as_deref() != org
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let member = match org {
        Some(org) => sharing::membership(db, user, org)?,
        None => None,
    };
    let rows = sharing::associated_collections(db, user, id)?;
    let writable = resolve_bulk_cipher_source_write_access(
        user,
        source
            .ownership()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        member.as_ref().map(CipherSharingMembership::view),
        &sharing::AccessData {
            cipher_org: org,
            records: &rows,
        },
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if !writable {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
impl OrganizationCipherBulkSharingStorage for Store {
    type BulkId = String;
    type SourceAccess = SourceAccess;
    fn bulk_sharing_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        sharing::source(&self.db, id)
    }
    fn bulk_sharing_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        sharing::membership(&self.db, user, org)
    }
    fn bulk_source_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<String>,
    ) -> rusqlite::Result<SourceAccess> {
        Ok(SourceAccess {
            canonical_org: source.organization_id.clone(),
            records: sharing::associated_collections(&self.db, user, &source.id)?,
        })
    }
    fn bulk_sharing_collection(
        &mut self,
        user: &str,
        org: &str,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingCollection<String>>> {
        sharing::selected_collection(&self.db, user, org, id)
    }
    fn associate_bulk_sharing_collection<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        p: &ValidatedCipherBulkShareAssociation<'_, D>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        recheck_source(
            &tx,
            p.owner(),
            p.cipher_id(),
            p.source_revision(),
            p.source_owner(),
            p.source_organization(),
        )?;
        sharing::recheck_target(
            &tx,
            p.owner(),
            p.target_organization(),
            Some(p.collection_id()),
        )?;
        tx.execute("INSERT OR IGNORE INTO organization_collection_ciphers(collection_id,cipher_id) VALUES(?1,?2)",params![p.collection_id(),p.cipher_id()])?;
        sharing::advance(
            &tx,
            p.owner(),
            Some(p.target_organization()),
            Some(p.collection_id()),
        )?;
        tx.commit()
    }
    fn commit_cipher_bulk_share<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        p: &ValidatedCipherBulkShare<'_, D>,
    ) -> rusqlite::Result<()> {
        let mut doc = self
            .pending
            .get("ciphers")
            .and_then(|v| v.get(p.index()))
            .cloned()
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let item = p
            .request()
            .cipher(p.index())
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let typed = CipherBulkShareItemRequest::deserialize(&doc)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if typed.id != Some(p.cipher_id())
            || typed.kind != item.cipher_type
            || typed.name != item.name
            || typed.organization_id != p.target_organization()
            || typed.folder_id != item.folder_id
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let requested_favorite = typed.favorite;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        recheck_source(
            &tx,
            p.owner(),
            p.cipher_id(),
            p.source_revision(),
            p.source_owner(),
            p.source_organization(),
        )?;
        if let Some(org) = p.target_organization() {
            // Recheck each exact selected destination; an unrelated associated
            // writable grant cannot authorize a newly readonly selection.
            for i in 0..p.request().collections_len() {
                let id = p
                    .request()
                    .collection(i)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                sharing::recheck_target(&tx, p.owner(), org, Some(id))?;
            }
        }
        if let Some(folder) = item.folder_id {
            let present: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE id=?1 AND owner=?2 AND kind='folder')",
                params![folder, p.owner()],
                |r| r.get(0),
            )?;
            if !present {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let original: String = tx.query_row(
            "SELECT document FROM items WHERE id=?1",
            [p.cipher_id()],
            |r| r.get(0),
        )?;
        let original: Value =
            serde_json::from_str(&original).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let favorite = match requested_favorite {
            Some(value) => value,
            None if p.source_organization().is_some() => tx.query_row(
                "SELECT COALESCE((SELECT favorite FROM cipher_annotations WHERE cipher_id=?1 AND user_id=?2),0)",
                params![p.cipher_id(), p.owner()],
                |row| row.get(0),
            )?,
            None => original.get("favorite").and_then(Value::as_bool).unwrap_or(false),
        };
        let revision = store::next_revision(&tx, p.owner())?;
        crate::attachments::rewrap(&tx, p.cipher_id(), &doc)?;
        let fields = doc.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
        for key in ["lastKnownRevisionDate", "attachments2"] {
            fields.remove(key);
        }
        doc["id"] = json!(p.cipher_id());
        doc["object"] = json!("cipherDetails");
        doc["organizationId"] = json!(p.target_organization());
        doc["creationDate"] = original["creationDate"].clone();
        doc["deletedDate"] = original["deletedDate"].clone();
        doc["revisionDate"] = json!(revision);
        doc["favorite"] = json!(favorite);
        if p.target_organization().is_some() {
            tx.execute("INSERT INTO cipher_annotations(cipher_id,user_id,folder_id,favorite) VALUES(?1,?2,?3,?4) ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite",params![p.cipher_id(),p.owner(),item.folder_id,favorite])?;
            doc["folderId"] = Value::Null;
            doc["favorite"] = json!(false);
            doc["archivedDate"] = Value::Null;
        }
        let owner = p.target_organization().is_none().then_some(p.owner());
        let changed=tx.execute("UPDATE items SET owner=?1,organization_id=?2,document=?3,revision=?4 WHERE id=?5 AND revision=?6 AND owner IS ?7 AND organization_id IS ?8",params![owner,p.target_organization(),doc.to_string(),revision,p.cipher_id(),p.source_revision(),p.source_owner(),p.source_organization()])?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        sharing::advance_cipher(&tx, p.owner(), p.cipher_id(), p.target_organization())?;
        tx.commit()
    }
}
#[cfg(test)]
mod tests;
