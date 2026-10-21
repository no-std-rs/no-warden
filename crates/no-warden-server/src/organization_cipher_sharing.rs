//! Opaque cipher sharing persistence and viewer-specific response projections.
use crate::{Failure, Store, json_guard_error, store};
use axum::http::StatusCode;
use no_warden::{
    VaultService,
    organization_cipher_sharing::{
        CipherAccessSnapshot, CipherCollectionAccessData, CipherCollectionAccessRecord,
        CipherOwnership, CipherShareIdsData, CipherSharingCollection, CipherSharingMembership,
        CipherSharingSource, OrganizationCipherSharingStorage, ValidatedCipherShare,
        ValidatedCipherShareAssociation, resolve_cipher_access,
    },
    wire::CipherRequest,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use serde_json::{Value, json};

fn schema_error(error: serde_json::Error) -> Failure {
    let failure = json_guard_error(error);
    if failure.0 == StatusCode::UNPROCESSABLE_ENTITY {
        Failure(failure.0, "Invalid cipher sharing request")
    } else {
        failure
    }
}

// Each selected ID can commit a transaction and advance viewer revisions.
// Bound host work during decoding, before the first association can mutate state.
const MAX_SHARE_COLLECTION_IDS: usize = 4096;

fn deserialize_collection_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct CollectionIds;
    impl<'de> Visitor<'de> for CollectionIds {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("collection IDs within the host selection budget")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
            let mut ids = Vec::new();
            loop {
                if ids.len() == MAX_SHARE_COLLECTION_IDS {
                    return if sequence.next_element::<IgnoredAny>()?.is_some() {
                        Err(de::Error::custom(
                            "Sharing selection exceeds the host item budget",
                        ))
                    } else {
                        Ok(ids)
                    };
                }
                match sequence.next_element::<String>()? {
                    Some(id) => ids.push(id),
                    None => return Ok(ids),
                }
            }
        }
    }
    deserializer.deserialize_seq(CollectionIds)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(
        alias = "CollectionIds",
        deserialize_with = "deserialize_collection_ids"
    )]
    collection_ids: Vec<String>,
    #[serde(alias = "Cipher")]
    cipher: Value,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let input: Self = serde_json::from_slice(body).map_err(schema_error)?;
        // Complete structural decoding precedes every association mutation.
        input.request()?;
        crate::attachments::validate_rewrap(&input.cipher)?;
        Ok(input)
    }
    pub fn request(&self) -> Result<CipherRequest<'_>, Failure> {
        CipherRequest::deserialize(&self.cipher).map_err(schema_error)
    }
    pub fn execute(&self, store: &mut Store, owner: &str, id: &str) -> Result<(), Failure> {
        let request = self.request()?;
        store.pending = self.cipher.clone();
        let result = VaultService::new(&mut *store).share_cipher(owner, id, &request, self);
        store.pending = Value::Null;
        result.map_err(Into::into)
    }
}
impl CipherShareIdsData for Input {
    fn len(&self) -> usize {
        self.collection_ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.collection_ids.get(index).map(String::as_str)
    }
}

pub(super) fn source(
    db: &Connection,
    id: &str,
) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
    db.query_row(
        "SELECT id,owner,organization_id,revision FROM items WHERE id=?1 AND kind='cipher'",
        [id],
        |row| {
            Ok(CipherSharingSource {
                id: row.get(0)?,
                owner_id: row.get(1)?,
                organization_id: row.get(2)?,
                revision: row.get(3)?,
            })
        },
    )
    .optional()
}
pub(super) fn membership(
    db: &Connection,
    user: &str,
    org: &str,
) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
    db.query_row(
        "SELECT user_id,organization_id,role,status,access_all FROM organization_memberships WHERE user_id=?1 AND organization_id=?2",
        params![user,org],
        |row| Ok(CipherSharingMembership { user_id: row.get(0)?, organization_id: row.get(1)?, role: row.get(2)?, status: row.get(3)?, access_all: row.get(4)? }),
    ).optional()
}
fn collection(row: &rusqlite::Row<'_>) -> rusqlite::Result<CipherSharingCollection<String>> {
    Ok(CipherSharingCollection {
        id: row.get(0)?,
        organization_id: row.get(1)?,
        user_id: row.get(2)?,
        assigned: row.get(3)?,
        read_only: row.get(4)?,
        hide_passwords: row.get(5)?,
        manage: row.get(6)?,
    })
}
const COLLECTION_FACTS: &str = "SELECT c.id,c.organization_id,?1,g.user_id IS NOT NULL,
 COALESCE(g.read_only,1),COALESCE(g.hide_passwords,0),COALESCE(g.manage,0)
 FROM organization_collections c LEFT JOIN organization_collection_users g ON g.collection_id=c.id AND g.user_id=?1";
pub(super) fn selected_collection(
    db: &Connection,
    user: &str,
    org: &str,
    id: &str,
) -> rusqlite::Result<Option<CipherSharingCollection<String>>> {
    db.query_row(
        &format!("{COLLECTION_FACTS} WHERE c.organization_id=?2 AND c.id=?3"),
        params![user, org, id],
        collection,
    )
    .optional()
}
pub(super) fn associated_collections(
    db: &Connection,
    user: &str,
    id: &str,
) -> rusqlite::Result<Vec<CipherSharingCollection<String>>> {
    let mut statement = db.prepare(&format!("{COLLECTION_FACTS} JOIN organization_collection_ciphers l ON l.collection_id=c.id WHERE l.cipher_id=?2 ORDER BY c.rowid"))?;
    statement
        .query_map(params![user, id], collection)?
        .collect()
}
fn mapped(error: no_warden::ApiError) -> rusqlite::Error {
    let _ = error;
    rusqlite::Error::InvalidQuery
}

/// Borrow the canonical cipher scope without changing actual collection facts.
/// Associated links can survive an earlier failed share into another organization.
pub(super) struct AccessData<'a> {
    pub(super) cipher_org: Option<&'a str>,
    pub(super) records: &'a [CipherSharingCollection<String>],
}
impl CipherCollectionAccessData for AccessData<'_> {
    fn len(&self) -> usize {
        self.records.len()
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        self.records
            .get(index)
            .map(|row| CipherCollectionAccessRecord {
                cipher_organization_id: self.cipher_org,
                collection: row.view(),
            })
    }
}

/// Resolve the same trusted core decisions for ordinary reads and list/sync.
pub fn access(
    db: &Connection,
    user: &str,
    id: &str,
) -> rusqlite::Result<Option<CipherAccessSnapshot>> {
    let Some(source) = source(db, id)? else {
        return Ok(None);
    };
    let membership = match source.organization_id.as_deref() {
        Some(org) => membership(db, user, org)?,
        None => None,
    };
    let collections = associated_collections(db, user, id)?;
    resolve_cipher_access(
        user,
        source.ownership().map_err(mapped)?,
        membership.as_ref().map(CipherSharingMembership::view),
        &AccessData {
            cipher_org: source.organization_id.as_deref(),
            records: &collections,
        },
    )
    .map(Some)
    .map_err(mapped)
}

pub fn project(
    db: &Connection,
    user: &str,
    id: &str,
    single: bool,
) -> rusqlite::Result<Option<Value>> {
    let Some(source) = source(db, id)? else {
        return Ok(None);
    };
    let membership = match source.organization_id.as_deref() {
        Some(org) => membership(db, user, org)?,
        None => None,
    };
    let collections = associated_collections(db, user, id)?;
    let ids_all: Vec<String> = collections.iter().map(|row| row.id.clone()).collect();
    let access = resolve_cipher_access(
        user,
        source.ownership().map_err(mapped)?,
        membership.as_ref().map(CipherSharingMembership::view),
        &AccessData {
            cipher_org: source.organization_id.as_deref(),
            records: &collections,
        },
    )
    .map_err(mapped)?;
    if !access.readable() {
        return Ok(None);
    }
    let text: String = db.query_row(
        "SELECT document FROM items WHERE id=?1 AND kind='cipher'",
        [id],
        |r| r.get(0),
    )?;
    let mut doc: Value = serde_json::from_str(&text).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let fields = doc.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
    for name in [
        "encryptedFor",
        "encryptedByKeyId",
        "lastKnownRevisionDate",
        "attachments2",
    ] {
        fields.remove(name);
    }
    for name in [
        "archivedDate",
        "attachments",
        "bankAccount",
        "card",
        "deletedDate",
        "driversLicense",
        "fields",
        "folderId",
        "identity",
        "key",
        "login",
        "notes",
        "passport",
        "passwordHistory",
        "secureNote",
        "sshKey",
    ] {
        fields.entry(name).or_insert(Value::Null);
    }
    fields.entry("reprompt").or_insert(json!(0));
    fields.entry("favorite").or_insert(json!(false));
    doc["object"] = json!("cipherDetails");
    let full = source.owner_id.is_some()
        || membership
            .as_ref()
            .is_some_and(CipherSharingMembership::full_access);
    let ids: Vec<&str> = if full {
        ids_all.iter().map(String::as_str).collect()
    } else {
        collections
            .iter()
            .filter(|row| row.assigned && (!single || !row.read_only))
            .map(|row| row.id.as_str())
            .collect()
    };
    doc["id"] = json!(id);
    doc["organizationId"] = source
        .organization_id
        .as_deref()
        .map_or(Value::Null, |org| json!(org));
    doc["collectionIds"] = json!(ids);
    doc["edit"] = json!(access.writable());
    doc["viewPassword"] = json!(access.view_password());
    doc["permissions"] = json!({"delete":access.delete(),"restore":access.restore()});
    // Actual default-configuration personal and shared projections both expose
    // this capability, including accounts without any organization membership.
    doc["organizationUseTotp"] = json!(true);
    if source.organization_id.is_some() {
        let annotation: Option<(Option<String>,bool)> = db.query_row("SELECT folder_id,favorite FROM cipher_annotations WHERE cipher_id=?1 AND user_id=?2",params![id,user],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (folder, favorite) = annotation.unwrap_or((None, false));
        doc["folderId"] = json!(folder);
        doc["favorite"] = json!(favorite);
        doc["archivedDate"] = Value::Null;
    }
    if let Some(archived) = db
        .query_row(
            "SELECT archived_at FROM cipher_archives WHERE cipher_id=?1 AND owner=?2",
            params![id, user],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
    {
        doc["archivedDate"] = json!(archived);
    }
    if source.organization_id.is_some() {
        // Native shared projections expose these known response fields while
        // the stored opaque document retains every submitted extension. Keep
        // the personal path's established unknown-field round trips intact.
        const FIELDS: [&str; 30] = [
            "archivedDate",
            "attachments",
            "bankAccount",
            "card",
            "collectionIds",
            "creationDate",
            "deletedDate",
            "driversLicense",
            "edit",
            "favorite",
            "fields",
            "folderId",
            "id",
            "identity",
            "key",
            "login",
            "name",
            "notes",
            "object",
            "organizationId",
            "organizationUseTotp",
            "passport",
            "passwordHistory",
            "permissions",
            "reprompt",
            "revisionDate",
            "secureNote",
            "sshKey",
            "type",
            "viewPassword",
        ];
        if doc["type"] == 2 && !doc["secureNote"].is_null() {
            let subtype = doc["secureNote"]
                .get("type")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if let Some(fields) = doc["secureNote"].as_object_mut() {
                fields.insert("type".to_owned(), json!(subtype));
            } else {
                doc["secureNote"] = json!({"type":subtype});
            }
        }
        doc.as_object_mut()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .retain(|name, _| FIELDS.contains(&name.as_str()));
    }
    Ok(Some(doc))
}

pub fn list(db: &Connection, user: &str) -> rusqlite::Result<Vec<Value>> {
    // The core independently checks every candidate's membership and collection
    // facts; a SQL join cannot confer access or duplicate an item in the response.
    let ids = {
        let mut statement = db.prepare("SELECT id FROM items WHERE kind='cipher' AND (owner=?1 OR organization_id IS NOT NULL) ORDER BY rowid")?;
        statement
            .query_map([user], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut rows = Vec::new();
    for id in ids {
        if let Some(row) = project(db, user, &id, false)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn recheck_source(db: &Connection, user: &str, id: &str, revision: &str) -> rusqlite::Result<()> {
    let source = source(db, id)?.ok_or(rusqlite::Error::InvalidQuery)?;
    if source.revision != revision
        || !matches!(source.ownership().map_err(mapped)?, CipherOwnership::Personal{user_id} if user_id==user)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
pub(super) fn recheck_target(
    db: &Connection,
    user: &str,
    org: &str,
    selected: Option<&str>,
) -> rusqlite::Result<()> {
    let member = membership(db, user, org)?;
    let rows = match selected {
        Some(id) => {
            vec![selected_collection(db, user, org, id)?.ok_or(rusqlite::Error::InvalidQuery)?]
        }
        None => Vec::new(),
    };
    let access = resolve_cipher_access(
        user,
        CipherOwnership::Organization {
            organization_id: org,
        },
        member.as_ref().map(CipherSharingMembership::view),
        &AccessData {
            cipher_org: Some(org),
            records: &rows,
        },
    )
    .map_err(mapped)?;
    if !access.writable() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
pub(super) fn advance(
    db: &Connection,
    user: &str,
    org: Option<&str>,
    collection: Option<&str>,
) -> rusqlite::Result<()> {
    let mut users = vec![user.to_owned()];
    if let Some(org) = org {
        let mut statement=db.prepare("SELECT user_id FROM organization_memberships WHERE organization_id=?1 AND access_all=1 UNION SELECT g.user_id FROM organization_collection_users g JOIN organization_collections c ON c.id=g.collection_id WHERE c.organization_id=?1 AND (?2 IS NULL OR c.id=?2)")?;
        users.extend(
            statement
                .query_map(params![org, collection], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    users.sort();
    users.dedup();
    for user in users {
        let revision = store::next_revision(db, &user)?;
        store::bump(db, &user, &revision)?;
    }
    Ok(())
}

// Final ownership changes notify only current readers in the canonical scope.
// Historical links can contribute a grant after confirmed membership is checked;
// a grant in the old organization alone does not admit its account here.
pub(super) fn advance_cipher(
    db: &Connection,
    caller: &str,
    cipher: &str,
    org: Option<&str>,
) -> rusqlite::Result<()> {
    let mut users = vec![caller.to_owned()];
    if let Some(org) = org {
        let mut statement =
            db.prepare("SELECT user_id FROM organization_memberships WHERE organization_id=?1")?;
        users.extend(
            statement
                .query_map([org], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    users.sort();
    users.dedup();
    for user in users {
        if access(db, &user, cipher)?.is_some_and(CipherAccessSnapshot::readable) {
            let revision = store::next_revision(db, &user)?;
            store::bump(db, &user, &revision)?;
        }
    }
    Ok(())
}

impl OrganizationCipherSharingStorage for Store {
    type ShareId = String;
    fn sharing_source(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
        source(&self.db, id)
    }
    fn sharing_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> rusqlite::Result<Option<CipherSharingMembership<String>>> {
        membership(&self.db, user, org)
    }
    fn sharing_collection(
        &mut self,
        user: &str,
        org: &str,
        id: &str,
    ) -> rusqlite::Result<Option<CipherSharingCollection<String>>> {
        selected_collection(&self.db, user, org, id)
    }
    fn associate_sharing_collection(
        &mut self,
        plan: &ValidatedCipherShareAssociation<'_>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        recheck_source(&tx, plan.owner(), plan.cipher_id(), plan.source_revision())?;
        recheck_target(
            &tx,
            plan.owner(),
            plan.target_organization(),
            Some(plan.collection_id()),
        )?;
        tx.execute("INSERT OR IGNORE INTO organization_collection_ciphers(collection_id,cipher_id) VALUES(?1,?2)",params![plan.collection_id(),plan.cipher_id()])?;
        advance(
            &tx,
            plan.owner(),
            Some(plan.target_organization()),
            Some(plan.collection_id()),
        )?;
        tx.commit()
    }
    fn commit_cipher_share(&mut self, plan: &ValidatedCipherShare<'_, '_>) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        recheck_source(&tx, plan.owner(), plan.cipher_id(), plan.source_revision())?;
        if let Some(org) = plan.target_organization() {
            let member = membership(&tx, plan.owner(), org)?;
            let rows = associated_collections(&tx, plan.owner(), plan.cipher_id())?;
            let access = resolve_cipher_access(
                plan.owner(),
                CipherOwnership::Organization {
                    organization_id: org,
                },
                member.as_ref().map(CipherSharingMembership::view),
                &AccessData {
                    cipher_org: Some(org),
                    records: &rows,
                },
            )
            .map_err(mapped)?;
            if !access.writable() {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let original: String = tx.query_row(
            "SELECT document FROM items WHERE id=?1",
            [plan.cipher_id()],
            |r| r.get(0),
        )?;
        let original: Value =
            serde_json::from_str(&original).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let revision = store::next_revision(&tx, plan.owner())?;
        let mut doc = self.pending.clone();
        let fields = doc.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
        fields.remove("lastKnownRevisionDate");
        fields.remove("attachments2");
        doc["id"] = json!(plan.cipher_id());
        doc["object"] = json!("cipherDetails");
        doc["organizationId"] = json!(plan.target_organization());
        doc["creationDate"] = original["creationDate"].clone();
        doc["deletedDate"] = original["deletedDate"].clone();
        doc["revisionDate"] = json!(revision);
        crate::attachments::rewrap(&tx, plan.cipher_id(), &self.pending)?;
        if plan.target_organization().is_some() {
            tx.execute("INSERT INTO cipher_annotations(cipher_id,user_id,folder_id,favorite) VALUES(?1,?2,?3,?4) ON CONFLICT(cipher_id,user_id) DO UPDATE SET folder_id=excluded.folder_id,favorite=excluded.favorite",params![plan.cipher_id(),plan.owner(),plan.request().folder_id,plan.request().favorite])?;
            doc["folderId"] = Value::Null;
            doc["favorite"] = json!(false);
            doc["archivedDate"] = Value::Null;
        }
        let owner = if plan.target_organization().is_some() {
            None
        } else {
            Some(plan.owner())
        };
        let changed=tx.execute("UPDATE items SET owner=?1,organization_id=?2,document=?3,revision=?4 WHERE id=?5 AND owner=?6 AND revision=?7",params![owner,plan.target_organization(),doc.to_string(),revision,plan.cipher_id(),plan.owner(),plan.source_revision()])?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        advance_cipher(
            &tx,
            plan.owner(),
            plan.cipher_id(),
            plan.target_organization(),
        )?;
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_selection_budget_precedes_every_association_mutation() {
        let mut consumed = 0;
        let ids = std::iter::repeat_n("", 5_000_000).inspect(|_| consumed += 1);
        let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(ids);
        assert!(deserialize_collection_ids(decoder).is_err());
        assert_eq!(consumed, MAX_SHARE_COLLECTION_IDS + 1);
        let cipher = json!({"type":2,"name":"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","secureNote":{"type":0}});
        let at_limit = serde_json::to_vec(
            &json!({"collectionIds":vec!["";MAX_SHARE_COLLECTION_IDS],"cipher":cipher}),
        )
        .unwrap();
        let input =
            Input::parse(&at_limit).unwrap_or_else(|_| panic!("Host selection boundary rejected"));
        assert_eq!(input.len(), MAX_SHARE_COLLECTION_IDS);
        let over_limit = serde_json::to_vec(
            &json!({"CollectionIds":vec!["";MAX_SHARE_COLLECTION_IDS+1],"Cipher":cipher}),
        )
        .unwrap();
        let failure = Input::parse(&over_limit)
            .err()
            .expect("Host selection budget must reject before execution");
        assert_eq!(failure.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(failure.1, "Invalid cipher sharing request");
    }
}
