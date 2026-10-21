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
        if !self.cipher.is_object() {
            return Err(Failure(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid cipher sharing request",
            ));
        }
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

fn source(db: &Connection, id: &str) -> rusqlite::Result<Option<CipherSharingSource<String>>> {
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
fn membership(
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
fn selected_collection(
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
fn associated_collections_sql() -> String {
    format!(
        "{COLLECTION_FACTS} JOIN organization_collection_ciphers l ON l.collection_id=c.id WHERE l.cipher_id=?2 ORDER BY c.rowid"
    )
}

fn associated_collections(
    db: &Connection,
    user: &str,
    id: &str,
) -> rusqlite::Result<Vec<CipherSharingCollection<String>>> {
    let mut statement = db.prepare(&associated_collections_sql())?;
    statement
        .query_map(params![user, id], collection)?
        .collect()
}

// Route projections omit grants from an inactive historical membership. This
// does not change read admission: native single GET still admits the surviving
// grant when membership in the cipher's canonical organization is confirmed.
fn visible_collections(
    db: &Connection,
    user: &str,
    id: &str,
) -> rusqlite::Result<Vec<CipherSharingCollection<String>>> {
    let mut statement = db.prepare(&format!(
        "{COLLECTION_FACTS} JOIN organization_collection_ciphers l ON l.collection_id=c.id
         JOIN organization_memberships m ON m.organization_id=c.organization_id AND m.user_id=?1
         WHERE l.cipher_id=?2 AND m.status=2 ORDER BY c.rowid"
    ))?;
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
struct AccessData<'a> {
    cipher_org: Option<&'a str>,
    records: &'a [CipherSharingCollection<String>],
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
    let visible = if full {
        collections
    } else {
        visible_collections(db, user, id)?
    };
    // A single GET keeps native's unfiltered grant flags. List/sync instead
    // project permissions from the viewer's currently visible collections.
    let permissions = if single || full {
        access
    } else {
        resolve_cipher_access(
            user,
            source.ownership().map_err(mapped)?,
            membership.as_ref().map(CipherSharingMembership::view),
            &AccessData {
                cipher_org: source.organization_id.as_deref(),
                records: &visible,
            },
        )
        .map_err(mapped)?
    };
    let ids: Vec<&str> = if full {
        visible.iter().map(|row| row.id.as_str()).collect()
    } else {
        visible
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
    doc["edit"] = json!(permissions.writable());
    doc["viewPassword"] = json!(permissions.view_password());
    doc["permissions"] = json!({"delete":permissions.delete(),"restore":permissions.restore()});
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
    Ok(Some(doc))
}

// Bound candidate materialization to personal ownership and canonical membership
// scopes with confirmed membership. Historical collection associations do not
// choose the canonical scope; core status and grant checks still decide access.
fn candidate_ids(db: &Connection, user: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = db.prepare("SELECT id FROM items WHERE kind='cipher' AND (owner=?1 OR organization_id IN (SELECT organization_id FROM organization_memberships WHERE user_id=?1 AND status=2)) ORDER BY rowid")?;
    statement
        .query_map([user], |row| row.get::<_, String>(0))?
        .collect()
}

pub fn list(db: &Connection, user: &str) -> rusqlite::Result<Vec<Value>> {
    // The core independently checks every candidate's membership and collection
    // facts; a SQL join cannot confer access or duplicate an item in the response.
    let ids = candidate_ids(db, user)?;
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
fn recheck_target(
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
fn advance(
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
fn advance_cipher(
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
    fn sharing_revision_is_older(
        &mut self,
        source: &CipherSharingSource<String>,
        requested: &str,
    ) -> rusqlite::Result<bool> {
        let current = chrono::DateTime::parse_from_rfc3339(&source.revision)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(chrono::DateTime::parse_from_rfc3339(requested)
            .ok()
            .is_some_and(|requested| requested < current))
    }
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
            // Historical links remain readable after a successful move, but
            // cannot replace live authority to write into its destination.
            let mut rows = associated_collections(&tx, plan.owner(), plan.cipher_id())?;
            rows.retain(|row| row.organization_id == org);
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
        } else if let Some(archived_at) = store::archive_value(&self.pending) {
            store::save_archive(&tx, plan.owner(), plan.cipher_id(), archived_at.as_deref())?;
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
mod archive_review_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod shape_review_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const REVISION: &str = "2026-01-01T00:00:00.000Z";

    #[test]
    fn final_share_rechecks_target_grants_without_using_historical_authority() {
        for revoke in [
            "DELETE FROM organization_collection_users WHERE collection_id='target' AND user_id='alice';",
            "UPDATE organization_collection_users SET read_only=1 WHERE collection_id='target' AND user_id='alice';",
        ] {
            let mut store = Store::open(":memory:").unwrap();
            store.db.execute_batch(
                "INSERT INTO accounts VALUES('alice','alice@example.test','{}','test','2026-01-01T00:00:00.000Z'),('bob','bob@example.test','{}','test','2026-01-01T00:00:00.000Z');
                 INSERT INTO organizations(id,name,billing_email) VALUES('old-org','old','old@example.test'),('target-org','target','target@example.test');
                 INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) VALUES('alice-old','old-org','alice','opaque',2,2,0),('alice-target','target-org','alice','opaque',2,2,0),('bob-old','old-org','bob','opaque',2,2,0),('bob-target','target-org','bob','opaque',2,2,0);
                 INSERT INTO organization_collections(id,organization_id,name) VALUES('old','old-org','opaque'),('target','target-org','opaque');
                 INSERT INTO organization_collection_users VALUES('old','alice',0,0,0),('target','alice',0,0,0),('old','bob',0,0,0);",
            ).unwrap();
            let original = json!({"id":"cipher","type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"secureNote":{"type":0},"key":null,"favorite":true,"folderId":null,"creationDate":REVISION,"revisionDate":REVISION,"organizationId":null});
            store.db.execute(
                "INSERT INTO items(id,owner,kind,document,revision,created) VALUES('cipher','alice','cipher',?1,?2,?2)",
                params![original.to_string(),REVISION],
            ).unwrap();
            let input = |org: &str, ids: &[&str]| {
                let mut document = original.clone();
                document["organizationId"] = json!(org);
                document["encryptedFor"] = json!("alice");
                document["lastKnownRevisionDate"] = json!(REVISION);
                Input::parse(
                    &serde_json::to_vec(&json!({"collectionIds":ids,"cipher":document})).unwrap(),
                )
                .unwrap_or_else(|_| panic!("Valid sharing fixture rejected"))
            };
            // An earlier failed move leaves a real, independently writable
            // historical association while the cipher is still personal.
            assert!(
                input("old-org", &["old", "missing"])
                    .execute(&mut store, "alice", "cipher")
                    .is_err()
            );
            let before: (String, String) = store
                .db
                .query_row(
                    "SELECT document,revision FROM items WHERE id='cipher'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            let account_before: String = store
                .db
                .query_row("SELECT revision FROM accounts WHERE id='alice'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            // This committed association-side effect changes permission before
            // the separate final transaction, without a timing-dependent test.
            store.db.execute_batch(&format!(
                "CREATE TRIGGER revoke_target_after_association AFTER UPDATE OF revision ON accounts WHEN NEW.id='alice' BEGIN {revoke} END;"
            )).unwrap();
            assert!(
                input("target-org", &["target"])
                    .execute(&mut store, "alice", "cipher")
                    .is_err(),
                "Historical grants must not replace revoked destination authority in the final transaction"
            );
            let after: (Option<String>, Option<String>, String, String) = store
                .db
                .query_row(
                    "SELECT owner,organization_id,document,revision FROM items WHERE id='cipher'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(after, (Some("alice".into()), None, before.0, before.1));
            assert_eq!(store.db.query_row("SELECT count(*) FROM organization_collection_ciphers WHERE cipher_id='cipher'",[],|r|r.get::<_,usize>(0)).unwrap(),2);
            assert_eq!(
                store
                    .db
                    .query_row(
                        "SELECT count(*) FROM cipher_annotations WHERE cipher_id='cipher'",
                        [],
                        |r| r.get::<_, usize>(0)
                    )
                    .unwrap(),
                0
            );
            assert_ne!(
                store
                    .db
                    .query_row("SELECT revision FROM accounts WHERE id='alice'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .unwrap(),
                account_before
            );
            // Restoring actual destination authority permits retry. Historical
            // access for another confirmed canonical member remains intact.
            store.db.execute_batch("DROP TRIGGER revoke_target_after_association;
                INSERT INTO organization_collection_users VALUES('target','alice',0,0,0) ON CONFLICT(collection_id,user_id) DO UPDATE SET read_only=0;").unwrap();
            assert!(
                input("target-org", &["target"])
                    .execute(&mut store, "alice", "cipher")
                    .is_ok()
            );
            let bob = project(&store.db, "bob", "cipher", true).unwrap().unwrap();
            assert_eq!(bob["organizationId"], "target-org");
            assert_eq!(bob["collectionIds"], json!(["old"]));
            assert_eq!(bob["edit"], true);
        }
    }

    #[test]
    fn list_candidates_are_canonical_membership_scoped_and_core_checks_still_apply() {
        let store = Store::open(":memory:").unwrap();
        store.db.execute_batch(
            "INSERT INTO accounts VALUES('alice','alice@example.test','{}','test','2026-01-01T00:00:00.000Z'),('bob','bob@example.test','{}','test','2026-01-01T00:00:00.000Z');
             INSERT INTO organizations(id,name,billing_email) VALUES('historical','old','old@example.test'),('canonical','current','current@example.test'),('accepted','accepted','accepted@example.test'),('revoked','revoked','revoked@example.test'),('invited','invited','invited@example.test'),('foreign','foreign','foreign@example.test');
             INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) VALUES('old-member','historical','alice','opaque',2,2,0),('current-member','canonical','alice','opaque',2,2,0),('accepted-member','accepted','alice','opaque',2,1,1),('revoked-member','revoked','alice','opaque',2,-1,1),('invited-member','invited','alice','opaque',2,0,1);
             INSERT INTO organization_collections(id,organization_id,name) VALUES('old-collection','historical','opaque');
             INSERT INTO organization_collection_users VALUES('old-collection','alice',0,0,0);",
        ).unwrap();
        for (id, owner, org, kind) in [
            ("personal", Some("alice"), None, "cipher"),
            ("other-personal", Some("bob"), None, "cipher"),
            ("historical-grant", None, Some("canonical"), "cipher"),
            ("ungranted", None, Some("canonical"), "cipher"),
            ("accepted-cipher", None, Some("accepted"), "cipher"),
            ("revoked-cipher", None, Some("revoked"), "cipher"),
            ("invited-cipher", None, Some("invited"), "cipher"),
            ("foreign-with-old-link", None, Some("foreign"), "cipher"),
            ("personal-folder", Some("alice"), None, "folder"),
        ] {
            let document = json!({"id":id,"type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"secureNote":{"type":0},"organizationId":org,"creationDate":REVISION,"revisionDate":REVISION});
            store.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,?3,?4,?5,?6,?6)",params![id,owner,org,kind,document.to_string(),REVISION]).unwrap();
        }
        // Existing historical associations never turn their organization into
        // the canonical candidate scope, in either direction.
        store.db.execute_batch("INSERT INTO organization_collection_ciphers VALUES('old-collection','historical-grant'),('old-collection','foreign-with-old-link');
            WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<100) INSERT INTO items(id,owner,organization_id,kind,document,revision,created) SELECT 'unrelated-'||v,NULL,'foreign','cipher','{}','r','r' FROM n;").unwrap();
        assert_eq!(
            candidate_ids(&store.db, "alice").unwrap(),
            ["personal", "historical-grant", "ungranted"]
        );
        // Confirmed membership bounds materialization, while core decisions still
        // reject ungranted sources and independently verify current status.
        for id in ["accepted-cipher", "revoked-cipher", "invited-cipher"] {
            assert!(project(&store.db, "alice", id, false).unwrap().is_none());
        }
        let rows = list(&store.db, "alice").unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["personal", "historical-grant"]
        );
        assert_eq!(rows[1]["organizationId"], "canonical");
        assert_eq!(rows[1]["collectionIds"], json!(["old-collection"]));
        assert_eq!(rows[1]["edit"], true);
    }

    #[test]
    fn cipher_associations_are_indexed_on_new_and_existing_stores() {
        let store = Store::open(":memory:").unwrap();
        store.db.execute_batch(
            "INSERT INTO accounts VALUES('alice','alice@example.test','{}','test','2026-01-01T00:00:00.000Z');
             INSERT INTO organizations(id,name,billing_email) VALUES('org','opaque','org@example.test');
             WITH RECURSIVE n(v) AS (VALUES(0) UNION ALL SELECT v+1 FROM n WHERE v<1000)
             INSERT INTO items(id,owner,organization_id,kind,document,revision,created) SELECT 'cipher-'||v,NULL,'org','cipher','{}','r','r' FROM n;
             INSERT INTO organization_collections(id,organization_id,name) SELECT 'collection-'||id,'org','opaque' FROM items;
             INSERT INTO organization_collection_ciphers SELECT 'collection-'||id,id FROM items;",
        ).unwrap();
        let lookup = || {
            let mut statement = store.db.prepare(&associated_collections_sql()).unwrap();
            let ids = statement
                .query_map(params!["alice", "cipher-0"], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ids, ["collection-cipher-0"]);
            statement.get_status(rusqlite::StatementStatus::FullscanStep)
        };
        assert_eq!(
            lookup(),
            0,
            "new stores must avoid scanning unrelated associations"
        );
        // Recreate a pre-index nonempty store, then run the same idempotent
        // initialization used on reopening it. Existing links remain intact.
        store
            .db
            .execute_batch("DROP INDEX organization_collection_ciphers_cipher")
            .unwrap();
        assert!(lookup() >= 1000);
        for _ in 0..2 {
            store
                .db
                .execute_batch(crate::organization_collections::SCHEMA)
                .unwrap();
            assert_eq!(lookup(), 0);
            assert_eq!(
                store
                    .db
                    .query_row(
                        "SELECT count(*) FROM organization_collection_ciphers",
                        [],
                        |r| r.get::<_, usize>(0)
                    )
                    .unwrap(),
                1001
            );
        }
    }

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
