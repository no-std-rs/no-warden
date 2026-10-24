//! Independently authored default-policy member editing and ordered grant writes.
use crate::{Failure, Store, password_login};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    organization_member_update::OrganizationMemberUpdateData,
    wire::{OrganizationInviteCollection, OrganizationInvitePermissions, OrganizationInviteRole},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_MEMBER_UPDATE_SELECTIONS: usize = 4096;
struct Selections<T>(Vec<T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Selections<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Items<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Items<T> {
            type Value = Selections<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("member selections within the host work budget")
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let mut items = Vec::new();
                loop {
                    if items.len() == MAX_MEMBER_UPDATE_SELECTIONS {
                        return if sequence.next_element::<IgnoredAny>()?.is_some() {
                            Err(de::Error::custom(
                                "Member update exceeds the host work budget",
                            ))
                        } else {
                            Ok(Selections(items))
                        };
                    }
                    match sequence.next_element::<T>()? {
                        Some(item) => items.push(item),
                        None => return Ok(Selections(items)),
                    }
                }
            }
        }
        deserializer.deserialize_seq(Items(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Role {
    Integer(i64),
    String(String),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    id: String,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(rename = "type")]
    role: Role,
    collections: Option<Selections<Selection>>,
    groups: Option<Selections<String>>,
    #[serde(default)]
    permissions: BTreeMap<String, Value>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(crate::json_guard_error)
    }
}
impl OrganizationMemberUpdateData for Input {
    fn role(&self) -> OrganizationInviteRole<'_> {
        match &self.role {
            Role::Integer(value) => OrganizationInviteRole::Integer(*value),
            Role::String(value) => OrganizationInviteRole::String(value),
        }
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        OrganizationInvitePermissions {
            create_new_collections: self.permissions.get("createNewCollections")
                == Some(&Value::Bool(true)),
            edit_any_collection: self.permissions.get("editAnyCollection")
                == Some(&Value::Bool(true)),
            delete_any_collection: self.permissions.get("deleteAnyCollection")
                == Some(&Value::Bool(true)),
        }
    }
    fn collections_len(&self) -> usize {
        self.collections.as_ref().map_or(0, |items| items.0.len())
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        self.collections
            .as_ref()?
            .0
            .get(index)
            .map(|selection| OrganizationInviteCollection {
                id: &selection.id,
                read_only: selection.read_only,
                hide_passwords: selection.hide_passwords,
                manage: selection.manage,
            })
    }
    fn groups_len(&self) -> usize {
        self.groups.as_ref().map_or(0, |items| items.0.len())
    }
    fn group(&self, index: usize) -> Option<&str> {
        self.groups.as_ref()?.0.get(index).map(String::as_str)
    }
}

/// Preserve internal guard errors; apply this route's observed envelope at the
/// socket boundary, including authentication failures before dispatch enters it.
pub fn error_response(error: Failure) -> Response {
    match error.0 {
        StatusCode::BAD_REQUEST if error.1 != "Invalid request" => {
            password_login::error_response(error.0, error.1)
        }
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::UNPROCESSABLE_ENTITY => {
            (error.0, Json(json!({"error":"Invalid request"}))).into_response()
        }
        _ => error.into_response(),
    }
}

use no_warden::organization_member_update::{
    OrganizationMemberUpdateCollection, OrganizationMemberUpdateRecord,
    OrganizationMemberUpdateStorage, ValidatedOrganizationMemberUpdate,
    ValidatedOrganizationMemberUpdateGrant, ValidatedOrganizationMemberUpdateStart,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

fn current_member(
    db: &Connection,
    organization: &str,
    member: &str,
) -> rusqlite::Result<Option<OrganizationMemberUpdateRecord<String>>> {
    db.query_row(
        "SELECT id,organization_id,user_id,role,status,access_all FROM organization_memberships
         WHERE organization_id=?1 AND id=?2",
        params![organization, member],
        |row| {
            Ok(OrganizationMemberUpdateRecord {
                membership_id: row.get(0)?,
                organization_id: row.get(1)?,
                user_id: row.get(2)?,
                role: row.get(3)?,
                status: row.get(4)?,
                access_all: row.get(5)?,
                // This adapter has no group storage or configurable policies.
                groups_configured: false,
            })
        },
    )
    .optional()
}
fn confirmed_owners(db: &Connection, organization: &str) -> rusqlite::Result<u64> {
    db.query_row("SELECT count(*) FROM organization_memberships WHERE organization_id=?1 AND role=0 AND status=2", [organization], |row| row.get(0))
}
fn check_live(
    db: &Connection,
    plan: &ValidatedOrganizationMemberUpdateStart<'_, String>,
) -> rusqlite::Result<()> {
    let actor: Option<(i32, i32)> = db.query_row(
        "SELECT role,status FROM organization_memberships WHERE organization_id=?1 AND user_id=?2",
        params![plan.organization(), plan.owner()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    if !matches!(actor, Some((role @ (0 | 1), 2)) if role == plan.actor_role()) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let Some(target) = current_member(db, plan.organization(), plan.membership_id())? else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    if target.user_id != plan.user_id()
        || target.role != plan.previous_role()
        || target.status != plan.status()
        || target.access_all != plan.previous_access_all()
        || (plan.actor_role() != 0 && target.role == 0)
        || (plan.actor_role() != 0
            && plan.new_role() != target.role
            && (matches!(target.role, 0 | 1) || matches!(plan.new_role(), 0 | 1)))
        || (plan.requires_other_confirmed_owner()
            && confirmed_owners(db, plan.organization())? <= 1)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
impl OrganizationMemberUpdateStorage for Store {
    type UpdateId = String;
    fn update_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> rusqlite::Result<Option<OrganizationMemberUpdateRecord<String>>> {
        current_member(&self.db, organization, member)
    }
    fn update_confirmed_owner_count(&mut self, organization: &str) -> rusqlite::Result<u64> {
        confirmed_owners(&self.db, organization)
    }
    fn update_collection(
        &mut self,
        organization: &str,
        collection: &str,
    ) -> rusqlite::Result<Option<OrganizationMemberUpdateCollection<String>>> {
        self.db.query_row("SELECT id,organization_id FROM organization_collections WHERE organization_id=?1 AND id=?2", params![organization,collection], |row| Ok(OrganizationMemberUpdateCollection{id:row.get(0)?,organization_id:row.get(1)?})).optional()
    }
    fn begin_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateStart<'_, String>,
    ) -> rusqlite::Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_live(&tx, plan)?;
        tx.execute("DELETE FROM organization_collection_users WHERE user_id=?1 AND collection_id IN (SELECT id FROM organization_collections WHERE organization_id=?2)", params![plan.user_id(),plan.organization()])?;
        let revision = crate::store::next_revision(&tx, plan.user_id())?;
        crate::store::bump(&tx, plan.user_id(), &revision)?;
        tx.commit()
    }
    fn append_member_update_grant(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateGrant<'_, '_, String>,
    ) -> rusqlite::Result<()> {
        let start = plan.start();
        let selection = plan.selection();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_live(&tx, start)?;
        let present: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM organization_collections WHERE organization_id=?1 AND id=?2)", params![start.organization(),selection.id], |row| row.get(0))?;
        if !present || start.new_access_all() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute("INSERT INTO organization_collection_users(collection_id,user_id,read_only,hide_passwords,manage) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection_id,user_id) DO UPDATE SET read_only=excluded.read_only,hide_passwords=excluded.hide_passwords,manage=excluded.manage", params![selection.id,start.user_id(),selection.read_only,selection.hide_passwords,selection.manage])?;
        tx.commit()
    }
    fn finish_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdate<'_, '_, String>,
    ) -> rusqlite::Result<()> {
        let start = plan.start();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_live(&tx, start)?;
        if tx.execute("UPDATE organization_memberships SET role=?1,access_all=?2 WHERE organization_id=?3 AND id=?4 AND user_id=?5 AND role=?6 AND status=?7 AND access_all=?8", params![start.new_role(),start.new_access_all(),start.organization(),start.membership_id(),start.user_id(),start.previous_role(),start.status(),start.previous_access_all()])? != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use no_warden::VaultService;

    fn fixture() -> Store {
        let store = Store::open(":memory:").unwrap();
        store.db.execute_batch(
            "INSERT INTO accounts VALUES('actor','actor@example.test','{}','opaque verifier','2026-01-01T00:00:00Z'),('target','target@example.test','{}','opaque verifier','2026-01-01T00:00:00Z'),('other','other@example.test','{}','opaque verifier','2026-01-01T00:00:00Z');
             INSERT INTO organizations VALUES('org','opaque name','billing@example.test',NULL,NULL),('foreign','opaque name','foreign@example.test',NULL,NULL);
             INSERT INTO organization_memberships VALUES('actor-member','org','actor','actor wrapped key',0,2,1),('target-member','org','target','target wrapped key',2,2,0),('other-member','org','other','other wrapped key',0,2,1);
             INSERT INTO organization_collections VALUES('old','org','opaque old',NULL),('first','org','opaque first',NULL),('second','org','opaque second',NULL),('foreign-collection','foreign','opaque foreign',NULL);
             INSERT INTO organization_collection_users VALUES('old','target',0,0,0);",
        ).unwrap();
        store
    }
    fn request(ids: &[&str]) -> Input {
        let selections: Vec<_> = ids
            .iter()
            .map(|id| json!({"id":id,"readOnly":true,"hidePasswords":false,"manage":true}))
            .collect();
        Input::parse(&serde_json::to_vec(&json!({"type":3,"collections":selections})).unwrap())
            .unwrap_or_else(|_| panic!("Independent fixture request rejected"))
    }
    fn grants(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT collection_id FROM organization_collection_users WHERE user_id='target' ORDER BY collection_id").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<Result<_,_>>().unwrap()
    }
    fn target(store: &Store) -> (i32, i32, bool, String) {
        store.db.query_row("SELECT role,status,access_all,key FROM organization_memberships WHERE id='target-member'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap()
    }
    fn revisions(store: &Store) -> Vec<(String, String)> {
        store
            .db
            .prepare("SELECT id,revision FROM accounts ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn ordered_member_grant_failure_retains_prefix_and_only_target_revision() {
        let mut store = fixture();
        let before = revisions(&store);
        let old_target = target(&store);
        let error = VaultService::new(&mut store)
            .update_org_member(
                "actor",
                "org",
                "target-member",
                &request(&["first", "foreign-collection"]),
            )
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(grants(&store), ["first"]);
        assert_eq!(target(&store), old_target);
        for (old, new) in before.iter().zip(revisions(&store)) {
            assert_eq!(old.0, new.0);
            assert_eq!(old.1 == new.1, old.0 != "target");
        }
        let success = request(&["first", "second", "first"]);
        VaultService::new(&mut store)
            .update_org_member("actor", "org", "target-member", &success)
            .unwrap();
        assert_eq!(grants(&store), ["first", "second"]);
        assert_eq!(target(&store), (3, 2, false, "target wrapped key".into()));
    }

    #[test]
    fn each_local_member_update_phase_rolls_back_only_its_failed_transaction() {
        for stage in ["begin", "grant", "finish"] {
            let mut store = fixture();
            let old_target = target(&store);
            let old_revisions = revisions(&store);
            let trigger = match stage {
                "begin" => {
                    "CREATE TRIGGER stop_update BEFORE UPDATE ON accounts WHEN OLD.id='target' BEGIN SELECT RAISE(ABORT,'fixture revision failure'); END;"
                }
                "grant" => {
                    "CREATE TRIGGER stop_update BEFORE INSERT ON organization_collection_users WHEN NEW.collection_id='second' BEGIN SELECT RAISE(ABORT,'fixture grant failure'); END;"
                }
                _ => {
                    "CREATE TRIGGER stop_update BEFORE UPDATE OF role ON organization_memberships WHEN OLD.id='target-member' BEGIN SELECT RAISE(ABORT,'fixture final failure'); END;"
                }
            };
            store.db.execute_batch(trigger).unwrap();
            let error = VaultService::new(&mut store)
                .update_org_member(
                    "actor",
                    "org",
                    "target-member",
                    &request(&["first", "second"]),
                )
                .unwrap_err();
            assert_eq!(error.status_code(), 500);
            assert_eq!(target(&store), old_target);
            match stage {
                "begin" => {
                    assert_eq!(grants(&store), ["old"]);
                    assert_eq!(revisions(&store), old_revisions);
                }
                "grant" => assert_eq!(grants(&store), ["first"]),
                _ => assert_eq!(grants(&store), ["first", "second"]),
            }
        }
    }

    #[test]
    fn later_member_update_phase_rechecks_live_actor_authority() {
        let mut store = fixture();
        let old_target = target(&store);
        store.db.execute_batch("CREATE TRIGGER revoke_actor AFTER DELETE ON organization_collection_users WHEN OLD.collection_id='old' BEGIN UPDATE organization_memberships SET status=-1 WHERE id='actor-member'; END;").unwrap();
        let error = VaultService::new(&mut store)
            .update_org_member("actor", "org", "target-member", &request(&["first"]))
            .unwrap_err();
        assert_eq!(error.status_code(), 500);
        assert!(grants(&store).is_empty());
        assert_eq!(target(&store), old_target);
        let actor: i32 = store
            .db
            .query_row(
                "SELECT status FROM organization_memberships WHERE id='actor-member'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actor, -1);
    }

    #[test]
    fn member_update_decoder_preserves_native_array_slots_and_bounds_host_work() {
        for body in [r#"{"type":2}"#, r#"[2,null,null]"#, r#"[2,[],[],{}]"#] {
            assert!(Input::parse(body.as_bytes()).is_ok());
        }
        for body in [
            r#"[2]"#,
            r#"[2,null]"#,
            r#"[2,null,null,null]"#,
            r#"{"Type":2}"#,
        ] {
            assert!(
                Input::parse(body.as_bytes())
                    .err()
                    .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
            );
        }
        let mut consumed = 0;
        let values = std::iter::repeat_n("", 5_000_000).inspect(|_| consumed += 1);
        let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(values);
        assert!(Selections::<String>::deserialize(decoder).is_err());
        assert_eq!(consumed, MAX_MEMBER_UPDATE_SELECTIONS + 1);
        let body =
            serde_json::to_vec(&json!({"type":2,"groups":vec!["";MAX_MEMBER_UPDATE_SELECTIONS+1]}))
                .unwrap();
        assert!(
            Input::parse(&body)
                .err()
                .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
}
