use super::*;
use crate::organization_collections::tests::{create_org, fixture, org};
use crate::organization_confirmations::tests::snapshot;
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};
use no_warden::VaultService;
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn add_member(store: &Store, org: &str, user: &str, role: i32, status: i32) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque-retained-key',?4,?5,0)",
            params![id, org, user, role, status],
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_member_inviters VALUES(?1,'alice@example.test')",
            [&id],
        )
        .unwrap();
    store.db.execute("INSERT INTO organization_collection_users SELECT id,?1,1,1,0 FROM organization_collections WHERE organization_id=?2",params![user,org]).unwrap();
    id
}
struct Setup {
    store: Store,
    org: String,
    sibling: String,
    alice: String,
    bob: String,
    carol: String,
}
fn setup(path: &str, bob_role: i32) -> Setup {
    let mut store = fixture(path);
    let org = org(&store);
    let sibling = create_org(&mut store, "alice");
    let alice = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='alice'",
            [&org],
            |r| r.get(0),
        )
        .unwrap();
    let doc = json!({"id":"carol","email":"carol@example.test","key":"opaque-key","securityStamp":"stamp","revisionDate":"2000-01-01T00:00:00.000Z"});
    store.db.execute("INSERT INTO accounts VALUES('carol','carol@example.test',?1,'opaque-verifier','2000-01-01T00:00:00.000Z')",[doc.to_string()]).unwrap();
    let bob = add_member(&store, &org, "bob", bob_role, 2);
    let carol = add_member(&store, &org, "carol", 2, 1);
    add_member(&store, &sibling, "bob", 2, 2);
    for user in ["bob", "carol"] {
        store
            .db
            .execute(
                "INSERT INTO organization_invitations VALUES(?1)",
                [format!("{user}@example.test")],
            )
            .unwrap();
        store.db.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher','{\"name\":\"opaque-ciphertext\"}',0,'2000','2000')",params![format!("personal-{user}"),user]).unwrap();
    }
    Setup {
        store,
        org,
        sibling,
        alice,
        bob,
        carol,
    }
}
fn input(ids: Value) -> Input {
    Input::parse(&serde_json::to_vec(&json!({"ids":ids})).unwrap())
        .unwrap_or_else(|_| panic!("Authored bulk input"))
}
fn run(store: &mut Store, org: &str, input: &Input) -> Value {
    let mut output = vec![None; input.len()];
    serde_json::to_value(
        VaultService::new(store)
            .bulk_remove_org_members("alice", org, input, &mut output)
            .unwrap(),
    )
    .unwrap()
}
fn row(id: &str, message: &str) -> Value {
    json!({"id":id,"object":"OrganizationBulkConfirmResponseModel","error":message})
}
fn changes(
    data: &Setup,
    mut before: BTreeMap<String, Vec<Vec<SqlValue>>>,
    removed: &[(&str, &str)],
) {
    let after = snapshot(&data.store);
    let ids: Vec<SqlValue> = removed
        .iter()
        .map(|(_, id)| SqlValue::Text((*id).into()))
        .collect();
    let users: Vec<SqlValue> = removed
        .iter()
        .map(|(user, _)| SqlValue::Text((*user).into()))
        .collect();
    let collections: Vec<SqlValue> = before["organization_collections"]
        .iter()
        .filter(|r| r[1] == SqlValue::Text(data.org.clone()))
        .map(|r| r[0].clone())
        .collect();
    before
        .get_mut("organization_memberships")
        .unwrap()
        .retain(|r| !ids.contains(&r[0]));
    before
        .get_mut("organization_member_inviters")
        .unwrap()
        .retain(|r| !ids.contains(&r[0]));
    before
        .get_mut("organization_collection_users")
        .unwrap()
        .retain(|r| !(collections.contains(&r[0]) && users.contains(&r[1])));
    for (user, _) in removed {
        before
            .get_mut("organization_invitations")
            .unwrap()
            .retain(|r| r[0] != SqlValue::Text(format!("{user}@example.test")));
        let old = before
            .get_mut("accounts")
            .unwrap()
            .iter_mut()
            .find(|r| r[0] == SqlValue::Text((*user).into()))
            .unwrap();
        let new = after["accounts"]
            .iter()
            .find(|r| r[0] == SqlValue::Text((*user).into()))
            .unwrap();
        let (
            SqlValue::Text(old_doc),
            SqlValue::Text(new_doc),
            SqlValue::Text(old_rev),
            SqlValue::Text(new_rev),
        ) = (&old[2], &new[2], &old[4], &new[4])
        else {
            panic!("Account schema")
        };
        assert!(new_rev > old_rev);
        let mut doc: Value = serde_json::from_str(old_doc).unwrap();
        doc["revisionDate"] = json!(new_rev);
        assert!(doc == serde_json::from_str::<Value>(new_doc).unwrap());
        old[2] = new[2].clone();
        old[4] = new[4].clone();
    }
    assert!(
        before == after,
        "Only explicitly removed memberships, scoped grants, invitation metadata and recipient revisions may change"
    );
}

#[test]
fn bulk_removal_decoder_requires_complete_ids_and_keeps_exact_opaque_strings() {
    for bytes in [
        br#"{}"#.as_slice(),
        br#"{"Ids":[]}"#,
        br#"{"ids":null}"#,
        br#"{"ids":false}"#,
        br#"{"ids":["a",null]}"#,
        br#"{"ids":["a",3]}"#,
        br#"{"ids":[],"ids":[]}"#,
        br#"[]"#,
    ] {
        assert!(
            Input::parse(bytes)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for bytes in [b"{".as_slice(), b"\xff", br#"[[],0]"#] {
        assert!(
            Input::parse(bytes)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
    let value = Input::parse(br#"[["","not-a-uuid","UPPER","\u0000\u96ea",""] ]"#)
        .unwrap_or_else(|_| panic!("Opaque positional IDs"));
    assert!(value.len() == 5 && value.get(3) == Some("\0雪") && value.get(0) == value.get(4));
    assert!(Input::parse(br#"{"ids":[],"ignored":false}"#).is_ok());
}

#[test]
fn bulk_removal_returns_ordered_rows_and_keeps_commits_across_duplicates_and_missing_ids() {
    let mut data = setup(":memory:", 2);
    let before = snapshot(&data.store);
    let ids = input(json!(["missing", data.bob, data.bob, "", data.carol]));
    let value = run(&mut data.store, &data.org, &ids);
    let missing = "User to delete isn't member of the organization";
    assert!(
        value
            == json!({"data":[row("missing",missing),row(&data.bob,""),row(&data.bob,missing),row("",missing),row(&data.carol,"")],"object":"list","continuationToken":null})
    );
    changes(&data, before, &[("bob", &data.bob), ("carol", &data.carol)]);
}

#[test]
fn bulk_removal_cached_owner_continues_after_its_own_successful_removal() {
    let mut data = setup(":memory:", 0);
    let before = snapshot(&data.store);
    let ids = input(json!([data.alice, "missing", data.bob, data.carol]));
    let value = run(&mut data.store, &data.org, &ids);
    assert!(
        value["data"]
            == json!([
                row(&data.alice, ""),
                row("missing", "User to delete isn't member of the organization"),
                row(&data.bob, "Can't delete the last owner"),
                row(&data.carol, "")
            ])
    );
    changes(
        &data,
        before,
        &[("alice", &data.alice), ("carol", &data.carol)],
    );
    assert!(
        VaultService::new(&mut data.store)
            .authorize_org_member_admin("alice", &data.org)
            .is_err()
    );
    assert!(
        VaultService::new(&mut data.store)
            .authorize_org_member_admin("bob", &data.org)
            .is_ok()
    );
    assert!(
        VaultService::new(&mut data.store)
            .authorize_org_member_admin("alice", &data.sibling)
            .is_ok()
    );
}

#[test]
fn bulk_removal_failed_self_commit_does_not_enable_absent_actor_authority() {
    let mut data = setup(":memory:", 0);
    data.store.db.execute_batch(&format!("CREATE TRIGGER fail_self BEFORE DELETE ON organization_memberships WHEN OLD.id='{}' BEGIN SELECT RAISE(ABORT,'private-self-diagnostic'); END;",data.alice)).unwrap();
    let before = snapshot(&data.store);
    let ids = input(json!([data.alice, data.carol]));
    let value = run(&mut data.store, &data.org, &ids);
    let message = value["data"][0]["error"].as_str().unwrap();
    assert!(!message.is_empty() && !message.contains("private-"));
    assert!(value["data"][1] == row(&data.carol, ""));
    changes(&data, before, &[("carol", &data.carol)]);
}

#[test]
fn bulk_removal_unrelated_actor_loss_or_replacement_cannot_reuse_batch_authority() {
    for replacement in [false, true] {
        let mut data = setup(":memory:", 2);
        let insert = if replacement {
            format!(
                "INSERT INTO organization_memberships VALUES('{}','{}','alice','opaque',0,2,1);",
                uuid::Uuid::new_v4(),
                data.org
            )
        } else {
            String::new()
        };
        data.store.db.execute_batch(&format!("CREATE TRIGGER unrelated_actor_change AFTER DELETE ON organization_memberships WHEN OLD.id='{}' BEGIN DELETE FROM organization_memberships WHERE id='{}'; {} END;",data.bob,data.alice,insert)).unwrap();
        let before = snapshot(&data.store);
        let ids = input(json!([data.bob, data.carol]));
        let value = run(&mut data.store, &data.org, &ids);
        assert!(value["data"][0] == row(&data.bob, ""));
        assert!(
            value["data"][1]["error"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        let after = snapshot(&data.store);
        let carol = SqlValue::Text(data.carol.clone());
        assert!(
            before["organization_memberships"]
                .iter()
                .find(|r| r[0] == carol)
                == after["organization_memberships"]
                    .iter()
                    .find(|r| r[0] == carol)
        );
        assert!(before["items"] == after["items"] && before["sessions"] == after["sessions"]);
        let user = SqlValue::Text("carol".into());
        assert!(
            before["accounts"].iter().find(|r| r[0] == user)
                == after["accounts"].iter().find(|r| r[0] == user)
        );
    }
}

#[test]
fn bulk_removal_provider_failure_rolls_back_one_item_and_later_item_commits() {
    let mut data = setup(":memory:", 2);
    data.store.db.execute_batch(&format!("CREATE TRIGGER fail_bob BEFORE DELETE ON organization_memberships WHEN OLD.id='{}' BEGIN SELECT RAISE(ABORT,'private-bob-diagnostic'); END;",data.bob)).unwrap();
    let before = snapshot(&data.store);
    let ids = input(json!([data.bob, data.carol]));
    let value = run(&mut data.store, &data.org, &ids);
    assert!(
        value["data"][0]["error"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && !s.contains("private-"))
    );
    assert!(value["data"][1] == row(&data.carol, ""));
    changes(&data, before, &[("carol", &data.carol)]);
}

async fn call(app: &App, path: &str, auth: bool, body: &[u8]) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    if auth {
        headers.insert(
            "authorization",
            "Bearer collection-fixture-access".parse().unwrap(),
        );
    }
    dispatch(
        State(app.clone()),
        Method::DELETE,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}
#[tokio::test]
async fn bulk_removal_http_checks_authority_paths_and_whole_schema_before_any_write() {
    let data = setup(":memory:", 2);
    let path = format!("/api/organizations/{}/users", data.org);
    let app = App {
        store: Arc::new(Mutex::new(data.store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let bad_later = serde_json::to_vec(&json!({"ids":[data.bob,17]})).unwrap();
    for (uri, auth, body, status) in [
        (path.clone(), false, b"{".as_slice(), 401),
        (
            "/api/organizations/invalid/users".into(),
            true,
            b"{".as_slice(),
            401,
        ),
        (
            format!(
                "/api/organizations/invalid/users?organizationId={}",
                data.org
            ),
            true,
            b"{".as_slice(),
            422,
        ),
        (path.clone(), true, bad_later.as_slice(), 422),
    ] {
        let before = snapshot(&app.store.lock().unwrap());
        assert!(call(&app, &uri, auth, body).await.status().as_u16() == status);
        assert!(snapshot(&app.store.lock().unwrap()) == before);
    }
    for body in [br#"{"ids":[]}"#.as_slice(), br#"[[]]"#] {
        let before = snapshot(&app.store.lock().unwrap());
        let response = call(&app, &path, true, body).await;
        assert!(response.status() == StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
        assert!(value == json!({"data":[],"object":"list","continuationToken":null}));
        assert!(snapshot(&app.store.lock().unwrap()) == before);
    }
}

#[test]
fn bulk_removal_successful_prefix_and_self_removal_survive_reopening() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "no-warden-bulk-removal-reopen-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("vault.db");
    let expected = {
        let mut data = setup(path.to_str().unwrap(), 0);
        let before = snapshot(&data.store);
        let ids = input(json!([data.alice, data.bob, data.carol]));
        let value = run(&mut data.store, &data.org, &ids);
        assert!(
            value["data"][0]["error"] == ""
                && value["data"][1]["error"] == "Can't delete the last owner"
                && value["data"][2]["error"] == ""
        );
        changes(
            &data,
            before,
            &[("alice", &data.alice), ("carol", &data.carol)],
        );
        snapshot(&data.store)
    };
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == expected);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}
