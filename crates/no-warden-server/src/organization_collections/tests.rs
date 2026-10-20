use super::*;
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method},
    response::IntoResponse,
};
use no_warden::identity::Secret;
use no_warden::wire::{OrganizationCreateRequest, OrganizationPlanType};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) fn fixture(path: &str) -> Store {
    let mut store = Store::open(path).unwrap();
    for owner in ["alice", "bob"] {
        let doc = json!({"id":owner,"email":format!("{owner}@example.test"),"key":"opaque-key","securityStamp":"stamp","revisionDate":"2000-01-01T00:00:00.000Z"});
        store.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",params![owner,format!("{owner}@example.test"),doc.to_string()]).unwrap();
    }
    let access = crate::digest("collection-fixture-access");
    store
        .db
        .execute(
            "INSERT INTO sessions VALUES(?1,'opaque-refresh','alice',?2,?3)",
            params![
                access,
                chrono::Utc::now().timestamp() + 600,
                chrono::Utc::now().timestamp() + 3600
            ],
        )
        .unwrap();
    store.db.execute("INSERT INTO device_registry VALUES('alice','fixture-device','fixture',23,'2000','2000')",[]).unwrap();
    store
        .db
        .execute(
            "INSERT INTO session_devices VALUES(?1,'alice','fixture-device')",
            [access],
        )
        .unwrap();
    create_org(&mut store, "alice");
    store
}
pub(crate) fn create_org(store: &mut Store, owner: &str) -> String {
    let request = OrganizationCreateRequest {
        billing_email: "a@example.test",
        collection_name: "opaque-initial",
        key: Secret::new("opaque-org-key"),
        name: "org",
        keys: None,
        plan_type: OrganizationPlanType::Integer(0),
    };
    serde_json::to_value(
        VaultService::new(store)
            .create_organization(owner, &request)
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
pub(crate) fn org(store: &Store) -> String {
    store
        .db
        .query_row(
            "SELECT id FROM organizations ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
pub(super) fn input() -> Input {
    Input::parse(br#"{"name":"opaque\u0000\u96ea","groups":[],"users":[],"externalId":" "}"#)
        .unwrap_or_else(|_| panic!("Collection input"))
}
pub(super) fn create(store: &mut Store, org: &str) -> Value {
    serde_json::to_value(
        VaultService::new(store)
            .create_org_collection("alice", org, &input())
            .unwrap(),
    )
    .unwrap()
}
pub(crate) fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut data = Vec::new();
    for table in [
        "accounts",
        "items",
        "attachments",
        "sessions",
        "device_registry",
        "session_devices",
        "organizations",
        "organization_memberships",
        "organization_collections",
        "organization_collection_users",
        "organization_collection_ciphers",
    ] {
        let mut statement = store
            .db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
            .unwrap();
        let count = statement.column_count();
        data.extend(
            statement
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    data
}
#[test]
fn owned_collection_input_preserves_schema_order_duplicates_and_uncapped_views() {
    for bytes in [
        br#"["",[],[],null]"#.as_slice(),
        br#"{"name":"","groups":[],"users":[]}"#,
        br#"["",[[true,"opaque",false,true]],[[false,"",true,false]]," "]"#,
    ] {
        assert!(Input::parse(bytes).is_ok());
    }
    for bytes in [
        b"{}".as_slice(),
        br#"["",[],null,null]"#,
        br#"{"name":"","name":"duplicate","groups":[],"users":[]}"#,
        br#"["",[],[[false,"id",false]],null]"#,
        br#"["",[[false,"id",false,null]],[],null]"#,
    ] {
        assert!(
            Input::parse(bytes)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for bytes in [
        b"{".as_slice(),
        br#"["",[],[],null,true]"#,
        b"{\"name\":\"\",\"groups\":[],\"users\":[],\"ignored\":\"\xff\"}",
    ] {
        assert!(
            Input::parse(bytes)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
    let selection = json!({"hidePasswords":false,"id":"opaque","readOnly":false,"manage":true});
    let body = json!({"name":"雪\0","groups":[],"users":vec![selection;513]});
    let decoded = Input::parse(&serde_json::to_vec(&body).unwrap())
        .unwrap_or_else(|_| panic!("Uncapped host view"));
    assert!(decoded.users_len() == 513 && decoded.name() == "雪\0");
}
#[test]
fn collection_creation_preserves_opaque_payloads_and_foreign_state() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    let bob = store.account("id", "bob").unwrap().unwrap();
    let alice = store.account("id", "alice").unwrap().unwrap();
    let response = create(&mut store, &org);
    let id = response["id"].as_str().unwrap();
    assert!(
        response.as_object().unwrap().len() == 10
            && response["name"] == "opaque\0雪"
            && response["externalId"] == " "
    );
    assert!(
        response["manage"] == true
            && response["readOnly"] == false
            && response["hidePasswords"] == false
    );
    let mut changed = store.account("id", "alice").unwrap().unwrap();
    assert!(changed["revisionDate"] != alice["revisionDate"]);
    changed["revisionDate"] = alice["revisionDate"].clone();
    assert!(changed == alice && store.account("id", "bob").unwrap().unwrap() == bob);
    let stable = snapshot(&store);
    let details = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, id)
            .unwrap(),
    )
    .unwrap();
    assert!(
        details.as_object().unwrap().len() == 13
            && details["assigned"] == true
            && details["users"] == json!([])
            && details["groups"] == json!([])
    );
    assert!(snapshot(&store) == stable);
    for ext in [None, Some(""), Some("\0雪")] {
        let mut input = input();
        input.external_id = ext.map(str::to_owned);
        let response = serde_json::to_value(
            VaultService::new(&mut store)
                .create_org_collection("alice", &org, &input)
                .unwrap(),
        )
        .unwrap();
        assert!(
            response["externalId"]
                == ext
                    .filter(|s| !s.is_empty())
                    .map_or(Value::Null, |s| json!(s))
        );
    }
}
pub(super) fn add_bob(store: &Store, org: &str, all: bool) {
    store.db.execute("INSERT INTO organization_memberships VALUES('bob-membership',?1,'bob','opaque-bob-key',2,2,?2)",params![org,all]).unwrap();
}
pub(super) fn grant_input(store: &Store, org: &str) -> Input {
    let owner_id: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='alice'",
            [org],
            |r| r.get(0),
        )
        .unwrap();
    Input::parse(&serde_json::to_vec(&json!({"name":"opaque","groups":[],"users":[{"hidePasswords":true,"id":owner_id,"readOnly":true,"manage":false},{"hidePasswords":true,"id":"bob-membership","readOnly":false,"manage":false},{"hidePasswords":false,"id":"bob-membership","readOnly":true,"manage":true}]})).unwrap()).unwrap_or_else(|_|panic!("Selections fixture"))
}
#[test]
fn collection_atomic_grants_skip_full_access_and_last_duplicate_selection_wins() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    add_bob(&store, &org, false);
    let before = store.account("id", "bob").unwrap().unwrap();
    let input = grant_input(&store, &org);
    let response = serde_json::to_value(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &input)
            .unwrap(),
    )
    .unwrap();
    let id = response["id"].as_str().unwrap();
    let count: i64 = store
        .db
        .query_row(
            "SELECT count(*) FROM organization_collection_users",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(count == 1);
    let details = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, id)
            .unwrap(),
    )
    .unwrap();
    assert!(
        details["users"]
            == json!([{"id":"bob-membership","readOnly":true,"hidePasswords":false,"manage":true}])
    );
    assert!(store.account("id", "bob").unwrap().unwrap()["revisionDate"] != before["revisionDate"]);
}
#[test]
fn collection_transaction_rolls_back_row_grants_revisions_and_response_cache() {
    for (table, operation) in [
        ("organization_collections", "INSERT"),
        ("organization_collection_users", "INSERT"),
        ("accounts", "UPDATE"),
    ] {
        let mut store = fixture(":memory:");
        let org = org(&store);
        add_bob(&store, &org, false);
        let input = grant_input(&store, &org);
        let before = snapshot(&store);
        store.db.execute_batch(&format!("CREATE TRIGGER fail_collection BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'rollback fixture'); END")).unwrap();
        assert!(
            VaultService::new(&mut store)
                .create_org_collection("alice", &org, &input)
                .is_err()
        );
        assert!(snapshot(&store) == before && store.organization_collection_cache.detail.is_none());
    }
}
#[test]
fn collection_reference_validation_orders_groups_before_members_without_mutation() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    let before = snapshot(&store);
    let mut input = input();
    input.groups.push(Selection {
        hide_passwords: false,
        id: "missing-group".into(),
        read_only: false,
        manage: false,
    });
    input.users.push(Selection {
        hide_passwords: false,
        id: "missing-member".into(),
        read_only: false,
        manage: false,
    });
    assert!(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &input)
            .err()
            .is_some_and(|e| e.message == "Invalid group")
    );
    input.groups.clear();
    assert!(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &input)
            .err()
            .is_some_and(|e| e.message == "Invalid member")
    );
    assert!(snapshot(&store) == before);
}

#[test]
fn imported_manager_rows_keep_loose_list_and_strict_effective_permissions_distinct() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    add_bob(&store, &org, false);
    store
        .db
        .execute(
            "UPDATE organization_memberships SET role=3 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    let created = create(&mut store, &org);
    let id = created["id"].as_str().unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',1,1,1)",
            [id],
        )
        .unwrap();
    let fetched = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("bob", &org, id)
            .unwrap(),
    )
    .unwrap();
    assert!(
        fetched["readOnly"] == false
            && fetched["hidePasswords"] == false
            && fetched["manage"] == true
            && fetched["assigned"] == true
    );
    assert!(
        VaultService::new(&mut store)
            .list_org_collections("bob", &org)
            .err()
            .is_some_and(
                |error| error.status_code() == 404 && error.message == "Resource not found."
            )
    );
    assert!(VaultService::new(&mut store).create_org_collection("bob", &org, &input()).err().is_some_and(|error| error.message == "You don't have permission to create collections"));
    // Effective flags do not replace the strict guard's stored manage decision.
    store
        .db
        .execute(
            "UPDATE organization_collection_users SET manage=0,read_only=0,hide_passwords=0",
            [],
        )
        .unwrap();
    assert!(
        VaultService::new(&mut store)
            .get_org_collection_details("bob", &org, id)
            .err()
            .is_some_and(|error| error.status_code() == 401)
    );
    store
        .db
        .execute(
            "UPDATE organization_memberships SET role=2,access_all=1 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    assert!(
        VaultService::new(&mut store)
            .list_org_collections("bob", &org)
            .err()
            .is_some_and(|error| error.status_code() == 401)
    );
}

#[test]
fn owner_without_access_all_keeps_full_management_but_only_explicit_revision_effects() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    store
        .db
        .execute(
            "UPDATE organization_memberships SET access_all=0 WHERE user_id='alice'",
            [],
        )
        .unwrap();
    let previous = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
    let created = create(&mut store, &org);
    assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] == previous);
    let detail = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, created["id"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(detail["assigned"] == true && detail["manage"] == true && detail["readOnly"] == false);
    let id: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE user_id='alice'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut input = input();
    input.users.push(Selection {
        hide_passwords: true,
        id,
        read_only: true,
        manage: false,
    });
    let created = serde_json::to_value(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &input)
            .unwrap(),
    )
    .unwrap();
    assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] != previous);
    let detail = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, created["id"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        detail["users"].as_array().unwrap().len() == 1
            && detail["users"][0]["manage"] == true
            && detail["users"][0]["readOnly"] == true
    );
}
#[test]
fn collection_global_management_precedes_organization_binding_and_uuid_parameters() {
    let mut store = fixture(":memory:");
    let first = org(&store);
    let own = create(&mut store, &first);
    let col = own["id"].as_str().unwrap();
    let other = create_org(&mut store, "alice");
    let foreign = create_org(&mut store, "bob");
    assert!(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &other, col)
            .err()
            .is_some_and(|e| e.status_code() == 400
                && e.message == "Collection is not owned by organization")
    );
    for org in [&first, &other] {
        assert!(
            VaultService::new(&mut store)
                .get_org_collection_details("bob", org, col)
                .err()
                .is_some_and(|e| e.status_code() == 401)
        );
    }
    let foreign_col: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [foreign],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &first, &foreign_col)
            .err()
            .is_some_and(|e| e.status_code() == 401)
    );
    for (raw_org, raw_col, query, code) in [
        ("bad.id", col, format!("organizationId={first}"), 422),
        (first.as_str(), "bad.id", format!("collectionId={col}"), 422),
        (
            "bad.id",
            "bad.id",
            format!("organizationId={first}&collectionId={col}"),
            422,
        ),
        (
            first.as_str(),
            "bad.id",
            format!("collectionId={foreign_col}"),
            401,
        ),
    ] {
        assert!(
            paths(&mut store, "alice", raw_org, Some(raw_col), Some(&query))
                .err()
                .is_some_and(|e| e.0.as_u16() == code)
        );
    }
}
#[tokio::test]
async fn collection_dispatch_requires_current_device_and_membership_before_json() {
    let store = fixture(":memory:");
    let org = org(&store);
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://localhost".into(),
        signing_key: [3; 32],
    };
    for (path, authorized, expected) in [
        (format!("/api/organizations/{org}/collections"), false, 401),
        (format!("/api/organizations/{org}/collections"), true, 400),
        ("/api/organizations/bad.id/collections".into(), true, 401),
        (
            format!("/api/organizations/bad.id/collections?organizationId={org}"),
            true,
            422,
        ),
    ] {
        let mut headers = HeaderMap::new();
        if authorized {
            headers.insert(
                "authorization",
                "Bearer collection-fixture-access".parse().unwrap(),
            );
        }
        let response = dispatch(
            State(app.clone()),
            Method::POST,
            path.parse().unwrap(),
            headers,
            Bytes::from_static(b"{"),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert!(response.status().as_u16() == expected);
    }
    let path = format!("/api/organizations/{org}/collections");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let response = dispatch(
        State(app.clone()),
        Method::POST,
        path.parse().unwrap(),
        headers.clone(),
        Bytes::from_static(br#"["opaque",[],[],null]"#),
    )
    .await
    .unwrap_or_else(|_| panic!("Collection dispatch"));
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(doc.as_object().unwrap().len() == 10);
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let response = dispatch(
        State(app),
        Method::POST,
        path.parse().unwrap(),
        headers,
        Bytes::from_static(b"{"),
    )
    .await
    .err()
    .unwrap();
    assert!(response.0 == StatusCode::UNAUTHORIZED);
}

#[test]
fn collection_rows_and_direct_selections_survive_private_database_reopen() {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(std::env::temp_dir().join(format!(
        "no-warden-collection-reopen-{}",
        uuid::Uuid::new_v4()
    )));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory.0).unwrap();
    let db = directory.0.join("vault.db");
    let mut store = fixture(db.to_str().unwrap());
    let org = org(&store);
    add_bob(&store, &org, false);
    let input = grant_input(&store, &org);
    let response = serde_json::to_value(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &input)
            .unwrap(),
    )
    .unwrap();
    let id = response["id"].as_str().unwrap();
    let expected = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, id)
            .unwrap(),
    )
    .unwrap();
    let state = snapshot(&store);
    drop(store);
    let mut reopened = Store::open(db.to_str().unwrap()).unwrap();
    assert!(snapshot(&reopened) == state);
    assert!(
        serde_json::to_value(
            VaultService::new(&mut reopened)
                .get_org_collection_details("alice", &org, id)
                .unwrap()
        )
        .unwrap()
            == expected
    );
}
