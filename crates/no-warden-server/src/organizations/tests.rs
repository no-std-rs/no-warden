use super::*;
use crate::{App, account_deletion, dispatch, store::Store};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
};
use no_warden::VaultService;
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

fn fixture(path: &str) -> Store {
    let store = Store::open(path).expect("Organization fixture storage");
    for owner in ["alice", "bob"] {
        let account = json!({"id":owner,"email":format!("{owner}@example.test"),"name":owner,
            "key":"opaque-account-key","keys":{"publicKey":"opaque-public","encryptedPrivateKey":"opaque-private"},
            "securityStamp":"opaque-stamp","revisionDate":"2000-01-01T00:00:00.000Z","futureField":true});
        store.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",
            params![owner,format!("{owner}@example.test"),account.to_string()]).unwrap();
        store
            .db
            .execute(
                "INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher',?3,0,'2000','2000')",
                params![
                    format!("{owner}-cipher"),
                    owner,
                    json!({"id":format!("{owner}-cipher"),"opaque":true}).to_string()
                ],
            )
            .unwrap();
    }
    let access = crate::digest("organization-fixture-access");
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
    store
}
fn input() -> Input {
    Input::parse(br#"{"billingEmail":"BILLING@EXAMPLE.test","collectionName":"opaque\u0000collection","key":"opaque\u0000wrapped-key","name":"Org\u96ea","keys":{"publicKey":"","encryptedPrivateKey":"opaque\u0000private"},"planType":"ignored-plan"}"#)
        .unwrap_or_else(|_| panic!("Organization input fixture"))
}
fn create(store: &mut Store, owner: &str) -> Value {
    let input = input();
    let mut service = VaultService::new(store);
    serde_json::to_value(
        service
            .create_organization(owner, &input.request())
            .unwrap(),
    )
    .unwrap()
}
fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut result = Vec::new();
    for table in [
        "accounts",
        "items",
        "sessions",
        "device_registry",
        "session_devices",
        "organizations",
        "organization_memberships",
        "organization_collections",
    ] {
        let mut statement = store
            .db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = statement.column_count();
        result.extend(
            statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get(i))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    result
}
#[test]
fn organization_owned_schema_decoding_preserves_opaque_data_and_error_categories() {
    let fixture = input();
    let request = fixture.request();
    assert!(request.name == "Org雪" && request.key.expose_secret() == "opaque\0wrapped-key");
    assert!(request.keys.is_some_and(|keys| keys.public_key.is_empty()));
    for body in [br#"["a@example.test","","","",null,-99]"#.as_slice(), br#"{"billingEmail":"a@example.test","collectionName":"","key":"","name":"","planType":"any"}"#] {
        assert!(Input::parse(body).is_ok());
    }
    for body in [b"{}".as_slice(),br#"["a@example.test","","","",null,true]"#,br#"["a@example.test","","","",null,1.2]"#,br#"["a@example.test","","","",null,null]"#,
        br#"{"billingEmail":"a@example.test","collectionName":"","key":"","name":"a","name":"b","planType":0}"#] {
        assert!(Input::parse(body).err().is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY));
    }
    for body in [b"{".as_slice(), b"{\"billingEmail\":\"a@example.test\",\"collectionName\":\"\",\"key\":\"\",\"name\":\"\",\"planType\":0,\"ignored\":\"\xff\"}",
        br#"["a@example.test","","","",null,0,1]"#] {
        assert!(Input::parse(body).err().is_some_and(|error| error.0 == StatusCode::BAD_REQUEST));
    }
}
#[test]
fn organization_creation_is_atomic_when_any_persistence_step_fails() {
    for table in [
        "organization_memberships",
        "organization_collections",
        "accounts",
    ] {
        let mut store = fixture(":memory:");
        let before = snapshot(&store);
        let operation = if table == "accounts" {
            "UPDATE"
        } else {
            "INSERT"
        };
        store.db.execute_batch(&format!("CREATE TRIGGER fail_creation BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'fixture rollback'); END;")).unwrap();
        let input = input();
        assert!(
            VaultService::new(&mut store)
                .create_organization("alice", &input.request())
                .is_err()
        );
        assert!(snapshot(&store) == before);
        assert!(store.organization_cache.is_none());
    }
}
#[test]
fn organization_creation_updates_only_owner_revision_and_projects_joined_keys() {
    let mut store = fixture(":memory:");
    let before = snapshot(&store);
    let old_alice = store.account("id", "alice").unwrap().unwrap();
    let old_bob = store.account("id", "bob").unwrap().unwrap();
    let org = create(&mut store, "alice");
    let id = org["id"].as_str().unwrap();
    assert!(org.as_object().unwrap().len() == 47 && org["billingEmail"] == "billing@example.test");
    assert!(org["hasPublicAndPrivateKeys"] == true && org["seats"].is_null());
    assert!(org.get("key").is_none() && org.get("publicKey").is_none());
    let mut alice = store.account("id", "alice").unwrap().unwrap();
    assert!(alice["revisionDate"] != old_alice["revisionDate"]);
    alice["revisionDate"] = old_alice["revisionDate"].clone();
    assert!(alice == old_alice && store.account("id", "bob").unwrap().unwrap() == old_bob);
    assert!(snapshot(&store)[2..before.len()] == before[2..]);
    let stable = snapshot(&store);
    let mut service = VaultService::new(&mut store);
    let fetched = serde_json::to_value(service.get_organization("alice", id).unwrap()).unwrap();
    assert!(fetched == org);
    assert!(
        service
            .get_organization("bob", id)
            .err()
            .is_some_and(|error| error.status_code() == 401)
    );
    let collections = service.list_user_collections("alice").unwrap();
    let base = serde_json::to_value(&collections).unwrap();
    let detailed = serde_json::to_value(collections.details()).unwrap();
    assert!(
        base["data"][0].as_object().unwrap().len() == 7
            && detailed[0].as_object().unwrap().len() == 10
    );
    assert!(base["data"][0]["name"] == "opaque\0collection" && detailed[0]["manage"] == true);
    let profiles = service.profile_organizations("alice").unwrap();
    let profile = serde_json::to_value(profiles.confirmed()).unwrap();
    assert!(
        profile[0].as_object().unwrap().len() == 59 && profile[0]["key"] == "opaque\0wrapped-key"
    );
    assert!(profile[0]["limitCollectionCreation"] == false && profile[0]["seats"] == 20);
    assert!(
        serde_json::to_value(service.list_user_collections("bob").unwrap()).unwrap()["data"]
            == json!([])
    );
    assert!(snapshot(&store) == stable);
}
#[test]
fn invalid_billing_and_missing_owner_preserve_storage() {
    let mut store = fixture(":memory:");
    let before = snapshot(&store);
    let mut input = input();
    input.billing_email = " space@EXAMPLE.test ".into();
    let error = VaultService::new(&mut store)
        .create_organization("alice", &input.request())
        .err()
        .unwrap();
    assert!(
        error.status_code() == 400
            && input.billing_error()
                == "BillingEmail  space@example.test  is not a valid email address"
    );
    assert!(snapshot(&store) == before);
    assert!(
        VaultService::new(&mut store)
            .create_organization("missing", &self::input().request())
            .is_err()
    );
    assert!(snapshot(&store) == before);
}
#[test]
fn last_confirmed_owner_cannot_be_deleted_but_other_confirmed_owner_allows_cleanup() {
    let mut store = fixture(":memory:");
    let org = create(&mut store, "alice");
    let before = snapshot(&store);
    assert!(last_owner(&store.db, "alice").unwrap());
    assert!(account_deletion::delete(&mut store.db, "alice").is_err());
    assert!(snapshot(&store) == before);
    // An accepted or revoked Owner does not satisfy the confirmed-owner rule.
    for status in [1, -1] {
        store
            .db
            .execute(
                "INSERT INTO organization_memberships VALUES('bob-owner',?1,'bob','opaque',0,?2,1)",
                params![org["id"].as_str().unwrap(), status],
            )
            .unwrap();
        assert!(last_owner(&store.db, "alice").unwrap());
        store
            .db
            .execute(
                "DELETE FROM organization_memberships WHERE id='bob-owner'",
                [],
            )
            .unwrap();
    }
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES('bob-owner',?1,'bob','opaque',0,2,1)",
            [org["id"].as_str().unwrap()],
        )
        .unwrap();
    assert!(!last_owner(&store.db, "alice").unwrap());
    account_deletion::delete(&mut store.db, "alice").unwrap();
    assert!(store.account("id", "alice").unwrap().is_none());
    assert!(last_owner(&store.db, "bob").unwrap());
    assert!(
        store
            .db
            .query_row("SELECT count(*) FROM organization_collections", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
            == 1
    );
}
#[test]
fn organization_owner_guard_preserves_path_precedence_and_query_fallback() {
    let mut store = fixture(":memory:");
    let org = create(&mut store, "alice");
    let id = org["id"].as_str().unwrap();
    assert!(owner_path(&store.db, "alice", id, Some("organizationId=foreign")).is_ok());
    for (path, query, code) in [
        ("bad", None, 401),
        ("bad", Some(format!("organizationId={id}")), 422),
        (
            "00000000-0000-0000-0000-000000000000",
            Some(format!("organizationId={id}")),
            401,
        ),
        ("bad", Some(format!("OrganizationId={id}")), 401),
        (
            "bad",
            Some(format!("organizationId=&organizationId={id}")),
            401,
        ),
    ] {
        assert!(
            owner_path(&store.db, "alice", path, query.as_deref())
                .err()
                .is_some_and(|error| error.0.as_u16() == code)
        );
    }
    for query in [
        format!("[organizationId]={id}"),
        format!(".organizationId.child={id}"),
    ] {
        assert!(
            owner_path(&store.db, "alice", "bad", Some(&query))
                .err()
                .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
}
#[tokio::test]
async fn organization_dispatch_authenticates_device_before_json_and_projects_profile_sync() {
    let app = App {
        store: Arc::new(Mutex::new(fixture(":memory:"))),
        base: "http://localhost".into(),
        signing_key: [1; 32],
    };
    let request = |method, path: &str, authorized, body: Bytes| {
        let mut headers = HeaderMap::new();
        if authorized {
            headers.insert(
                "authorization",
                "Bearer organization-fixture-access".parse().unwrap(),
            );
        }
        dispatch(
            State(app.clone()),
            method,
            path.parse::<Uri>().unwrap(),
            headers,
            body,
        )
    };
    let response = request(
        Method::POST,
        "/api/organizations",
        false,
        Bytes::from_static(b"{"),
    )
    .await
    .err()
    .unwrap();
    assert!(response.0 == StatusCode::UNAUTHORIZED);
    let response = request(
        Method::POST,
        "/api/organizations",
        true,
        Bytes::from_static(b"{"),
    )
    .await
    .err()
    .unwrap();
    assert!(response.0 == StatusCode::BAD_REQUEST);
    let body = Bytes::from_static(br#"["a@example.test","opaque-name","opaque-key","org",null,0]"#);
    assert!(
        request(Method::POST, "/api/organizations", true, body)
            .await
            .unwrap_or_else(|_| panic!("Organization create dispatch"))
            .status()
            == StatusCode::OK
    );
    for path in ["/api/accounts/profile", "/api/sync"] {
        let response = request(Method::GET, path, true, Bytes::new())
            .await
            .unwrap_or_else(|_| panic!("Organization discovery dispatch: {path}"))
            .into_response();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        let profile = if path == "/api/sync" {
            &document["profile"]
        } else {
            &document
        };
        assert!(
            profile["organizations"][0]["key"] == "opaque-key"
                && profile["organizationsNew"][0]["key"] == "opaque-key"
        );
        if path == "/api/sync" {
            assert!(document["collections"][0]["manage"] == true);
        }
    }
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let response = request(
        Method::POST,
        "/api/organizations",
        true,
        Bytes::from_static(b"{"),
    )
    .await
    .err()
    .unwrap();
    assert!(response.0 == StatusCode::UNAUTHORIZED);
}

struct PrivateDirectory(std::path::PathBuf);
impl PrivateDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "no-warden-organization-unit-{}",
            uuid::Uuid::new_v4()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn organization_opaque_state_survives_reopen_and_concurrent_last_owner_cleanup() {
    let directory = PrivateDirectory::new();
    let path = directory.0.join("vault.db");
    let mut first = fixture(path.to_str().unwrap());
    let org = create(&mut first, "alice");
    let id = org["id"].as_str().unwrap();
    first.db.execute("INSERT INTO organization_memberships VALUES('bob-owner',?1,'bob','other-opaque-key',0,2,1)",[id]).unwrap();
    let expected = snapshot(&first);
    drop(first);
    let first = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&first) == expected);
    let keys: (String, String) = first
        .db
        .query_row(
            "SELECT public_key,encrypted_private_key FROM organizations WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(keys.0.is_empty() && keys.1 == "opaque\0private");
    let second = Store::open(path.to_str().unwrap()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [("alice", first), ("bob", second)]
        .into_iter()
        .map(|(owner, mut store)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                store
                    .db
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                assert!(!last_owner(&store.db, owner).unwrap());
                barrier.wait();
                account_deletion::delete(&mut store.db, owner).is_ok()
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|success| *success)
        .count();
    assert!(successes == 1);
    let store = Store::open(path.to_str().unwrap()).unwrap();
    let remaining: String = store
        .db
        .query_row(
            "SELECT user_id FROM organization_memberships WHERE organization_id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(last_owner(&store.db, &remaining).unwrap());
    assert!(
        store
            .db
            .query_row("SELECT count(*) FROM organization_collections", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
            == 1
    );
}

#[tokio::test]
async fn organization_raw_path_segments_reach_authentication_before_uuid_errors() {
    let mut store = fixture(":memory:");
    let organization = create(&mut store, "alice");
    let id = organization["id"].as_str().unwrap();
    let encoded = format!("%{:02X}{}", id.as_bytes()[0], &id[1..]);
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://localhost".into(),
        signing_key: [3; 32],
    };
    for (path, authorized, expected) in [
        ("/api/organizations/bad.id".to_owned(), false, 401),
        ("/api/organizations/bad.id".to_owned(), true, 401),
        (
            format!("/api/organizations/bad.id?organizationId={id}"),
            true,
            422,
        ),
        (format!("/api/organizations/{encoded}"), false, 401),
        (format!("/api/organizations/{encoded}"), true, 200),
        (format!("/api/organizations/%25{id}"), true, 401),
        (
            format!("/api/organizations/%25{id}?organizationId={id}"),
            true,
            422,
        ),
    ] {
        let mut headers = HeaderMap::new();
        if authorized {
            headers.insert(
                "authorization",
                "Bearer organization-fixture-access".parse().unwrap(),
            );
        }
        let response = dispatch(
            State(app.clone()),
            Method::GET,
            path.parse().unwrap(),
            headers,
            Bytes::new(),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert!(
            response.status().as_u16() == expected,
            "Organization path status differs"
        );
        if expected == 200 {
            let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            assert!(serde_json::from_slice::<Value>(&bytes).unwrap() == organization);
        }
    }
}
