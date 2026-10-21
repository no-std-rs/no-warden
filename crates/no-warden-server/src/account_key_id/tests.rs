use super::*;
use crate::{App, store::Store};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
};
use no_warden::{Storage, VaultService};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier, Mutex};

fn fixture(path: &str) -> Store {
    let store = Store::open(path).expect("Key-ID fixture database failed");
    for owner in ["alice", "bob"] {
        let document = json!({"id":owner,"email":format!("{owner}@example.test"),
            "key":"opaque-wrapped-key","keys":{"publicKey":"opaque-public","encryptedPrivateKey":"opaque-private"},
            "securityStamp":"opaque-stamp","revisionDate":"2000-01-01T00:00:00.000Z","futureField":{"preserved":true}});
        store.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",
            params![owner,format!("{owner}@example.test"),document.to_string()]).unwrap();
        store
            .db
            .execute(
                "INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher',?3,0,'2000-01-01','2000-01-01')",
                params![
                    format!("{owner}-cipher"),
                    owner,
                    json!({"name":"opaque-cipher","futureField":{"preserved":true}}).to_string()
                ],
            )
            .unwrap();
    }
    let access = crate::digest("fixture-key-id-access");
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
    store.db.execute("INSERT INTO device_registry VALUES('alice','fixture-device','fixture',23,'2000-01-01','2000-01-01')",[]).unwrap();
    store
        .db
        .execute(
            "INSERT INTO session_devices VALUES(?1,'alice','fixture-device')",
            [access],
        )
        .unwrap();
    store
}
fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut result = Vec::new();
    for table in [
        "accounts",
        "items",
        "sessions",
        "device_registry",
        "session_devices",
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
fn write(store: &mut Store, id: &str) -> Result<(), no_warden::ApiError> {
    VaultService::new(store).set_user_key_id("alice", &UserKeyIdRequest { user_key_id: id })
}

#[test]
fn key_id_owned_decode_accepts_opaque_strings_and_matches_parse_error_categories() {
    for (body, expected) in [
        (br#"{"userKeyId":""}"#.as_slice(), ""),
        (
            br#"{"userKeyId":"opaque\u0000\u96ea","userId":"forged","unknown":1,"unknown":2}"#,
            "opaque\0雪",
        ),
        (br#"["positional"]"#, "positional"),
        (
            br#"{"userKeyId":"canonical","UserKeyId":"ignored"}"#,
            "canonical",
        ),
    ] {
        let input = Input::parse(body).unwrap_or_else(|_| panic!("Valid key-ID schema rejected"));
        assert!(input.request().user_key_id == expected);
    }
    for body in [
        b"{}".as_slice(),
        b"[]",
        br#"{"UserKeyId":"wrong-case"}"#,
        br#"{"userKeyId":null}"#,
        br#"{"userKeyId":2}"#,
        br#"{"userKeyId":"one","user\u004beyId":"two"}"#,
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for body in [
        b"{".as_slice(),
        b"",
        b"{\"userKeyId\":\"would-initialize\",\"ignored\":\"\xff\"}",
        br#"["one","extra"]"#,
        br#"{"userKeyId":"one"} true"#,
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
}

#[test]
fn key_id_empty_assignment_is_immutable_and_changes_only_owner_id_and_revision() {
    let mut store = fixture(":memory:");
    let before = snapshot(&store);
    let owner_before = store.account("id", "alice").unwrap().unwrap();
    write(&mut store, "").unwrap();
    assert!(store.user_key_id("alice").unwrap() == Some(""));
    let mut owner_after = store.account("id", "alice").unwrap().unwrap();
    assert!(owner_after["revisionDate"] != owner_before["revisionDate"]);
    owner_after.as_object_mut().unwrap().remove("userKeyId");
    owner_after["revisionDate"] = owner_before["revisionDate"].clone();
    assert!(owner_after == owner_before);
    let accepted = snapshot(&store);
    assert!(accepted[1..] == before[1..]); // Only the first account row changes.
    for candidate in ["", "replacement"] {
        let error = write(&mut store, candidate).unwrap_err();
        assert!(error.status_code() == 422 && error.message == "Unexpected data");
        assert!(snapshot(&store) == accepted);
    }
}

#[test]
fn key_id_sqlite_preserves_long_unicode_and_nul_values_across_reopen() {
    let directory = PrivateDirectory::new();
    let path = directory.path.join("vault.db");
    let mut store = fixture(path.to_str().unwrap());
    let value = format!("prefix\0{}", "雪é".repeat(300));
    write(&mut store, &value).unwrap();
    assert!(store.user_key_id("alice").unwrap() == Some(value.as_str()));
    let accepted = snapshot(&store);
    drop(store);
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(store.user_key_id("alice").unwrap() == Some(value.as_str()));
    assert!(write(&mut store, "replacement").is_err());
    assert!(snapshot(&store) == accepted);
}

#[test]
fn key_id_failed_revision_or_commit_rolls_back_assignment_and_all_other_state() {
    for failure in ["revision", "commit"] {
        let mut store = fixture(":memory:");
        let before = snapshot(&store);
        if failure == "revision" {
            store.db.execute_batch("CREATE TRIGGER reject_key_id BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'fixture revision fault'); END;").unwrap();
        } else {
            store.db.execute_batch("CREATE TABLE rejected_key_id(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_key_id AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO rejected_key_id VALUES('missing'); END;").unwrap();
        }
        assert!(write(&mut store, "candidate").is_err());
        assert!(snapshot(&store) == before && store.user_key_id("alice").unwrap().is_none());
        store
            .db
            .execute_batch("DROP TRIGGER reject_key_id;")
            .unwrap();
        write(&mut store, "retry").unwrap();
        assert!(store.user_key_id("alice").unwrap() == Some("retry"));
    }
}

#[test]
fn key_id_two_connections_cannot_overwrite_the_first_committed_identifier() {
    let directory = PrivateDirectory::new();
    let path = directory.path.join("vault.db");
    let first = fixture(path.to_str().unwrap());
    let second = Store::open(path.to_str().unwrap()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [first, second]
        .into_iter()
        .enumerate()
        .map(|(index, mut store)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                store
                    .db
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                barrier.wait();
                let candidate = if index == 0 { "first" } else { "second" };
                (candidate, write(&mut store, candidate))
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(results.iter().filter(|(_, r)| r.is_ok()).count() == 1);
    assert!(
        results
            .iter()
            .filter(|(_, r)| r.as_ref().is_err_and(|e| e.status_code() == 422))
            .count()
            == 1
    );
    let winner = results.iter().find(|(_, r)| r.is_ok()).unwrap().0;
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(store.user_key_id("alice").unwrap() == Some(winner));
}

#[tokio::test]
async fn key_id_dispatch_checks_current_device_before_schema_and_ignores_media_type() {
    let app = App {
        store: Arc::new(Mutex::new(fixture(":memory:"))),
        base: "http://127.0.0.1".into(),
        signing_key: [7; 32],
    };
    let path: Uri = "/api/accounts/key-management/user-key-id".parse().unwrap();
    let before = snapshot(&app.store.lock().unwrap());
    for (bearer, bound) in [(false, true), (true, false)] {
        let mut headers = HeaderMap::new();
        if bearer {
            headers.insert(
                "authorization",
                "Bearer fixture-key-id-access".parse().unwrap(),
            );
        }
        if !bound {
            app.store
                .lock()
                .unwrap()
                .db
                .execute("DELETE FROM session_devices", [])
                .unwrap();
        }
        let error = crate::dispatch(
            State(app.clone()),
            Method::POST,
            path.clone(),
            headers,
            Bytes::from_static(b"{"),
        )
        .await
        .err()
        .unwrap();
        assert!(error.0 == StatusCode::UNAUTHORIZED);
    }
    {
        let store = app.store.lock().unwrap();
        store
            .db
            .execute(
                "INSERT INTO session_devices VALUES(?1,'alice','fixture-device')",
                [crate::digest("fixture-key-id-access")],
            )
            .unwrap();
        assert!(snapshot(&store) == before);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer fixture-key-id-access".parse().unwrap(),
    );
    headers.insert("content-type", "text/plain".parse().unwrap());
    let response = crate::dispatch(
        State(app.clone()),
        Method::POST,
        path.clone(),
        headers.clone(),
        Bytes::from_static(br#"{"userKeyId":"opaque"}"#),
    )
    .await
    .unwrap_or_else(|_| panic!("Bound owner migration rejected"));
    assert!(
        response.status() == StatusCode::OK
            && axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
    );
    let error = crate::dispatch(
        State(app),
        Method::POST,
        path,
        headers,
        Bytes::from_static(br#"{"userKeyId":"replacement"}"#),
    )
    .await
    .err()
    .unwrap();
    assert!(error.0 == StatusCode::UNPROCESSABLE_ENTITY && error.1 == "Unexpected data");
    let response = crate::password_login::error_response(error.0, error.1);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        value.as_object().unwrap().len() == 9
            && value["message"] == "Unexpected data"
            && value["errorModel"]["message"] == "Unexpected data"
    );
}

struct PrivateDirectory {
    path: std::path::PathBuf,
}
impl PrivateDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("no-warden-key-id-unit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { path }
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
