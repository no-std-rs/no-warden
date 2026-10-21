use super::*;
use crate::{App, store::Store};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
};
use no_warden::{VaultService, wire::CompletePreloginResponse};
use rusqlite::{params, types::Value as SqlValue};
use serde_json::json;
use std::sync::{Arc, Mutex};

fn fixture(path: &str) -> Store {
    let store = Store::open(path).unwrap();
    for (owner, email, values) in [
        ("alice", "alice@example.test", [0, 100_000, 0, 0]),
        ("bob", "bob@example.test", [1, 3, 64, 4]),
        ("unicode", "i\u{307}@example.test", [-7, -8, -9, i32::MAX]),
    ] {
        let document = json!({"id":owner,"email":email,"kdf":values[0],"kdfIterations":values[1],
            "kdfMemory":if values[0] == 0 {Value::Null} else {json!(values[2])},
            "kdfParallelism":if values[0] == 0 {Value::Null} else {json!(values[3])},
            "key":"opaque-wrapped-key","futureField":{"preserved":true},
            "securityStamp":"opaque-stamp","revisionDate":"2000-01-01T00:00:00.000Z"});
        store.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",
            params![owner,email,document.to_string()]).unwrap();
        store
            .db
            .execute(
                "INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher',?3,0,'2000-01-01','2000-01-01')",
                params![
                    format!("{owner}-cipher"),
                    owner,
                    json!({"name":"opaque-cipher","futureField":[1,2]}).to_string()
                ],
            )
            .unwrap();
    }
    store.db.execute("INSERT INTO sessions VALUES('opaque-access','opaque-refresh','alice',2000000000,2000003600)",[]).unwrap();
    store.db.execute("INSERT INTO device_registry VALUES('alice','device','fixture',23,'2000-01-01','2000-01-01')",[]).unwrap();
    store
        .db
        .execute(
            "UPDATE prelogin_key SET secret=?1",
            [([7_u8; 32]).as_slice()],
        )
        .unwrap();
    store
}

type Snapshot = Vec<(String, Vec<Vec<SqlValue>>)>;
fn snapshot(store: &Store) -> Snapshot {
    let tables = store
        .db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut statement = store
                .db
                .prepare(&format!(
                    "SELECT * FROM \"{}\" ORDER BY rowid",
                    table.replace('"', "\"\"")
                ))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}
fn discover(store: &mut Store, email: &str) -> CompletePreloginResponse {
    VaultService::new(store)
        .prelogin(&PreloginRequest { email })
        .unwrap()
}

#[test]
fn prelogin_owned_schema_preserves_escapes_and_classifies_guard_errors() {
    for (body, expected) in [
        (br#"{"email":""}"#.as_slice(), ""),
        (br#"["opaque\u0000\u96ea"]"#, "opaque\0雪"),
        (
            br#"{"email":"canonical","Email":"ignored","future":1,"future":2}"#,
            "canonical",
        ),
    ] {
        let input = Input::parse(body).unwrap_or_else(|_| panic!("Valid prelogin schema rejected"));
        assert!(input.request().email == expected);
    }
    for body in [
        b"{}".as_slice(),
        b"[]",
        br#"{"Email":"wrong-case"}"#,
        br#"{"email":null}"#,
        br#"{"email":7}"#,
        br#"{"email":"one","em\u0061il":"two"}"#,
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for body in [
        b"".as_slice(),
        b"{",
        br#"["one","extra"]"#,
        br#"{"email":"one"} true"#,
        b"{\"email\":\"one\",\"ignored\":\"\xff\"}",
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
}

#[test]
fn prelogin_known_signed_settings_normalize_once_and_leave_all_state_unchanged() {
    let mut store = fixture(":memory:");
    let before = snapshot(&store);
    for (email, expected) in [
        (
            "\u{2003}ALICE@EXAMPLE.TEST\u{a0}",
            PreloginKdfSettings {
                kdf_type: 0,
                iterations: 100_000,
                memory: None,
                parallelism: None,
            },
        ),
        (
            "BOB@example.test",
            PreloginKdfSettings {
                kdf_type: 1,
                iterations: 3,
                memory: Some(64),
                parallelism: Some(4),
            },
        ),
        (
            "\u{2003}İ@EXAMPLE.TEST\u{a0}",
            PreloginKdfSettings {
                kdf_type: -7,
                iterations: -8,
                memory: Some(-9),
                parallelism: Some(i32::MAX),
            },
        ),
    ] {
        let response = discover(&mut store, email);
        assert!(response.settings() == expected);
        let value = serde_json::to_value(response).unwrap();
        assert!(value.as_object().unwrap().len() == 6 && value["salt"].is_null());
        assert!(value["kdf"] == expected.kdf_type && value["kdfIterations"] == expected.iterations);
        assert!(value["kdfSettings"] == serde_json::to_value(expected).unwrap());
        assert!(snapshot(&store) == before);
    }
}

#[test]
fn prelogin_unknown_choices_use_the_persistent_private_key_and_normalized_email() {
    let mut store = fixture(":memory:");
    let before = snapshot(&store);
    // Independent HMAC-SHA256 vectors with a 32-byte 0x07 key select slots 2 and 4.
    for (email, variant, index) in [
        (
            "nobody@example.test",
            "\u{2003}NOBODY@EXAMPLE.TEST\u{a0}",
            2,
        ),
        ("other@example.test", " OTHER@EXAMPLE.TEST\n", 4),
        ("", "\u{2003}\n", 2),
    ] {
        let expected = UNKNOWN_KDF_CATALOG[index];
        for query in [email, variant, email] {
            assert!(discover(&mut store, query).settings() == expected);
            assert!(snapshot(&store) == before);
        }
    }
    let first = discover(&mut store, "unknown\0雪").settings();
    assert!(UNKNOWN_KDF_CATALOG.contains(&first));
    assert!(discover(&mut store, "unknown\0雪").settings() == first);
    assert!(snapshot(&store) == before);
}

#[test]
fn prelogin_installation_secret_and_unknown_choice_survive_database_reopen() {
    let directory = PrivateDirectory::new();
    let path = directory.path.join("vault.db");
    let mut store = fixture(path.to_str().unwrap());
    let before = snapshot(&store);
    let response = discover(&mut store, "nobody@example.test").settings();
    drop(store);
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == before);
    assert!(discover(&mut store, "NOBODY@EXAMPLE.TEST").settings() == response);
    assert!(snapshot(&store) == before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777 == 0o600);
    }
}

#[test]
fn prelogin_provider_errors_map_without_replacing_them_with_unknown_account_success() {
    let mut store = fixture(":memory:");
    store
        .db
        .execute(
            "UPDATE accounts SET document=json_set(document,'$.kdf',2147483648) WHERE id='alice'",
            [],
        )
        .unwrap();
    let before = snapshot(&store);
    let error = VaultService::new(&mut store)
        .prelogin(&PreloginRequest {
            email: "alice@example.test",
        })
        .unwrap_err();
    assert!(error.status_code() == 500 && snapshot(&store) == before);
    store.db.execute("DELETE FROM prelogin_key", []).unwrap();
    let before = snapshot(&store);
    let error = VaultService::new(&mut store)
        .prelogin(&PreloginRequest {
            email: "nobody@example.test",
        })
        .unwrap_err();
    assert!(error.status_code() == 500 && snapshot(&store) == before);
    assert!(discover(&mut store, "bob@example.test").settings().kdf_type == 1);
}

#[tokio::test]
async fn prelogin_dispatch_aliases_are_public_and_accept_json_independently_of_media_type() {
    let app = App {
        store: Arc::new(Mutex::new(fixture(":memory:"))),
        base: "http://127.0.0.1".into(),
        signing_key: [1; 32],
    };
    let before = snapshot(&app.store.lock().unwrap());
    for path in [
        "/identity/accounts/prelogin",
        "/identity/accounts/prelogin/password",
        "/api/accounts/prelogin",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer deliberately-invalid".parse().unwrap(),
        );
        headers.insert("content-type", "text/plain".parse().unwrap());
        let response = crate::dispatch(
            State(app.clone()),
            Method::POST,
            format!("{path}?email=bob%40example.test")
                .parse::<Uri>()
                .unwrap(),
            headers.clone(),
            Bytes::from_static(br#"{"email":"ALICE@EXAMPLE.TEST"}"#),
        )
        .await
        .unwrap_or_else(|_| panic!("Public prelogin failed"));
        assert!(response.status() == StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            value["kdf"] == 0
                && value["kdfIterations"] == 100_000
                && value["kdfMemory"].is_null()
                && value["salt"].is_null()
        );
        for (body, status) in [(br#"{}"#.as_slice(), 422), (b"{", 400)] {
            let error = crate::dispatch(
                State(app.clone()),
                Method::POST,
                path.parse().unwrap(),
                headers.clone(),
                Bytes::copy_from_slice(body),
            )
            .await
            .err()
            .unwrap();
            assert!(error.0.as_u16() == status);
        }
    }
    assert!(snapshot(&app.store.lock().unwrap()) == before);
}

struct PrivateDirectory {
    path: std::path::PathBuf,
}
impl PrivateDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("no-warden-prelogin-test-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self { path }
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
