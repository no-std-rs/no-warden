//! Adapter invariants for opaque file Send bytes, independently authored fixtures.
use crate::{send_files, sends, store::Store};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
};
use no_warden::{
    VaultService,
    identity::Secret,
    sends::{FileSendStorage, SendFileUpload},
};
use rusqlite::{params, types::Value as SqlValue};
use serde_json::{Value, json};

const BYTES: &[u8] = &[0, 255, 13, 10, 128, 3];
const NAME: &str = "opaque-encrypted-filename";

fn fixture(path: &str) -> Store {
    let store = Store::open(path).expect("Private fixture database failed");
    for owner in ["alice", "bob"] {
        store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'unused','2000-01-01T00:00:00.000Z')",
            params![owner, format!("{owner}@example.test"), json!({"id":owner,"key":"opaque-account-key","revisionDate":"2000-01-01T00:00:00.000Z"}).to_string()]).expect("Fixture account failed");
    }
    configure(store)
}
fn configure(mut store: Store) -> Store {
    store.download_base = "http://127.0.0.1:18600".into();
    store
}
fn input(file: Value) -> sends::Input {
    let deletion = (chrono::Utc::now() + chrono::TimeDelta::days(1)).to_rfc3339();
    sends::Input::parse(&serde_json::to_vec(&json!({"type":1,"name":"opaque-name","key":"opaque-key",
        "notes":"opaque-notes","file":file,"fileLength":BYTES.len(),"deletionDate":deletion,"disabled":false})).unwrap())
        .unwrap_or_else(|_| panic!("Valid file fixture rejected"))
}
fn reserve(store: &mut Store, owner: &str, file: Value) -> Value {
    let input = input(file);
    input.stage_dates(store);
    let request = input.file_request();
    let mut service = VaultService::new(store);
    let response = service
        .reserve_file_send(owner, &request, &sends::context())
        .unwrap();
    serde_json::to_value(response).unwrap()
}
fn reservation(store: &mut Store, owner: &str) -> (String, String) {
    let value = reserve(store, owner, json!({"fileName":NAME}));
    (
        value["sendResponse"]["id"].as_str().unwrap().into(),
        value["sendResponse"]["file"]["id"].as_str().unwrap().into(),
    )
}
fn upload(
    store: &mut Store,
    owner: &str,
    id: &str,
    file: &str,
    bytes: &[u8],
) -> Result<(), no_warden::ApiError> {
    store.pending_send_file_data = bytes.to_vec();
    let result = VaultService::new(&mut *store).upload_send_file(
        owner,
        id,
        file,
        &SendFileUpload {
            file_name: Some(NAME),
            file_size: bytes.len() as u64,
            allow_legacy_filename_suffix: false,
        },
    );
    store.pending_send_file_data.clear();
    result
}
fn document(store: &mut Store, owner: &str, id: &str) -> Value {
    serde_json::to_value(VaultService::new(store).get_send(owner, id).unwrap()).unwrap()
}
fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut values = Vec::new();
    for table in [
        "accounts",
        "personal_sends",
        "send_files",
        "send_file_reservations",
        "send_signing_key",
    ] {
        let mut statement = store
            .db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = statement.column_count();
        values.extend(
            statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    values
}
fn count(store: &Store, table: &str, id: &str) -> i64 {
    store
        .db
        .query_row(
            &format!("SELECT count(*) FROM {table} WHERE send_id=?1"),
            [id],
            |row| row.get(0),
        )
        .unwrap()
}
fn query(store: &mut Store, id: &str, file: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let proof = sends::token(
        &sends::signing_key(&store.db).unwrap(),
        &sends::Claims {
            nbf: now,
            exp: now + 120,
            iss: sends::issuer(&store.download_base).unwrap(),
            sub: format!("{id}/{file}"),
        },
    )
    .unwrap();
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("t", &proof)
        .finish()
}
async fn read(store: &mut Store, id: &str, file: &str, query: &str) -> Vec<u8> {
    let response = send_files::download(store, id, file, Some(query))
        .unwrap_or_else(|_| panic!("Authorized binary read failed"));
    assert!(
        response.status() == StatusCode::OK
            && response.headers().get(header::CONTENT_TYPE).is_none()
    );
    axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("Binary response failed")
        .to_vec()
}

#[test]
fn file_send_reservation_projects_generated_metadata_and_scalar_upload_urls() {
    let mut store = fixture(":memory:");
    let owner_before = store.account("id", "alice").unwrap();
    let foreign_before = store.account("id", "bob").unwrap();
    let value = reserve(
        &mut store,
        "alice",
        json!({"id":"forged","size":999,"sizeName":"forged","fileName":NAME,
        "response":"remove","Future":[{"NestedKey":"opaque-value"}]}),
    );
    let send = &value["sendResponse"];
    let id = send["id"].as_str().unwrap();
    let file = send["file"]["id"].as_str().unwrap();
    assert!(value.as_object().unwrap().len() == 4 && send.as_object().unwrap().len() == 18);
    assert!(
        value["fileUploadType"] == 0
            && value["object"] == "send-fileUpload"
            && value["url"] == format!("/sends/{id}/file/{file}")
    );
    assert!(
        file.len() == 64
            && file
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(
        send["type"] == 1
            && send["text"].is_null()
            && send["file"]["size"].as_str() == Some("6")
            && send["file"]["sizeName"] == "6.00 bytes"
    );
    assert!(
        send["file"]["fileName"] == NAME
            && send["file"].get("response").is_none()
            && send["file"]["future"][0]["nestedKey"] == "opaque-value"
    );
    assert!(
        count(&store, "send_files", id) == 0
            && count(&store, "send_file_reservations", id) == 1
            && store.account("id", "bob").unwrap() == foreign_before
            && store.account("id", "alice").unwrap() != owner_before
    );
    let scalar = reserve(&mut store, "alice", json!("opaque-scalar"));
    let scalar_id = scalar["sendResponse"]["id"].as_str().unwrap();
    assert!(scalar["sendResponse"]["file"].is_null());
    let url = scalar["url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("/sends/{scalar_id}/file/"))
            && count(&store, "send_file_reservations", scalar_id) == 1
    );
}

#[test]
fn file_send_upload_rolls_back_bytes_revision_and_deferred_commit_then_retries() {
    for fault in 0..3 {
        let mut store = fixture(":memory:");
        let (id, file) = reservation(&mut store, "alice");
        let original = document(&mut store, "alice", &id);
        let owner_before = store.account("id", "alice").unwrap();
        let trigger = match fault {
            0 => {
                "CREATE TRIGGER reject_upload BEFORE INSERT ON send_files BEGIN SELECT RAISE(ABORT,'injected blob failure'); END;"
            }
            1 => {
                "CREATE TRIGGER reject_upload BEFORE UPDATE OF revision ON accounts WHEN NEW.id='alice' BEGIN SELECT RAISE(ABORT,'injected revision failure'); END;"
            }
            _ => {
                "CREATE TABLE failed_file_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_upload AFTER INSERT ON send_files BEGIN INSERT INTO failed_file_commit(owner) VALUES('missing-owner'); END;"
            }
        };
        store.db.execute_batch(trigger).unwrap();
        let before = snapshot(&store);
        assert!(upload(&mut store, "alice", &id, &file, BYTES).is_err());
        assert!(
            store.db.is_autocommit()
                && snapshot(&store) == before
                && count(&store, "send_files", &id) == 0
        );
        if fault == 2 {
            assert!(
                store
                    .db
                    .query_row("SELECT count(*) FROM failed_file_commit", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap()
                    == 0
            );
        }
        store
            .db
            .execute_batch("DROP TRIGGER reject_upload")
            .unwrap();
        upload(&mut store, "alice", &id, &file, BYTES).unwrap();
        assert!(
            count(&store, "send_files", &id) == 1 && document(&mut store, "alice", &id) == original
        );
        assert!(snapshot(&store) != before);
        assert!(store.account("id", "alice").unwrap() != owner_before);
    }
}

#[test]
fn file_send_duplicate_upload_returns_opendal_without_overwriting_or_touching_revisions() {
    let mut store = fixture(":memory:");
    let (id, file) = reservation(&mut store, "alice");
    upload(&mut store, "alice", &id, &file, BYTES).unwrap();
    let before = snapshot(&store);
    let changed = vec![17_u8; BYTES.len()];
    let error = upload(&mut store, "alice", &id, &file, &changed).unwrap_err();
    assert!(error.status_code() == 400 && error.message == "OpenDAL" && snapshot(&store) == before);
    let stored: Vec<u8> = store
        .db
        .query_row(
            "SELECT data FROM send_files WHERE send_id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(stored == BYTES);
}

#[tokio::test]
async fn file_send_binary_and_private_signing_key_survive_database_reopen() {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(
        std::env::temp_dir().join(format!("no-warden-file-send-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.0.join("vault.sqlite");
    let mut store = fixture(path.to_str().unwrap());
    let (id, file) = reservation(&mut store, "alice");
    upload(&mut store, "alice", &id, &file, BYTES).unwrap();
    let query = query(&mut store, &id, &file);
    let key = sends::signing_key(&store.db).unwrap();
    let before = snapshot(&store);
    drop(store);
    let mut store = configure(Store::open(path.to_str().unwrap()).unwrap());
    assert!(sends::signing_key(&store.db).unwrap() == key && snapshot(&store) == before);
    assert!(read(&mut store, &id, &file, &query).await == BYTES && snapshot(&store) == before);
}

#[test]
fn file_send_updates_preserve_immutable_metadata_and_reject_foreign_owners() {
    let mut store = fixture(":memory:");
    let (id, file) = reservation(&mut store, "alice");
    upload(&mut store, "alice", &id, &file, BYTES).unwrap();
    let original = document(&mut store, "alice", &id);
    let before = snapshot(&store);
    let changed = input(json!({"id":"forged","size":1,"fileName":"changed-opaque"}));
    let request = changed.file_request();
    changed.stage_dates(&mut store);
    assert!(
        VaultService::new(&mut store)
            .update_file_send("bob", &id, &request, &sends::context())
            .is_err()
    );
    assert!(snapshot(&store) == before);
    changed.stage_dates(&mut store);
    let mut service = VaultService::new(&mut store);
    let response = service
        .update_file_send("alice", &id, &request, &sends::context())
        .unwrap();
    let response = serde_json::to_value(response).unwrap();
    assert!(response["file"] == original["file"] && count(&store, "send_files", &id) == 1);
    let before = snapshot(&store);
    assert!(upload(&mut store, "bob", &id, &file, BYTES).is_err() && snapshot(&store) == before);
}

#[tokio::test]
async fn file_send_download_ignores_current_policy_but_deletion_cascades_only_owned_bytes() {
    let mut store = fixture(":memory:");
    let (id, file) = reservation(&mut store, "alice");
    let (foreign, foreign_file) = reservation(&mut store, "bob");
    upload(&mut store, "alice", &id, &file, BYTES).unwrap();
    upload(&mut store, "bob", &foreign, &foreign_file, BYTES).unwrap();
    let capability_started = std::time::Instant::now();
    let proof = query(&mut store, &id, &file);
    let foreign_proof = query(&mut store, &foreign, &foreign_file);
    let foreign_before = document(&mut store, "bob", &foreign);
    let bob_before = store.account("id", "bob").unwrap();
    store.db.execute("UPDATE personal_sends SET disabled=1,expiration='2000-01-01T00:00:00Z',deletion='2000-01-01T00:00:00Z',max_access_count=0 WHERE id=?1",[&id]).unwrap();
    let before = snapshot(&store);
    assert!(read(&mut store, &id, &file, &proof).await == BYTES && snapshot(&store) == before);
    VaultService::new(&mut store)
        .delete_send("alice", &id)
        .unwrap();
    assert!(
        send_files::download(&mut store, &id, &file, Some(&proof))
            .err()
            .is_some_and(|error| error.0 == StatusCode::NOT_FOUND)
    );
    assert!(
        count(&store, "send_files", &id) == 0 && count(&store, "send_file_reservations", &id) == 0
    );
    let (second, second_file) = reservation(&mut store, "alice");
    upload(&mut store, "alice", &second, &second_file, BYTES).unwrap();
    // This isolates SQLite's account FK cascade, not the broader deletion API policy.
    store
        .db
        .execute("DELETE FROM accounts WHERE id='alice'", [])
        .unwrap();
    assert!(
        count(&store, "send_files", &second) == 0
            && count(&store, "send_file_reservations", &second) == 0
    );
    assert!(read(&mut store, &foreign, &foreign_file, &foreign_proof).await == BYTES);
    assert!(
        document(&mut store, "bob", &foreign) == foreign_before
            && store.account("id", "bob").unwrap() == bob_before
    );
    assert!(capability_started.elapsed() < std::time::Duration::from_secs(60));
}

#[tokio::test]
async fn file_send_multipart_ignores_unknown_fields_and_uses_first_matching_data_root() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "multipart/form-data; boundary=unit-boundary"
            .parse()
            .unwrap(),
    );
    for name in ["data", "data.x", "data[x]", ".data", "[data]"] {
        let body = format!(
            "--unit-boundary\r\nContent-Disposition: form-data; name=\"future\"\r\n\r\nignored\r\n--unit-boundary\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"first\"\r\nContent-Type: application/octet-stream\r\n\r\nfirst-body\r\n--unit-boundary\r\nContent-Disposition: form-data; name=\"data\"; filename=\"second\"\r\n\r\nsecond-body\r\n--unit-boundary--\r\n"
        );
        let parsed = send_files::parse_upload(&headers, Bytes::from(body))
            .await
            .unwrap_or_else(|_| panic!("Valid multipart rejected"));
        assert!(parsed.file_name.as_deref() == Some("first") && parsed.data == b"first-body");
    }
    let missing=Bytes::from_static(b"--unit-boundary\r\nContent-Disposition: form-data; name=\"DATA\"; filename=\"ignored\"\r\n\r\nignored\r\n--unit-boundary--\r\n");
    assert!(
        send_files::parse_upload(&headers, missing)
            .await
            .err()
            .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
    );
}

#[tokio::test]
async fn file_send_download_query_uses_first_exact_root_and_distinguishes_missing_from_empty() {
    let mut store = fixture(":memory:");
    let (id, file) = reservation(&mut store, "alice");
    upload(&mut store, "alice", &id, &file, BYTES).unwrap();
    let canonical = query(&mut store, &id, &file);
    let proof = url::form_urlencoded::parse(canonical.as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    for name in ["t", "t.x", "t[x]", ".t", "[t]"] {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(name, &proof)
            .append_pair("t", "invalid-later")
            .finish();
        let before = snapshot(&store);
        assert!(
            read(&mut store, &id, &file, &encoded).await == BYTES && snapshot(&store) == before
        );
    }
    for query in [None, Some("T=ignored"), Some("unknown=value")] {
        assert!(
            send_files::download(&mut store, &id, &file, query)
                .err()
                .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for query in ["t=", "t=invalid", "t=invalid&t=ignored"] {
        assert!(
            send_files::download(&mut store, &id, &file, Some(query))
                .err()
                .is_some_and(|error| error.0 == StatusCode::NOT_FOUND)
        );
    }
    assert!(
        send_files::download(&mut store, "malformed!", &file, None)
            .err()
            .is_some_and(|error| error.0 == StatusCode::UNPROCESSABLE_ENTITY)
    );
    assert!(
        store
            .verify_send_file_download(&id, &file, &Secret::new("invalid"))
            .is_ok_and(|valid| !valid)
    );
}
