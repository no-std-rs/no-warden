use super::*;
use axum::{
    body::{Bytes, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method},
};
use rusqlite::types::Value as SqlValue;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Fixture {
    s: Store,
    org: String,
    collection: String,
    cipher: String,
    folder: String,
}
fn fixture(path: &str) -> Fixture {
    let s = crate::organization_collections::tests::fixture(path);
    let org = crate::organization_collections::tests::org(&s);
    let collection: String =
        s.db.query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let cipher = uuid::Uuid::new_v4().to_string();
    let folder = uuid::Uuid::new_v4().to_string();
    s.db.execute("INSERT INTO organization_memberships VALUES('bob-member',?1,'bob','opaque wrapped key',2,2,0)",[&org]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',1,0,0)",
        [&collection],
    )
    .unwrap();
    let doc = json!({"id":cipher,"type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","secureNote":{"type":0,"nestedOpaque":{"unchanged":[null,"opaque encrypted extension",7]}},"key":"opaque wrapped item key","fields":[{"name":"opaque","value":"opaque","type":0}],"passwordHistory":[{"password":"opaque","lastUsedDate":"2000"}],"favorite":false,"folderId":null,"creationDate":"2000-01-01T00:00:00Z","revisionDate":"2000-01-01T00:00:00Z","deletedDate":null,"organizationId":org,"outerOpaque":{"unchanged":"opaque encrypted extension"}});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,NULL,?2,'cipher',?3,'initial-revision','initial-created')",params![cipher,org,doc.to_string()]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
        params![collection, cipher],
    )
    .unwrap();
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,'bob',NULL,'folder',?2,'folder-revision','folder-created')",params![folder,json!({"id":folder,"name":"opaque folder"}).to_string()]).unwrap();
    for (who, favorite) in [("alice", true), ("bob", false)] {
        s.db.execute(
            "INSERT INTO cipher_annotations VALUES(?1,?2,NULL,?3)",
            params![cipher, who, favorite],
        )
        .unwrap();
    }
    Fixture {
        s,
        org,
        collection,
        cipher,
        folder,
    }
}
fn input(v: Value) -> Input {
    Input::parse(&serde_json::to_vec(&v).unwrap())
        .unwrap_or_else(|_| panic!("Valid input rejected"))
}
fn revision(s: &Store, who: &str) -> String {
    s.db.query_row("SELECT revision FROM accounts WHERE id=?1", [who], |r| {
        r.get(0)
    })
    .unwrap()
}
fn raw(s: &Store, id: &str) -> (Option<String>, Option<String>, String, String, String) {
    s.db.query_row(
        "SELECT owner,organization_id,document,revision,created FROM items WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .unwrap()
}
fn state(s: &Store) -> Vec<Vec<SqlValue>> {
    let mut data = Vec::new();
    for table in [
        "items",
        "accounts",
        "cipher_annotations",
        "organization_memberships",
        "organization_collection_users",
        "organization_collection_ciphers",
        "sessions",
        "device_registry",
        "session_devices",
    ] {
        let mut q =
            s.db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
        let n = q.column_count();
        data.extend(
            q.query_map([], |r| {
                (0..n)
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
fn rejected(result: Result<Value, Failure>) -> Failure {
    match result {
        Err(e) => e,
        Ok(_) => panic!("Invalid operation admitted"),
    }
}
fn personal(f: &Fixture) {
    let mut doc: Value = serde_json::from_str(&raw(&f.s, &f.cipher).2).unwrap();
    doc["organizationId"] = Value::Null;
    f.s.db
        .execute(
            "UPDATE items SET owner='bob',organization_id=NULL,document=?1 WHERE id=?2",
            params![doc.to_string(), f.cipher],
        )
        .unwrap();
}

#[test]
fn readonly_and_manage_annotations_preserve_common_bytes_and_other_account_even_on_noop() {
    let mut f = fixture(":memory:");
    let common = raw(&f.s, &f.cipher);
    let other = revision(&f.s, "alice");
    let owner = sharing::project(&f.s.db, "alice", &f.cipher, true)
        .unwrap()
        .unwrap();
    for manage in [false, true] {
        f.s.db.execute("UPDATE organization_collection_users SET manage=?1 WHERE collection_id=?2 AND user_id='bob'",params![manage,f.collection]).unwrap();
        for _ in 0..2 {
            let old = revision(&f.s, "bob");
            let value=input(json!({"favorite":true,"folderId":f.folder,"name":"ignored","organizationId":"ignored"})).execute(&mut f.s,"bob",&f.cipher).unwrap_or_else(|_|panic!("Readable readonly annotation failed"));
            assert_eq!(value.as_object().unwrap().len(), 30);
            assert_eq!(value["favorite"], true);
            assert_eq!(value["folderId"], f.folder);
            assert_eq!(value["edit"], false);
            assert!(value.get("outerOpaque").is_none());
            assert_eq!(
                value["secureNote"]["nestedOpaque"],
                json!({"unchanged":[null,"opaque encrypted extension",7]})
            );
            assert_eq!(raw(&f.s, &f.cipher), common);
            assert_eq!(revision(&f.s, "alice"), other);
            assert_ne!(revision(&f.s, "bob"), old);
            assert_eq!(
                sharing::project(&f.s.db, "alice", &f.cipher, true)
                    .unwrap()
                    .unwrap(),
                owner
            );
        }
    }
}
#[test]
fn personal_only_two_annotations_change_and_scoped_projection_keeps_unrelated_get_behavior() {
    let mut f = fixture(":memory:");
    personal(&f);
    let before = raw(&f.s, &f.cipher);
    let other = revision(&f.s, "alice");
    let mut expected: Value = serde_json::from_str(&before.2).unwrap();
    expected["favorite"] = json!(true);
    expected["folderId"] = json!(f.folder);
    let value = input(json!({"favorite":true,"folderId":f.folder}))
        .execute(&mut f.s, "bob", &f.cipher)
        .unwrap_or_else(|_| panic!("Personal partial failed"));
    let after = raw(&f.s, &f.cipher);
    assert_eq!(
        (&after.0, &after.1, &after.3, &after.4),
        (&before.0, &before.1, &before.3, &before.4)
    );
    assert_eq!(serde_json::from_str::<Value>(&after.2).unwrap(), expected);
    assert_eq!(revision(&f.s, "alice"), other);
    assert_eq!(value.as_object().unwrap().len(), 30);
    assert!(value.get("outerOpaque").is_none());
    assert!(
        sharing::project(&f.s.db, "bob", &f.cipher, true)
            .unwrap()
            .unwrap()
            .get("outerOpaque")
            .is_some()
    );
    for body in [
        json!({"favorite":false}),
        json!({"favorite":false,"folderId":null}),
        json!({"favorite":false,"folderId":""}),
        json!({"favorite":false,"FolderId":f.folder}),
    ] {
        let v = input(body)
            .execute(&mut f.s, "bob", &f.cipher)
            .unwrap_or_else(|_| panic!("Folder clear failed"));
        assert!(v["folderId"].is_null());
    }
}
#[test]
fn source_membership_and_folder_rejections_leave_all_state_unchanged() {
    let mut f = fixture(":memory:");
    for folder in ["missing".to_owned(), f.cipher.clone()] {
        let before = state(&f.s);
        let e = rejected(
            input(json!({"favorite":true,"folderId":folder})).execute(&mut f.s, "bob", &f.cipher),
        );
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(state(&f.s), before);
    }
    f.s.db
        .execute("UPDATE items SET owner='alice' WHERE id=?1", [&f.folder])
        .unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(
            input(json!({"favorite":true,"folderId":f.folder})).execute(&mut f.s, "bob", &f.cipher)
        )
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s), before);
    for status in [0, 1, -1] {
        f.s.db
            .execute(
                "UPDATE organization_memberships SET status=?1 WHERE user_id='bob'",
                [status],
            )
            .unwrap();
        let before = state(&f.s);
        assert_eq!(
            rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s), before);
    }
    f.s.db
        .execute(
            "UPDATE organization_memberships SET status=2 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    f.s.db
        .execute(
            "DELETE FROM organization_collection_users WHERE user_id='bob'",
            [],
        )
        .unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s), before);
    personal(&f);
    f.s.db
        .execute("UPDATE items SET owner='alice' WHERE id=?1", [&f.cipher])
        .unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s), before);
}
#[test]
fn historical_readonly_grant_requires_current_canonical_membership_not_old_membership_status() {
    let mut f = fixture(":memory:");
    let newer = crate::organization_collections::tests::create_org(&mut f.s, "alice");
    f.s.db.execute("INSERT INTO organization_memberships VALUES('new-bob',?1,'bob','opaque wrapped key',2,2,0)",[&newer]).unwrap();
    f.s.db
        .execute(
            "UPDATE items SET organization_id=?1 WHERE id=?2",
            params![newer, f.cipher],
        )
        .unwrap();
    f.s.db.execute("UPDATE organization_memberships SET status=-1 WHERE user_id='bob' AND organization_id=?1",[&f.org]).unwrap();
    input(json!({"favorite":true}))
        .execute(&mut f.s, "bob", &f.cipher)
        .unwrap_or_else(|_| panic!("Historical read grant failed"));
    f.s.db
        .execute(
            "UPDATE organization_memberships SET status=-1 WHERE id='new-bob'",
            [],
        )
        .unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":false})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s), before);
}
#[test]
fn account_revision_failure_rolls_back_actual_shared_and_personal_annotation_writes() {
    for is_personal in [false, true] {
        let mut f = fixture(":memory:");
        if is_personal {
            personal(&f);
        }
        f.s.db.execute_batch("CREATE TRIGGER fail_partial_revision BEFORE UPDATE OF revision ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'local test rollback'); END;").unwrap();
        let before = state(&f.s);
        assert_eq!(
            rejected(
                input(json!({"favorite":true,"folderId":f.folder}))
                    .execute(&mut f.s, "bob", &f.cipher)
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(state(&f.s), before);
        f.s.db
            .execute_batch("DROP TRIGGER fail_partial_revision")
            .unwrap();
        input(json!({"favorite":true,"folderId":f.folder}))
            .execute(&mut f.s, "bob", &f.cipher)
            .unwrap_or_else(|_| panic!("Retry after rollback failed"));
    }
}
#[test]
fn owned_json_decodes_escaped_folder_and_schema_uses_categories_without_diagnostic_matching() {
    let folder = "aaaaaaaa-0000-0000-0000-000000000000";
    let escaped = Input::parse(
        br#"{"folderId":"\u0061aaaaaaa-0000-0000-0000-000000000000","favorite":true}"#,
    )
    .unwrap_or_else(|_| panic!("Escaped folder rejected"));
    assert_eq!(escaped.folder_id.as_deref(), Some(folder));
    for text in [
        r#"{}"#,
        r#"{"favorite":null}"#,
        r#"{"favorite":"expected fewer elements"}"#,
        r#"{"favorite":0}"#,
        r#"{"favorite":true,"folderId":7}"#,
        r#"{"Favorite":true}"#,
    ] {
        let e = match Input::parse(text.as_bytes()) {
            Err(e) => e,
            Ok(_) => panic!("Wrong schema admitted"),
        };
        assert_eq!(e.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let extra = match Input::parse(br#"[null,true,0]"#) {
        Err(e) => e,
        Ok(_) => panic!("Extra tuple admitted"),
    };
    assert_eq!(extra.0, StatusCode::BAD_REQUEST);
    let tuple = Input::parse(br#"[null,true]"#).unwrap_or_else(|_| panic!("Valid tuple rejected"));
    assert!(tuple.favorite);
    assert!(tuple.folder_id.is_none());
}

static WRITE_BLOCKED: AtomicBool = AtomicBool::new(false);
fn busy(retry: i32) -> bool {
    WRITE_BLOCKED.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(1));
    retry < 5000
}
#[test]
fn immediate_transaction_rechecks_live_authority_identity_and_preserves_current_personal_json() {
    // A real second SQLite writer commits only after the provider reaches its
    // IMMEDIATE lock. WAL permits earlier observational reads of old facts.
    // This tests the storage boundary, not a claim about native concurrency.
    for change in [
        "membership",
        "grant",
        "revision",
        "ownership",
        "folder-owner",
        "folder-identity",
        "folder-kind",
        "personal-current-json",
        "material-budget",
    ] {
        let dir =
            std::env::temp_dir().join(format!("no-warden-partial-race-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let f = fixture(path.to_str().unwrap());
        if change == "personal-current-json" {
            personal(&f);
        }
        let old_account = revision(&f.s, "bob");
        let mut external = Connection::open(&path).unwrap();
        external.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let tx = external
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        match change {
            "membership" => {
                tx.execute(
                    "UPDATE organization_memberships SET status=-1 WHERE user_id='bob'",
                    [],
                )
                .unwrap();
            }
            "grant" => {
                tx.execute(
                    "DELETE FROM organization_collection_users WHERE user_id='bob'",
                    [],
                )
                .unwrap();
            }
            "revision" => {
                tx.execute(
                    "UPDATE items SET revision='concurrent-revision' WHERE id=?1",
                    [&f.cipher],
                )
                .unwrap();
            }
            "ownership" => {
                tx.execute(
                    "UPDATE items SET organization_id=NULL,owner='alice' WHERE id=?1",
                    [&f.cipher],
                )
                .unwrap();
            }
            "folder-owner" => {
                tx.execute("UPDATE items SET owner='alice' WHERE id=?1", [&f.folder])
                    .unwrap();
            }
            "folder-identity" => {
                tx.execute(
                    "UPDATE items SET id=?1 WHERE id=?2",
                    params![uuid::Uuid::new_v4().to_string(), f.folder],
                )
                .unwrap();
            }
            "folder-kind" => {
                tx.execute("UPDATE items SET kind='cipher' WHERE id=?1", [&f.folder])
                    .unwrap();
            }
            "personal-current-json" => {
                tx.execute("UPDATE items SET document=json_set(document,'$.concurrentOpaque',json('{\"kept\":[1,null,\"opaque\"]}')) WHERE id=?1",[&f.cipher]).unwrap();
            }
            "material-budget" => {
                tx.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO organization_collections(id,organization_id,name,external_id) SELECT 'bounded-'||x,?1,'opaque',NULL FROM n",[&f.org]).unwrap();
                tx.execute("INSERT INTO organization_collection_ciphers SELECT id,?1 FROM organization_collections WHERE id LIKE 'bounded-%'",[&f.cipher]).unwrap();
            }
            _ => unreachable!(),
        }
        WRITE_BLOCKED.store(false, Ordering::SeqCst);
        f.s.db.busy_handler(Some(busy)).unwrap();
        let id = f.cipher.clone();
        let folder = f.folder.clone();
        let worker_id = id.clone();
        let worker = std::thread::spawn(move || {
            let mut s = f.s;
            let ok = input(json!({"favorite":true,"folderId":folder}))
                .execute(&mut s, "bob", &worker_id)
                .is_ok();
            (s, ok)
        });
        let start = Instant::now();
        while !WRITE_BLOCKED.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let reached = WRITE_BLOCKED.load(Ordering::SeqCst);
        tx.commit().unwrap();
        let (s, ok) = worker.join().unwrap();
        assert!(reached, "Provider did not reach atomic write boundary");
        assert_eq!(ok, change == "personal-current-json");
        if ok {
            let doc: Value = serde_json::from_str(&raw(&s, &id).2).unwrap();
            assert_eq!(doc["concurrentOpaque"], json!({"kept":[1,null,"opaque"]}));
            assert_eq!(doc["favorite"], true);
            assert_ne!(revision(&s, "bob"), old_account);
        } else {
            assert_eq!(revision(&s, "bob"), old_account);
            let favorite: bool =
                s.db.query_row(
                    "SELECT favorite FROM cipher_annotations WHERE cipher_id=?1 AND user_id='bob'",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!favorite);
        }
        drop(s);
        drop(external);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn bounded_association_preflight_rejects_before_any_annotation_write() {
    let mut f = fixture(":memory:");
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO organization_collections(id,organization_id,name,external_id) SELECT 'bounded-'||x,?1,'opaque',NULL FROM n",[&f.org]).unwrap();
    f.s.db.execute("INSERT INTO organization_collection_ciphers SELECT id,?1 FROM organization_collections WHERE id LIKE 'bounded-%'",[&f.cipher]).unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "not-a-member", &f.cipher)).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s), before);
    for status in [0, -1] {
        f.s.db
            .execute(
                "UPDATE organization_memberships SET status=?1 WHERE user_id='bob'",
                [status],
            )
            .unwrap();
        let before = state(&f.s);
        assert_eq!(
            rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s), before);
    }
    f.s.db
        .execute(
            "UPDATE organization_memberships SET status=2 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s), before);
    personal(&f);
    let before = state(&f.s);
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s), before);
    f.s.db
        .execute(
            "DELETE FROM organization_collection_ciphers WHERE collection_id LIKE 'bounded-%'",
            [],
        )
        .unwrap();
    let huge = "x".repeat(MAX_FACT_BYTES);
    f.s.db
        .execute(
            "INSERT INTO organization_collections VALUES(?1,?2,'opaque',NULL)",
            params![huge, f.org],
        )
        .unwrap();
    f.s.db
        .execute(
            "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
            params![huge, f.cipher],
        )
        .unwrap();
    let before = revision(&f.s, "bob");
    assert_eq!(
        rejected(input(json!({"favorite":true})).execute(&mut f.s, "bob", &f.cipher)).0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(revision(&f.s, "bob"), before);
}
#[tokio::test]
async fn two_authenticated_device_bound_aliases_and_socket_error_shapes() {
    let f = fixture(":memory:");
    let id = f.cipher.clone();
    let app = crate::App {
        store: Arc::new(Mutex::new(f.s)),
        base: "http://localhost".into(),
        signing_key: [1; 32],
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let uri = format!("/api/ciphers/{id}/partial")
        .parse::<axum::http::Uri>()
        .unwrap();
    for method in [Method::PUT, Method::POST] {
        let response = crate::dispatch_http(
            State(app.clone()),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            method.clone(),
            uri.clone(),
            headers.clone(),
            Bytes::from_static(br#"{"favorite":true}"#),
        )
        .await
        .unwrap_or_else(|_| panic!("Partial alias rejected"));
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body.as_object().unwrap().len(), 30);
        assert_eq!(body["favorite"], true);
        for (text, status) in [
            (br#"{}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"[null,true,0]"#.as_slice(), StatusCode::BAD_REQUEST),
        ] {
            let response = crate::dispatch_http(
                State(app.clone()),
                ConnectInfo("127.0.0.1:12345".parse().unwrap()),
                method.clone(),
                uri.clone(),
                headers.clone(),
                Bytes::copy_from_slice(text),
            )
            .await
            .unwrap_or_else(|_| panic!("Socket error not rendered"));
            assert_eq!(response.status(), status);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap())
                    .unwrap();
            assert_eq!(
                body.as_object().unwrap().keys().collect::<Vec<_>>(),
                vec!["error"]
            );
        }
    }
    let before = revision(&app.store.lock().unwrap(), "alice");
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let e = match crate::dispatch(
        State(app.clone()),
        Method::PUT,
        uri,
        headers,
        Bytes::from_static(br#"{"favorite":false}"#),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("Unbound session admitted"),
    };
    assert_eq!(e.0, StatusCode::UNAUTHORIZED);
    assert_eq!(revision(&app.store.lock().unwrap(), "alice"), before);
}
