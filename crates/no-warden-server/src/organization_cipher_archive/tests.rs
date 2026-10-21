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
}
fn fixture(path: &str) -> Fixture {
    let s = crate::organization_collections::tests::fixture(path);
    let org = crate::organization_collections::tests::org(&s);
    let collection: String =
        s.db.query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    for user in ["carol", "david", "erin"] {
        let doc = json!({"id":user,"email":format!("{user}@example.test"),"key":"opaque account key","privateKey":"opaque account private key","securityStamp":"unchanged stamp","revisionDate":"2000-01-01T00:00:00.000Z"});
        s.db.execute(
            "INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",
            params![user, format!("{user}@example.test"), doc.to_string()],
        )
        .unwrap();
    }
    for (id, user, role, status) in [
        ("bob-member", "bob", 2, 2),
        ("carol-member", "carol", 2, 2),
        ("david-member", "david", 1, 1),
        ("erin-member", "erin", 1, -1),
    ] {
        s.db.execute("INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque wrapped org key',?4,?5,0)",params![id,org,user,role,status]).unwrap();
    }
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',1,0,0)",
        [&collection],
    )
    .unwrap();
    let cipher = add_shared(&s, &org, &collection);
    s.db.execute_batch("CREATE TABLE archive_revision_writes(user_id TEXT NOT NULL); CREATE TRIGGER archive_revision_audit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO archive_revision_writes VALUES(NEW.id); END;").unwrap();
    Fixture {
        s,
        org,
        collection,
        cipher,
    }
}
fn add_shared(s: &Store, org: &str, collection: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let doc = json!({"id":id,"type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","key":"opaque wrapped cipher key","secureNote":{"type":0,"nestedOpaque":{"unchanged":[null,"opaque encrypted extension",7]}},"fields":[{"name":"opaque","value":"opaque","type":0}],"passwordHistory":[{"password":"opaque","lastUsedDate":"2000"}],"favorite":false,"folderId":null,"creationDate":"2000-01-01T00:00:00Z","revisionDate":"2000-01-01T00:00:00Z","deletedDate":null,"organizationId":org,"outerOpaque":{"unchanged":"opaque encrypted extension"}});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,NULL,?2,'cipher',?3,'initial-revision','initial-created')",params![id,org,doc.to_string()]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
        params![collection, id],
    )
    .unwrap();
    for (user, favorite) in [("alice", true), ("bob", false)] {
        let folder = uuid::Uuid::new_v4().to_string();
        s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,NULL,'folder',?3,'folder-revision','folder-created')",params![folder,user,json!({"id":folder,"name":"opaque encrypted folder"}).to_string()]).unwrap();
        s.db.execute(
            "INSERT INTO cipher_annotations VALUES(?1,?2,?3,?4)",
            params![id, user, folder, favorite],
        )
        .unwrap();
    }
    id
}
fn personal(s: &Store, owner: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let doc = json!({"id":id,"type":2,"name":"opaque encrypted personal","notes":"opaque encrypted notes","secureNote":{"type":0},"favorite":true,"folderId":null,"organizationId":null,"creationDate":"2000","revisionDate":"unchanged","outerOpaque":[null,"opaque"]});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,NULL,'cipher',?3,'personal-revision','personal-created')",params![id,owner,doc.to_string()]).unwrap();
    id
}
fn state(db: &Connection) -> Vec<Vec<SqlValue>> {
    let mut rows = Vec::new();
    for table in [
        "items",
        "accounts",
        "cipher_archives",
        "cipher_annotations",
        "organization_memberships",
        "organization_collection_users",
        "organization_collection_ciphers",
        "sessions",
        "device_registry",
        "session_devices",
        "archive_revision_writes",
    ] {
        let mut q = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let n = q.column_count();
        rows.extend(
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
    rows
}
fn table(db: &Connection, name: &str) -> Vec<Vec<SqlValue>> {
    let mut q = db
        .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
        .unwrap();
    let n = q.column_count();
    q.query_map([], |r| {
        (0..n)
            .map(|i| r.get(i))
            .collect::<rusqlite::Result<Vec<SqlValue>>>()
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}
fn revision(s: &Store, actor: &str) -> String {
    s.db.query_row("SELECT revision FROM accounts WHERE id=?1", [actor], |r| {
        r.get(0)
    })
    .unwrap()
}
fn writes(s: &Store) -> Vec<String> {
    s.db.prepare("SELECT user_id FROM archive_revision_writes ORDER BY user_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn clear_writes(s: &Store) {
    s.db.execute("DELETE FROM archive_revision_writes", [])
        .unwrap();
}
fn archived(s: &Store, actor: &str, id: &str) -> Option<String> {
    s.db.query_row(
        "SELECT archived_at FROM cipher_archives WHERE owner=?1 AND cipher_id=?2",
        params![actor, id],
        |r| r.get(0),
    )
    .optional()
    .unwrap()
    .flatten()
}
fn account_protected(s: &Store) -> Vec<Value> {
    s.db.prepare("SELECT document FROM accounts ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| {
            let mut v: Value = serde_json::from_str(&r.unwrap()).unwrap();
            v.as_object_mut().unwrap().remove("revisionDate");
            v
        })
        .collect()
}
fn unwrap_result<T>(v: Result<T, Failure>) -> T {
    v.unwrap_or_else(|_| panic!("Valid archive operation rejected"))
}
fn rejected(v: Result<Response, Failure>) -> Failure {
    match v {
        Err(e) => e,
        Ok(_) => panic!("Invalid archive operation admitted"),
    }
}
async fn single(s: &mut Store, actor: &str, id: &str, archive: bool) -> Value {
    let response = unwrap_result(super::dispatch(
        if archive {
            Route::CipherArchive(id)
        } else {
            Route::CipherUnarchive(id)
        },
        actor,
        b"{invalid ignored JSON",
        s,
    ));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
async fn selected(s: &mut Store, actor: &str, ids: &[&str], archive: bool) -> Value {
    let response = unwrap_result(super::dispatch(
        if archive {
            Route::CipherBulkArchive
        } else {
            Route::CipherBulkUnarchive
        },
        actor,
        &serde_json::to_vec(&json!({"ids":ids})).unwrap(),
        s,
    ));
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn readonly_and_manage_single_changes_actor_archive_but_refreshes_only_current_readers() {
    let mut f = fixture(":memory:");
    single(&mut f.s, "alice", &f.cipher, true).await;
    let owner_date = archived(&f.s, "alice", &f.cipher);
    assert!(owner_date.is_some());
    let raw = table(&f.s.db, "items");
    let private = table(&f.s.db, "cipher_annotations");
    let keys = account_protected(&f.s);
    for manage in [false, true] {
        f.s.db.execute("UPDATE organization_collection_users SET manage=?1 WHERE collection_id=?2 AND user_id='bob'",params![manage,f.collection]).unwrap();
        for archive in [true, true, false, false] {
            let old: Vec<_> = ["alice", "bob", "carol", "david", "erin"]
                .iter()
                .map(|user| revision(&f.s, user))
                .collect();
            let previous = archived(&f.s, "bob", &f.cipher);
            clear_writes(&f.s);
            let value = single(&mut f.s, "bob", &f.cipher, archive).await;
            assert_eq!(value["object"], "cipherDetails");
            assert_eq!(value.as_object().unwrap().len(), 30);
            assert_eq!(value["edit"], false);
            assert_eq!(value["favorite"], false);
            assert!(value["folderId"].is_string());
            assert_eq!(value["archivedDate"].is_string(), archive);
            assert!(value.get("outerOpaque").is_none());
            assert_eq!(
                value["secureNote"]["nestedOpaque"],
                json!({"unchanged":[null,"opaque encrypted extension",7]})
            );
            if archive {
                assert_ne!(archived(&f.s, "bob", &f.cipher), previous);
            } else {
                assert!(archived(&f.s, "bob", &f.cipher).is_none());
            }
            assert_eq!(archived(&f.s, "alice", &f.cipher), owner_date);
            assert_eq!(writes(&f.s), vec!["alice", "bob"]);
            for (index, user) in ["alice", "bob", "carol", "david", "erin"]
                .iter()
                .enumerate()
            {
                if index < 2 {
                    assert_ne!(revision(&f.s, user), old[index]);
                } else {
                    assert_eq!(revision(&f.s, user), old[index]);
                }
            }
            assert_eq!(table(&f.s.db, "items"), raw);
            assert_eq!(table(&f.s.db, "cipher_annotations"), private);
            assert_eq!(account_protected(&f.s), keys);
        }
    }
}
#[tokio::test]
async fn selected_deduplicates_but_advances_only_actor_once_and_empty_selection_is_observational() {
    let mut f = fixture(":memory:");
    let second = add_shared(&f.s, &f.org, &f.collection);
    let raw = table(&f.s.db, "items");
    let private = table(&f.s.db, "cipher_annotations");
    let keys = account_protected(&f.s);
    for archive in [true, false] {
        let old_owner = revision(&f.s, "alice");
        clear_writes(&f.s);
        let value = selected(&mut f.s, "bob", &[&f.cipher, &f.cipher], archive).await;
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["object"], "list");
        assert!(value["continuationToken"].is_null());
        assert_eq!(value["data"].as_array().unwrap().len(), 1);
        assert_eq!(value["data"][0]["id"], f.cipher);
        assert_eq!(value["data"][0].as_object().unwrap().len(), 30);
        assert_eq!(writes(&f.s), vec!["bob"]);
        assert_eq!(revision(&f.s, "alice"), old_owner);
        clear_writes(&f.s);
        let value = selected(&mut f.s, "bob", &[&second, &f.cipher, &second], archive).await;
        let mut ids: Vec<_> = value["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        ids.sort();
        let mut expected = vec![f.cipher.as_str(), second.as_str()];
        expected.sort();
        assert_eq!(ids, expected);
        assert_eq!(writes(&f.s), vec!["bob"]);
        assert_eq!(revision(&f.s, "alice"), old_owner);
        let before = state(&f.s.db);
        let empty = selected(&mut f.s, "bob", &[], archive).await;
        assert_eq!(
            empty,
            json!({"object":"list","data":[],"continuationToken":null})
        );
        assert_eq!(state(&f.s.db), before);
        assert_eq!(table(&f.s.db, "items"), raw);
        assert_eq!(table(&f.s.db, "cipher_annotations"), private);
        assert_eq!(account_protected(&f.s), keys);
    }
}
#[tokio::test]
async fn personal_archive_preserves_entire_raw_document_and_foreign_personal_is_denied() {
    let mut f = fixture(":memory:");
    let id = personal(&f.s, "bob");
    let other = personal(&f.s, "alice");
    let raw = table(&f.s.db, "items");
    for archive in [true, false] {
        clear_writes(&f.s);
        let value = single(&mut f.s, "bob", &id, archive).await;
        assert_eq!(value["archivedDate"].is_string(), archive);
        assert_eq!(value.as_object().unwrap().len(), 30);
        assert_eq!(writes(&f.s), vec!["bob"]);
        assert_eq!(table(&f.s.db, "items"), raw);
    }
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherArchive(&other),
            "bob",
            b"",
            &mut f.s
        ))
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s.db), before);
}
#[test]
fn all_admission_failures_preserve_whole_selection_state_and_account_keys() {
    let mut f = fixture(":memory:");
    let foreign = personal(&f.s, "alice");
    let missing = uuid::Uuid::new_v4().to_string();
    for actor in ["carol", "david", "erin", "no-member"] {
        let before = state(&f.s.db);
        assert_eq!(
            rejected(super::dispatch(
                Route::CipherArchive(&f.cipher),
                actor,
                b"",
                &mut f.s
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s.db), before);
    }
    for archive in [true, false] {
        for ids in [
            [f.cipher.as_str(), missing.as_str()],
            [missing.as_str(), f.cipher.as_str()],
            [f.cipher.as_str(), foreign.as_str()],
        ] {
            let before = state(&f.s.db);
            let body = serde_json::to_vec(&json!({"ids":ids})).unwrap();
            assert_eq!(
                rejected(super::dispatch(
                    if archive {
                        Route::CipherBulkArchive
                    } else {
                        Route::CipherBulkUnarchive
                    },
                    "bob",
                    &body,
                    &mut f.s
                ))
                .0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(state(&f.s.db), before);
        }
    }
}
#[tokio::test]
async fn late_account_failure_and_later_selected_annotation_failure_roll_back_actual_writes() {
    let mut f = fixture(":memory:");
    // A single mutation writes the annotation, advances Alice, then encounters
    // this Bob revision failure. Every earlier write must roll back too.
    f.s.db.execute_batch("CREATE TRIGGER fail_archive_revision BEFORE UPDATE OF revision ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'local rollback fixture'); END;").unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherArchive(&f.cipher),
            "bob",
            b"",
            &mut f.s
        ))
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(state(&f.s.db), before);
    f.s.db
        .execute_batch("DROP TRIGGER fail_archive_revision")
        .unwrap();
    single(&mut f.s, "bob", &f.cipher, true).await;
    f.s.db.execute_batch("CREATE TRIGGER fail_unarchive_revision BEFORE UPDATE OF revision ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'local rollback fixture'); END;").unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherUnarchive(&f.cipher),
            "bob",
            b"",
            &mut f.s
        ))
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(state(&f.s.db), before);
    f.s.db
        .execute_batch("DROP TRIGGER fail_unarchive_revision")
        .unwrap();
    let second = add_shared(&f.s, &f.org, &f.collection);
    let later = std::cmp::max(f.cipher.as_str(), second.as_str());
    f.s.db.execute_batch(&format!("CREATE TRIGGER fail_later_archive AFTER INSERT ON cipher_archives WHEN NEW.cipher_id='{later}' AND NEW.owner='bob' BEGIN SELECT RAISE(ABORT,'local rollback fixture'); END;")).unwrap();
    // Clear both rows so the trigger runs on the later actual INSERT, after the
    // first target's annotation INSERT has already succeeded in this transaction.
    f.s.db
        .execute("DELETE FROM cipher_archives WHERE owner='bob'", [])
        .unwrap();
    let before = state(&f.s.db);
    let body = serde_json::to_vec(&json!({"ids":[second,f.cipher]})).unwrap();
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherBulkArchive,
            "bob",
            &body,
            &mut f.s
        ))
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(state(&f.s.db), before);
}

static WRITE_BLOCKED: AtomicBool = AtomicBool::new(false);
fn busy(retry: i32) -> bool {
    WRITE_BLOCKED.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(1));
    retry < 5000
}
#[test]
fn real_second_writer_cannot_revoke_or_replace_an_admitted_target_before_commit() {
    // WAL permits observational reads of old committed facts. The other writer
    // commits only after this provider reaches its IMMEDIATE write boundary.
    // This is a local provider guarantee, not measured native concurrency parity.
    for change in [
        "membership",
        "grant",
        "source-revision",
        "source-owner",
        "source-disappears",
    ] {
        let dir =
            std::env::temp_dir().join(format!("no-warden-archive-race-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("db.sqlite");
        let f = fixture(path.to_str().unwrap());
        let mut other = Connection::open(&path).unwrap();
        other.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let tx = other
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
            "source-revision" => {
                tx.execute(
                    "UPDATE items SET revision='changed revision' WHERE id=?1",
                    [&f.cipher],
                )
                .unwrap();
            }
            "source-owner" => {
                tx.execute(
                    "UPDATE items SET owner='alice',organization_id=NULL WHERE id=?1",
                    [&f.cipher],
                )
                .unwrap();
            }
            "source-disappears" => {
                tx.execute("DELETE FROM items WHERE id=?1", [&f.cipher])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let expected = state(&tx);
        WRITE_BLOCKED.store(false, Ordering::SeqCst);
        f.s.db.busy_handler(Some(busy)).unwrap();
        let id = f.cipher.clone();
        let worker = std::thread::spawn(move || {
            let mut s = f.s;
            let denied = super::dispatch(Route::CipherArchive(&id), "bob", b"", &mut s).is_err();
            (s, denied)
        });
        let start = Instant::now();
        while !WRITE_BLOCKED.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let reached = WRITE_BLOCKED.load(Ordering::SeqCst);
        tx.commit().unwrap();
        let (s, denied) = worker.join().unwrap();
        assert!(reached, "Provider never reached live write boundary");
        assert!(denied, "Stale authority or source admitted");
        assert_eq!(state(&s.db), expected);
        drop(s);
        drop(other);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn bounded_material_policies_fail_without_writes_and_skip_unconfirmed_foreign_facts() {
    let mut f = fixture(":memory:");
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO organization_collections(id,organization_id,name,external_id) SELECT 'bounded-'||x,?1,'opaque',NULL FROM n",[&f.org]).unwrap();
    f.s.db.execute("INSERT INTO organization_collection_ciphers SELECT id,?1 FROM organization_collections WHERE id LIKE 'bounded-%'",[&f.cipher]).unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherArchive(&f.cipher),
            "bob",
            b"",
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
    for actor in ["david", "erin", "no-member"] {
        let before = state(&f.s.db);
        assert_eq!(
            rejected(super::dispatch(
                Route::CipherArchive(&f.cipher),
                actor,
                b"",
                &mut f.s
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s.db), before);
    }
    let body = serde_json::to_vec(&json!({"ids":vec![f.cipher.as_str();4097]})).unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherBulkArchive,
            "bob",
            &body,
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
    f.s.db
        .execute(
            "DELETE FROM organization_collection_ciphers WHERE collection_id LIKE 'bounded-%'",
            [],
        )
        .unwrap();
    let large = "x".repeat(8 * 1024 * 1024);
    f.s.db
        .execute(
            "UPDATE items SET document=?1 WHERE id=?2",
            params![json!({"opaque":large}).to_string(), f.cipher],
        )
        .unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        rejected(super::dispatch(
            Route::CipherArchive(&f.cipher),
            "bob",
            b"",
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
}

#[test]
fn excessive_reader_candidates_fail_before_annotations_or_any_account_revision() {
    let mut f = fixture(":memory:");
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO accounts(id,email,document,password,revision) SELECT 'bounded-reader-'||x,'bounded-reader-'||x||'@example.test','{}','opaque-verifier','2000-01-01T00:00:00.000Z' FROM n",[]).unwrap();
    f.s.db.execute("INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) SELECT id,?1,id,'opaque wrapped key',2,2,0 FROM accounts WHERE id LIKE 'bounded-reader-%'",[&f.org]).unwrap();
    let before = state(&f.s.db);
    assert!(super::dispatch(Route::CipherArchive(&f.cipher), "bob", b"", &mut f.s).is_err());
    assert_eq!(state(&f.s.db), before);
}

async fn socket(
    app: &crate::App,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: &[u8],
) -> Response {
    match crate::dispatch_http(
        State(app.clone()),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        method,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}
#[tokio::test]
async fn socket_enforces_auth_binding_native_schema_shapes_and_put_only_routes() {
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
    for tail in ["archive", "unarchive"] {
        let path = format!("/api/ciphers/{id}/{tail}");
        let response = socket(
            &app,
            Method::PUT,
            &path,
            headers.clone(),
            b"{invalid ignored JSON",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(value["object"], "cipherDetails");
        assert_eq!(value.as_object().unwrap().len(), 30);
        let before = state(&app.store.lock().unwrap().db);
        let response = socket(&app, Method::POST, &path, headers.clone(), b"").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(state(&app.store.lock().unwrap().db), before);
    }
    for (body, status) in [
        (b"{}".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
        (br#"{"Ids":[]}"#, StatusCode::UNPROCESSABLE_ENTITY),
        (br#"{"ids":[null]}"#, StatusCode::UNPROCESSABLE_ENTITY),
        (
            br#"{"ids":["expected fewer elements",2]}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (br#"[[],0]"#, StatusCode::BAD_REQUEST),
        (b"{", StatusCode::BAD_REQUEST),
    ] {
        let before = state(&app.store.lock().unwrap().db);
        let response = socket(
            &app,
            Method::PUT,
            "/api/ciphers/archive",
            headers.clone(),
            body,
        )
        .await;
        assert_eq!(response.status(), status);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(
            value.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["error"]
        );
        assert_eq!(state(&app.store.lock().unwrap().db), before);
    }
    let response = socket(
        &app,
        Method::PUT,
        "/api/ciphers/archive",
        headers.clone(),
        &serde_json::to_vec(&json!({"ids":[uuid::Uuid::new_v4().to_string()]})).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 9);
    let response = socket(
        &app,
        Method::PUT,
        "/api/ciphers/not-a-uuid/archive",
        headers.clone(),
        b"{}",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let before = state(&app.store.lock().unwrap().db);
    let response = socket(
        &app,
        Method::PUT,
        "/api/ciphers/not-a-uuid/archive",
        HeaderMap::new(),
        b"{bad",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state(&app.store.lock().unwrap().db), before);
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let before = state(&app.store.lock().unwrap().db);
    let response = socket(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/archive"),
        headers,
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state(&app.store.lock().unwrap().db), before);
}
