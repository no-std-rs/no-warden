// Independently authored MIT OR Apache-2.0 provider/socket regressions.
use crate::{Failure, Store, organization_cipher_sharing as sharing};
use axum::{
    body::{Bytes, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use no_warden::route::Route;
use rusqlite::{Connection, TransactionBehavior, params, types::Value as SqlValue};
use serde_json::{Value, json};
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
    for user in ["carol", "david", "erin", "frank", "helen"] {
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
        ("frank-member", "frank", 1, 2),
        ("helen-member", "helen", 2, 2),
    ] {
        s.db.execute("INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque wrapped org key',?4,?5,0)",params![id,org,user,role,status]).unwrap();
    }
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,0)",
        [&collection],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'helen',1,0,0)",
        [&collection],
    )
    .unwrap();
    let cipher = add_shared(&s, &org, &collection);
    s.db.execute_batch("CREATE TABLE lifecycle_revision_writes(user_id TEXT NOT NULL); CREATE TRIGGER lifecycle_revision_audit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO lifecycle_revision_writes VALUES(NEW.id); END;").unwrap();
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
    let doc = json!({"id":id,"type":2,"name":"opaque encrypted personal","notes":"opaque encrypted notes","favorite":true,"folderId":null,"organizationId":null,"creationDate":"2000","revisionDate":"unchanged","key":"opaque wrapped personal key","outerOpaque":[null,"opaque"],"secureNote":{"type":0,"nestedOpaque":[null,7,"opaque"]}});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,NULL,'cipher',?3,'personal-revision','personal-created')",params![id,owner,doc.to_string()]).unwrap();
    id
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
    s.db.prepare("SELECT user_id FROM lifecycle_revision_writes ORDER BY user_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn clear_writes(s: &Store) {
    s.db.execute("DELETE FROM lifecycle_revision_writes", [])
        .unwrap();
}
fn account_protected(s: &Store) -> Vec<(String, String, String, Value)> {
    s.db.prepare("SELECT id,email,password,document FROM accounts ORDER BY id")
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .map(|r| {
            let (id, email, password, raw) = r.unwrap();
            let mut v: Value = serde_json::from_str(&raw).unwrap();
            v.as_object_mut().unwrap().remove("revisionDate");
            (id, email, password, v)
        })
        .collect()
}
type Snapshot = Vec<(String, Vec<Vec<SqlValue>>)>;
fn state(db: &Connection) -> Snapshot {
    let names: Vec<String> = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    names
        .into_iter()
        .map(|name| {
            let rows = table(db, &name);
            (name, rows)
        })
        .collect()
}
#[derive(Clone, Copy)]
enum Action {
    Trash,
    Restore,
    Delete,
}
fn route(action: Action, id: &str) -> Route<'_> {
    match action {
        Action::Trash => Route::CipherSoftDelete(id),
        Action::Restore => Route::CipherRestore(id),
        Action::Delete => Route::CipherDelete(id),
    }
}
fn error(result: Result<Response, Failure>) -> Failure {
    match result {
        Err(e) => e,
        Ok(_) => panic!("Invalid lifecycle request admitted"),
    }
}
async fn perform(s: &mut Store, actor: &str, id: &str, action: Action) -> Option<Value> {
    let response = super::dispatch(route(action, id), actor, s)
        .unwrap_or_else(|_| panic!("Valid lifecycle operation rejected"));
    assert_eq!(response.status(), StatusCode::OK);
    if matches!(action, Action::Restore) {
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(value["object"], "cipherDetails");
        assert_eq!(value.as_object().unwrap().len(), 30);
        assert!(value.get("outerOpaque").is_none());
        Some(value)
    } else {
        assert!(response.headers().get("content-type").is_none());
        assert!(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .is_empty()
        );
        None
    }
}
fn document(s: &Store, id: &str) -> Value {
    let raw: String =
        s.db.query_row("SELECT document FROM items WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    serde_json::from_str(&raw).unwrap()
}
fn stable_item_metadata(
    s: &Store,
    id: &str,
) -> (String, Option<String>, Option<String>, String, String) {
    s.db.query_row(
        "SELECT id,owner,organization_id,kind,created FROM items WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .unwrap()
}
fn item_revision(s: &Store, id: &str) -> String {
    s.db.query_row("SELECT revision FROM items WHERE id=?1", [id], |r| r.get(0))
        .unwrap()
}
fn strip_lifecycle(mut value: Value) -> Value {
    for key in ["deletedDate", "revisionDate"] {
        value.as_object_mut().unwrap().remove(key);
    }
    value
}
fn unrelated_state(s: &Store) -> Snapshot {
    state(&s.db)
        .into_iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "items" | "accounts" | "lifecycle_revision_writes"
            )
        })
        .collect()
}
fn add_archives(s: &Store, id: &str) {
    for (user, date) in [
        ("alice", "2001-01-01T00:00:00.000Z"),
        ("bob", "2002-01-01T00:00:00.000Z"),
    ] {
        s.db.execute(
            "INSERT INTO cipher_archives VALUES(?1,?2,?3)",
            params![id, user, date],
        )
        .unwrap();
    }
}
fn attach(s: &Store, id: &str, label: &str) {
    s.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,'opaque encrypted filename','opaque wrapped attachment key',3,x'00ff01')",params![label,id]).unwrap();
    s.db.execute(
        "INSERT INTO attachment_downloads VALUES(?1,?2,123456)",
        params![format!("download-{label}"), label],
    )
    .unwrap();
}

#[tokio::test]
async fn trash_repeat_restore_active_preserve_opaque_payload_private_archives_and_refresh_current_readers()
 {
    let mut f = fixture(":memory:");
    add_archives(&f.s, &f.cipher);
    let original = document(&f.s, &f.cipher);
    let metadata = stable_item_metadata(&f.s, &f.cipher);
    let protected = account_protected(&f.s);
    let other = unrelated_state(&f.s);
    let folders: Vec<_> = table(&f.s.db, "items")
        .into_iter()
        .filter(|row| row[0] != SqlValue::Text(f.cipher.clone()))
        .collect();
    for action in [
        Action::Trash,
        Action::Trash,
        Action::Restore,
        Action::Restore,
    ] {
        let before = item_revision(&f.s, &f.cipher);
        let previous_deleted = document(&f.s, &f.cipher)["deletedDate"].clone();
        let old_revs: [String; 7] =
            ["alice", "bob", "carol", "david", "erin", "frank", "helen"].map(|u| revision(&f.s, u));
        clear_writes(&f.s);
        let response = perform(&mut f.s, "bob", &f.cipher, action).await;
        let now = document(&f.s, &f.cipher);
        assert_eq!(stable_item_metadata(&f.s, &f.cipher), metadata);
        assert_eq!(
            strip_lifecycle(now.clone()),
            strip_lifecycle(original.clone())
        );
        assert_ne!(item_revision(&f.s, &f.cipher), before);
        assert_eq!(now["revisionDate"], item_revision(&f.s, &f.cipher));
        let deleted: bool =
            f.s.db
                .query_row("SELECT deleted FROM items WHERE id=?1", [&f.cipher], |r| {
                    r.get(0)
                })
                .unwrap();
        assert_eq!(deleted, matches!(action, Action::Trash));
        if deleted {
            assert!(now["deletedDate"].is_string());
            assert_ne!(now["deletedDate"], previous_deleted);
        } else {
            assert!(now["deletedDate"].is_null());
        }
        assert_eq!(writes(&f.s), vec!["alice", "bob", "frank", "helen"]);
        for (index, user) in ["alice", "bob", "carol", "david", "erin", "frank", "helen"]
            .iter()
            .enumerate()
        {
            assert_eq!(
                revision(&f.s, user) != old_revs[index],
                ["alice", "bob", "frank", "helen"].contains(user)
            );
        }
        assert_eq!(account_protected(&f.s), protected);
        assert_eq!(unrelated_state(&f.s), other);
        assert_eq!(
            table(&f.s.db, "items")
                .into_iter()
                .filter(|row| row[0] != SqlValue::Text(f.cipher.clone()))
                .collect::<Vec<_>>(),
            folders
        );
        if let Some(value) = response {
            assert_eq!(
                value,
                crate::organization_cipher_archive::project(&f.s.db, "bob", &f.cipher)
                    .unwrap_or_else(|_| panic!("Valid lifecycle projection rejected"))
            );
            assert_eq!(value["secureNote"], original["secureNote"]);
        }
    }
}

#[tokio::test]
async fn write_admission_accepts_owner_admin_writable_and_readonly_manage_but_denies_readonly_or_unconfirmed()
 {
    for (actor, readonly, manage, admitted) in [
        ("alice", false, false, true),
        ("frank", false, false, true),
        ("bob", false, false, true),
        ("bob", true, true, true),
        ("bob", true, false, false),
        ("carol", false, false, false),
        ("david", false, false, false),
        ("erin", false, false, false),
    ] {
        for action in [Action::Trash, Action::Restore, Action::Delete] {
            let mut f = fixture(":memory:");
            f.s.db.execute("UPDATE organization_collection_users SET read_only=?1,manage=?2 WHERE collection_id=?3 AND user_id='bob'",params![readonly,manage,f.collection]).unwrap();
            if actor == "bob" && readonly {
                let value = sharing::project(&f.s.db, actor, &f.cipher, true)
                    .unwrap()
                    .unwrap();
                assert_eq!(value["edit"], false);
            }
            let before = state(&f.s.db);
            if admitted {
                perform(&mut f.s, actor, &f.cipher, action).await;
            } else {
                assert_eq!(
                    error(super::dispatch(route(action, &f.cipher), actor, &mut f.s)).0,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(state(&f.s.db), before);
            }
        }
    }
}

#[tokio::test]
async fn personal_source_preserves_unknown_nested_cipher_material_and_notifies_only_owner() {
    let mut f = fixture(":memory:");
    let id = personal(&f.s, "alice");
    add_archives(&f.s, &id);
    let original = document(&f.s, &id);
    let metadata = stable_item_metadata(&f.s, &id);
    let other = unrelated_state(&f.s);
    let peers: [String; 6] =
        ["bob", "carol", "david", "erin", "frank", "helen"].map(|u| revision(&f.s, u));
    let protected = account_protected(&f.s);
    for action in [Action::Trash, Action::Restore, Action::Restore] {
        clear_writes(&f.s);
        perform(&mut f.s, "alice", &id, action).await;
        assert_eq!(stable_item_metadata(&f.s, &id), metadata);
        assert_eq!(unrelated_state(&f.s), other);
        assert_eq!(
            strip_lifecycle(document(&f.s, &id)),
            strip_lifecycle(original.clone())
        );
        assert_eq!(writes(&f.s), vec!["alice"]);
        assert_eq!(
            ["bob", "carol", "david", "erin", "frank", "helen"].map(|u| revision(&f.s, u)),
            peers
        );
        assert_eq!(account_protected(&f.s), protected);
    }
    let before = state(&f.s.db);
    assert_eq!(
        error(super::dispatch(
            Route::CipherSoftDelete(&id),
            "bob",
            &mut f.s
        ))
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state(&f.s.db), before);
}

#[tokio::test]
async fn permanent_delete_active_or_trashed_cascades_only_target_children_and_notifies_prior_readers()
 {
    for trashed in [false, true] {
        let mut f = fixture(":memory:");
        let other = add_shared(&f.s, &f.org, &f.collection);
        add_archives(&f.s, &f.cipher);
        add_archives(&f.s, &other);
        attach(&f.s, &f.cipher, "target-attachment");
        attach(&f.s, &other, "other-attachment");
        if trashed {
            perform(&mut f.s, "bob", &f.cipher, Action::Trash).await;
        }
        let before = state(&f.s.db);
        let keys = account_protected(&f.s);
        clear_writes(&f.s);
        perform(&mut f.s, "bob", &f.cipher, Action::Delete).await;
        assert_eq!(writes(&f.s), vec!["alice", "bob", "frank", "helen"]);
        assert_eq!(account_protected(&f.s), keys);
        assert!(sharing::source(&f.s.db, &f.cipher).unwrap().is_none());
        assert!(
            sharing::project(&f.s.db, "alice", &f.cipher, true)
                .unwrap()
                .is_none()
        );
        for (table_name, column) in [
            ("organization_collection_ciphers", "cipher_id"),
            ("cipher_annotations", "cipher_id"),
            ("cipher_archives", "cipher_id"),
            ("attachments", "cipher_id"),
        ] {
            let n: usize =
                f.s.db
                    .query_row(
                        &format!("SELECT count(*) FROM {table_name} WHERE {column}=?1"),
                        [&f.cipher],
                        |r| r.get(0),
                    )
                    .unwrap();
            assert_eq!(n, 0);
        }
        assert_eq!(f.s.db.query_row("SELECT count(*) FROM attachment_downloads WHERE attachment_id='target-attachment'",[],|r|r.get::<_,usize>(0)).unwrap(),0);
        let after = state(&f.s.db);
        for (name, rows) in before {
            let expected: Vec<_> = match name.as_str() {
                "accounts" | "lifecycle_revision_writes" => continue,
                "items" => rows
                    .into_iter()
                    .filter(|r| r[0] != SqlValue::Text(f.cipher.clone()))
                    .collect(),
                "cipher_archives" | "cipher_annotations" => rows
                    .into_iter()
                    .filter(|r| r[0] != SqlValue::Text(f.cipher.clone()))
                    .collect(),
                "organization_collection_ciphers" => rows
                    .into_iter()
                    .filter(|r| r[1] != SqlValue::Text(f.cipher.clone()))
                    .collect(),
                "attachments" => rows
                    .into_iter()
                    .filter(|r| r[1] != SqlValue::Text(f.cipher.clone()))
                    .collect(),
                "attachment_downloads" => rows
                    .into_iter()
                    .filter(|r| r[1] != SqlValue::Text("target-attachment".into()))
                    .collect(),
                _ => rows,
            };
            assert_eq!(
                &after.iter().find(|(n, _)| n == &name).unwrap().1,
                &expected,
                "Unrelated SQL state changed"
            );
        }
    }
}

#[test]
fn late_reader_and_child_cascade_failure_roll_back_the_entire_lifecycle_transaction() {
    for action in [Action::Trash, Action::Restore, Action::Delete] {
        for failure in ["late-account", "deferred-commit"] {
            let mut f = fixture(":memory:");
            add_archives(&f.s, &f.cipher);
            attach(&f.s, &f.cipher, "rollback-attachment");
            if failure == "late-account" {
                f.s.db.execute_batch("CREATE TRIGGER lifecycle_late_failure BEFORE UPDATE OF revision ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'local rollback fixture'); END;").unwrap();
            } else {
                f.s.db.execute_batch("CREATE TABLE lifecycle_failed_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER lifecycle_deferred_failure AFTER UPDATE OF revision ON accounts WHEN NEW.id='bob' BEGIN INSERT INTO lifecycle_failed_commit VALUES('absent-account'); END;").unwrap();
            }
            let before = state(&f.s.db);
            assert_eq!(
                error(super::dispatch(route(action, &f.cipher), "bob", &mut f.s)).0,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert_eq!(state(&f.s.db), before);
        }
    }
    for table_name in [
        "attachments",
        "cipher_annotations",
        "cipher_archives",
        "organization_collection_ciphers",
        "attachment_downloads",
    ] {
        let mut f = fixture(":memory:");
        add_archives(&f.s, &f.cipher);
        attach(&f.s, &f.cipher, "rollback-attachment");
        f.s.db.execute_batch(&format!("CREATE TRIGGER lifecycle_child_failure AFTER DELETE ON {table_name} BEGIN SELECT RAISE(ABORT,'local child rollback fixture'); END;")).unwrap();
        let before = state(&f.s.db);
        assert_eq!(
            error(super::dispatch(
                Route::CipherDelete(&f.cipher),
                "bob",
                &mut f.s
            ))
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(state(&f.s.db), before);
    }
}

static WRITE_BLOCKED: AtomicBool = AtomicBool::new(false);
fn busy(retry: i32) -> bool {
    WRITE_BLOCKED.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(1));
    retry < 5000
}
#[test]
fn real_wal_writer_cannot_revoke_write_or_replace_an_admitted_source_before_commit() {
    // Local transactional/live-grant guarantee; native concurrency is unmeasured.
    for change in [
        "membership",
        "grant-write",
        "source-revision",
        "source-owner",
        "source-disappears",
    ] {
        let dir =
            std::env::temp_dir().join(format!("no-warden-lifecycle-race-{}", uuid::Uuid::new_v4()));
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
            "grant-write" => {
                tx.execute("UPDATE organization_collection_users SET read_only=1,manage=0 WHERE user_id='bob'",[]).unwrap();
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
            let denied = super::dispatch(Route::CipherSoftDelete(&id), "bob", &mut s).is_err();
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
fn local_material_and_reader_caps_preserve_state_and_skip_foreign_unconfirmed_owned_fact_loads() {
    let mut f = fixture(":memory:");
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO organization_collections(id,organization_id,name,external_id) SELECT 'bounded-'||x,?1,'opaque',NULL FROM n",[&f.org]).unwrap();
    f.s.db.execute("INSERT INTO organization_collection_ciphers SELECT id,?1 FROM organization_collections WHERE id LIKE 'bounded-%'",[&f.cipher]).unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        error(super::dispatch(
            Route::CipherSoftDelete(&f.cipher),
            "bob",
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
    // Negative-only membership optimization skips oversize foreign facts; no
    // grant SQL duplicates the core's final WRITE decision.
    for actor in ["david", "erin", "no-member"] {
        let before = state(&f.s.db);
        assert_eq!(
            error(super::dispatch(
                Route::CipherSoftDelete(&f.cipher),
                actor,
                &mut f.s
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s.db), before);
    }
    f.s.db
        .execute(
            "DELETE FROM organization_collection_ciphers WHERE collection_id LIKE 'bounded-%'",
            [],
        )
        .unwrap();
    let large = "x".repeat(8 * 1024 * 1024);
    let raw = document(&f.s, &f.cipher);
    let mut oversized = raw.clone();
    oversized["outerOpaque"] = Value::String(large);
    f.s.db
        .execute(
            "UPDATE items SET document=?1 WHERE id=?2",
            params![oversized.to_string(), f.cipher],
        )
        .unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        error(super::dispatch(
            Route::CipherSoftDelete(&f.cipher),
            "bob",
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
    f.s.db
        .execute(
            "UPDATE items SET document=?1 WHERE id=?2",
            params![raw.to_string(), f.cipher],
        )
        .unwrap();
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO accounts(id,email,document,password,revision) SELECT 'bounded-reader-'||x,'bounded-reader-'||x||'@example.test','{}','opaque-verifier','2000-01-01T00:00:00.000Z' FROM n",[]).unwrap();
    f.s.db.execute("INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) SELECT id,?1,id,'opaque wrapped key',2,2,0 FROM accounts WHERE id LIKE 'bounded-reader-%'",[&f.org]).unwrap();
    let before = state(&f.s.db);
    assert!(super::dispatch(Route::CipherSoftDelete(&f.cipher), "bob", &mut f.s).is_err());
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
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}
async fn error_keys(response: Response, expected: StatusCode, count: usize) {
    assert_eq!(response.status(), expected);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(
        value.as_object().unwrap().len(),
        count,
        "Unexpected lifecycle error envelope at status {expected}"
    );
}
#[tokio::test]
async fn socket_native_lifecycle_methods_body_ignoring_auth_binding_and_error_shapes() {
    let f = fixture(":memory:");
    let second = add_shared(&f.s, &f.org, &f.collection);
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
    for (path, status, count) in [
        (
            "/api/ciphers/not-a-uuid/delete".to_owned(),
            StatusCode::UNPROCESSABLE_ENTITY,
            1,
        ),
        (
            format!("/api/ciphers/{}/delete", uuid::Uuid::new_v4()),
            StatusCode::BAD_REQUEST,
            9,
        ),
    ] {
        let before = state(&app.store.lock().unwrap().db);
        error_keys(
            socket(
                &app,
                Method::PUT,
                &path,
                headers.clone(),
                b"{invalid ignored JSON",
            )
            .await,
            status,
            count,
        )
        .await;
        assert_eq!(state(&app.store.lock().unwrap().db), before);
    }
    let before = state(&app.store.lock().unwrap().db);
    error_keys(
        socket(
            &app,
            Method::PUT,
            "/api/ciphers/not-a-uuid/delete",
            HeaderMap::new(),
            b"{",
        )
        .await,
        StatusCode::UNAUTHORIZED,
        1,
    )
    .await;
    assert_eq!(state(&app.store.lock().unwrap().db), before);
    // Valid unrelated JSON is ignored, rather than decoded as a cipher write.
    let response = socket(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/delete"),
        headers.clone(),
        br#"{"unrelated":"opaque ignored field"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("content-type").is_none());
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    let response = socket(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/restore"),
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
    error_keys(
        socket(
            &app,
            Method::POST,
            &format!("/api/ciphers/{id}/restore"),
            headers.clone(),
            b"",
        )
        .await,
        StatusCode::NOT_FOUND,
        1,
    )
    .await;
    assert_eq!(state(&app.store.lock().unwrap().db), before);
    // POST /id/delete is the measured permanent-delete alias, not Trash.
    for (method, path) in [
        (Method::POST, format!("/api/ciphers/{id}/delete")),
        (Method::DELETE, format!("/api/ciphers/{second}")),
    ] {
        let response = socket(&app, method, &path, headers.clone(), b"{ignored").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-type").is_none());
        assert!(
            to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }
    {
        let s = app.store.lock().unwrap();
        assert!(sharing::source(&s.db, &id).unwrap().is_none());
        assert!(sharing::source(&s.db, &second).unwrap().is_none());
    }
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let before = state(&app.store.lock().unwrap().db);
    error_keys(
        socket(
            &app,
            Method::PUT,
            &format!("/api/ciphers/{id}/delete"),
            headers,
            b"",
        )
        .await,
        StatusCode::UNAUTHORIZED,
        1,
    )
    .await;
    assert_eq!(state(&app.store.lock().unwrap().db), before);
}
