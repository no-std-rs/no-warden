// Independently authored MIT OR Apache-2.0 real SQL/socket regressions.
use super::*;
use crate::organization_cipher_sharing as sharing;
use axum::{
    body::{Bytes, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method},
};
use rusqlite::{Connection, params, types::Value as SqlValue};
use serde_json::Value;
use std::sync::{Arc, Mutex};

const USERS: [&str; 6] = ["alice", "bob", "carol", "david", "erin", "frank"];
struct Fixture {
    s: Store,
    org: String,
    collection: String,
    first: String,
    second: String,
}
fn fixture() -> Fixture {
    let s = crate::organization_collections::tests::fixture(":memory:");
    let org = crate::organization_collections::tests::org(&s);
    let collection: String =
        s.db.query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    for user in &USERS[2..] {
        s.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",params![user,format!("{user}@example.test"),json!({"id":user,"email":format!("{user}@example.test"),"key":"opaque account key","privateKey":"opaque private key","securityStamp":"unchanged","revisionDate":"2000-01-01T00:00:00.000Z"}).to_string()]).unwrap();
    }
    for (user, role, status) in [
        ("bob", 2, 2),
        ("carol", 2, 2),
        ("david", 2, 2),
        ("erin", 1, 1),
        ("frank", 1, -1),
    ] {
        s.db.execute("INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque wrapped organization key',?4,?5,0)",params![format!("{user}-member"),org,user,role,status]).unwrap();
    }
    for (user, manage) in [("bob", true), ("carol", false)] {
        s.db.execute(
            "INSERT INTO organization_collection_users VALUES(?1,?2,1,0,?3)",
            params![collection, user, manage],
        )
        .unwrap();
    }
    let first = add_source(&s, &org, &collection);
    let second = add_source(&s, &org, &collection);
    s.db.execute_batch("CREATE TABLE selected_lifecycle_journal(user_id TEXT NOT NULL); CREATE TRIGGER selected_lifecycle_audit AFTER UPDATE OF revision ON accounts BEGIN INSERT INTO selected_lifecycle_journal VALUES(NEW.id); END;").unwrap();
    Fixture {
        s,
        org,
        collection,
        first,
        second,
    }
}
fn add_source(s: &Store, org: &str, collection: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let doc = json!({"id":id,"type":2,"organizationId":org,"name":"opaque encrypted name","notes":"opaque encrypted notes","key":"opaque wrapped cipher key","secureNote":{"type":0,"nestedOpaque":{"untouched":[null,17,"opaque"]}},"fields":[{"name":"opaque","value":"opaque","type":0}],"passwordHistory":[{"password":"opaque","lastUsedDate":"2000"}],"favorite":false,"folderId":null,"creationDate":"2000","revisionDate":"2000","deletedDate":null,"outerOpaque":{"untouched":[7,null,"opaque"]}});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,NULL,?2,'cipher',?3,'source-revision','source-created')",params![id,org,doc.to_string()]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
        params![collection, id],
    )
    .unwrap();
    for (index, user) in USERS[..3].iter().enumerate() {
        let folder = uuid::Uuid::new_v4().to_string();
        s.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,'folder',?3,'folder-revision','folder-created')",params![folder,user,json!({"id":folder,"name":"opaque encrypted private folder"}).to_string()]).unwrap();
        s.db.execute(
            "INSERT INTO cipher_annotations VALUES(?1,?2,?3,?4)",
            params![id, user, folder, index != 1],
        )
        .unwrap();
        s.db.execute(
            "INSERT INTO cipher_archives VALUES(?1,?2,?3)",
            params![id, user, format!("200{}-01-01T00:00:00.000Z", index + 1)],
        )
        .unwrap();
    }
    id
}
fn table(db: &Connection, name: &str) -> Vec<Vec<SqlValue>> {
    let mut q = db
        .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
        .unwrap();
    let count = q.column_count();
    q.query_map([], |r| {
        (0..count)
            .map(|i| r.get(i))
            .collect::<rusqlite::Result<Vec<SqlValue>>>()
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}
type Snapshot = Vec<(String, Vec<Vec<SqlValue>>)>;
fn state(db: &Connection) -> Snapshot {
    let names:Vec<String>=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    names
        .into_iter()
        .map(|n| {
            let rows = table(db, &n);
            (n, rows)
        })
        .collect()
}
fn revisions(s: &Store) -> [String; 6] {
    USERS.map(|u| {
        s.db.query_row("SELECT revision FROM accounts WHERE id=?1", [u], |r| {
            r.get(0)
        })
        .unwrap()
    })
}
fn journal(s: &Store) -> Vec<String> {
    s.db.prepare("SELECT user_id FROM selected_lifecycle_journal ORDER BY user_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn clear_journal(s: &Store) {
    s.db.execute("DELETE FROM selected_lifecycle_journal", [])
        .unwrap();
}
fn document(s: &Store, id: &str) -> Value {
    let raw: String =
        s.db.query_row("SELECT document FROM items WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    serde_json::from_str(&raw).unwrap()
}
fn revision(s: &Store, id: &str) -> String {
    s.db.query_row("SELECT revision FROM items WHERE id=?1", [id], |r| r.get(0))
        .unwrap()
}
fn strip_lifecycle(mut v: Value) -> Value {
    for k in ["deletedDate", "revisionDate"] {
        v.as_object_mut().unwrap().remove(k);
    }
    v
}
fn error(result: Result<Response, Failure>) -> Failure {
    match result {
        Err(e) => e,
        Ok(_) => panic!("Rejected selected operation admitted"),
    }
}
#[derive(Clone, Copy)]
enum Action {
    Trash,
    Restore,
    Delete,
}
fn actions() -> [Action; 3] {
    [Action::Trash, Action::Restore, Action::Delete]
}
fn route(action: Action) -> Route<'static> {
    match action {
        Action::Trash => Route::CipherBulkTrash,
        Action::Restore => Route::CipherBulkRestore,
        Action::Delete => Route::CipherBulkDelete,
    }
}
fn body(ids: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&json!({"ids":ids})).unwrap()
}
async fn perform(s: &mut Store, actor: &str, ids: &[&str], action: Action) -> Option<Value> {
    let r = super::dispatch(route(action), actor, &body(ids), s)
        .unwrap_or_else(|_| panic!("Valid selected lifecycle rejected"));
    assert_eq!(r.status(), StatusCode::OK);
    if matches!(action, Action::Restore) {
        assert_eq!(r.headers().get("content-type").unwrap(), "application/json");
        let v: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 1024 * 1024).await.unwrap()).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 3);
        assert_eq!(v["object"], "list");
        assert!(v["continuationToken"].is_null());
        Some(v)
    } else {
        assert!(r.headers().get("content-type").is_none());
        assert!(to_bytes(r.into_body(), 1024).await.unwrap().is_empty());
        None
    }
}
fn projection(db: &Connection, actor: &str, id: &str) -> Result<Value, ()> {
    crate::organization_cipher_archive::project(db, actor, id).map_err(|_| ())
}
fn protected_accounts(s: &Store) -> Vec<(String, String, String, Value)> {
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
        .map(|row| {
            let (id, email, password, raw) = row.unwrap();
            let mut document: Value = serde_json::from_str(&raw).unwrap();
            document.as_object_mut().unwrap().remove("revisionDate");
            (id, email, password, document)
        })
        .collect()
}

#[tokio::test]
async fn duplicate_empty_selections_reuse_reader_fanout_and_preserve_opaque_private_archives() {
    for action in actions() {
        let mut f = fixture();
        let before = state(&f.s.db);
        assert_eq!(
            perform(&mut f.s, "bob", &[], action)
                .await
                .map(|v| v["data"].as_array().unwrap().len()),
            matches!(action, Action::Restore).then_some(0)
        );
        assert_eq!(state(&f.s.db), before);
        let raw = document(&f.s, &f.first);
        let accounts = protected_accounts(&f.s);
        let old_revisions = revisions(&f.s);
        let response = perform(&mut f.s, "bob", &[&f.first, &f.first], action).await;
        assert_eq!(journal(&f.s), ["alice", "bob", "carol"]);
        for (i, old) in old_revisions.iter().enumerate() {
            assert_eq!(revisions(&f.s)[i] != *old, i < 3)
        }
        assert_eq!(protected_accounts(&f.s), accounts);
        if !matches!(action, Action::Delete) {
            assert_eq!(
                strip_lifecycle(document(&f.s, &f.first)),
                strip_lifecycle(raw)
            );
            for name in [
                "cipher_archives",
                "cipher_annotations",
                "organization_collection_ciphers",
            ] {
                assert_eq!(
                    table(&f.s.db, name),
                    before.iter().find(|(n, _)| n == name).unwrap().1
                )
            }
            if let Some(v) = response {
                assert_eq!(v["data"].as_array().unwrap().len(), 1);
                let row = &v["data"][0];
                assert_eq!(row.as_object().unwrap().len(), 30);
                assert_eq!(row, &projection(&f.s.db, "bob", &f.first).unwrap());
            }
            clear_journal(&f.s);
            let list = perform(
                &mut f.s,
                "bob",
                &[&f.second, &f.first, &f.second],
                Action::Restore,
            )
            .await
            .unwrap();
            let rows = list["data"].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            let mut ids: Vec<_> = rows.iter().map(|v| v["id"].as_str().unwrap()).collect();
            ids.sort_unstable();
            let mut expected = vec![f.first.as_str(), f.second.as_str()];
            expected.sort_unstable();
            assert_eq!(ids, expected);
            for row in rows {
                assert_eq!(row.as_object().unwrap().len(), 30);
                assert_eq!(
                    row,
                    &projection(&f.s.db, "bob", row["id"].as_str().unwrap()).unwrap()
                );
            }
            assert_eq!(
                journal(&f.s),
                ["alice", "alice", "bob", "bob", "carol", "carol"]
            );
        } else {
            assert!(sharing::source(&f.s.db, &f.first).unwrap().is_none());
            assert!(sharing::source(&f.s.db, &f.second).unwrap().is_some())
        }
    }
}

#[tokio::test]
async fn current_write_roles_mixed_subsets_and_all_invalid_targets_preserve_protected_state() {
    for (actor, readonly, manage, admitted) in [
        ("alice", true, false, true),
        ("bob", false, false, true),
        ("bob", true, true, true),
        ("bob", true, false, false),
        ("carol", true, false, false),
        ("david", false, false, false),
        ("erin", false, false, false),
        ("frank", false, false, false),
    ] {
        for action in actions() {
            let mut f = fixture();
            f.s.db.execute("UPDATE organization_collection_users SET read_only=?1,manage=?2 WHERE user_id='bob'",params![readonly,manage]).unwrap();
            let before = state(&f.s.db);
            if admitted {
                perform(&mut f.s, actor, &[&f.first], action).await;
            } else {
                assert_eq!(
                    error(super::dispatch(
                        route(action),
                        actor,
                        &body(&[&f.first]),
                        &mut f.s
                    ))
                    .0,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(state(&f.s.db), before)
            }
        }
    }
    for action in actions() {
        let mut f = fixture();
        let before = state(&f.s.db);
        let missing = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            error(super::dispatch(
                route(action),
                "bob",
                &body(&[&missing, "not-a-uuid"]),
                &mut f.s
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&f.s.db), before);
        let protected = document(&f.s, &f.second);
        let first = document(&f.s, &f.first);
        let old_revision = revision(&f.s, &f.first);
        let old_accounts = revisions(&f.s);
        assert_eq!(
            error(super::dispatch(
                route(action),
                "bob",
                &body(&[&f.first, &missing]),
                &mut f.s
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(document(&f.s, &f.second), protected);
        let exists = sharing::source(&f.s.db, &f.first).unwrap().is_some();
        let changed = if exists {
            revision(&f.s, &f.first) != old_revision
        } else {
            true
        };
        assert!(journal(&f.s).is_empty() || journal(&f.s) == ["alice", "bob", "carol"]);
        assert_eq!(!journal(&f.s).is_empty(), changed);
        for (i, old) in old_accounts.iter().enumerate() {
            assert_eq!(revisions(&f.s)[i] != *old, changed && i < 3)
        }
        if exists {
            assert_eq!(
                strip_lifecycle(document(&f.s, &f.first)),
                strip_lifecycle(first)
            );
        } else {
            assert!(matches!(action, Action::Delete));
        }
    }
}

#[test]
fn real_sql_second_step_failure_retains_first_source_and_reader_writes_but_rolls_back_the_current_graph()
 {
    // This is a local injected SQL rollback guarantee, not native attachment or
    // injected-failure parity. Three exact readers make the threshold independent
    // of source/account HashSet order.
    for action in actions() {
        let mut f = fixture();
        for id in [&f.first, &f.second] {
            let attachment = format!("local-attachment-{id}");
            f.s.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,'opaque encrypted filename','opaque wrapped attachment key',3,x'00ff01')",params![attachment,id]).unwrap();
            f.s.db
                .execute(
                    "INSERT INTO attachment_downloads VALUES(?1,?2,123456)",
                    params![format!("download-{id}"), attachment],
                )
                .unwrap();
        }
        f.s.db.execute_batch("CREATE TRIGGER selected_lifecycle_fail_second BEFORE UPDATE OF revision ON accounts WHEN (SELECT count(*) FROM selected_lifecycle_journal)>=3 BEGIN SELECT RAISE(ABORT,'local selected rollback fixture'); END;").unwrap();
        let before = state(&f.s.db);
        let originals = [document(&f.s, &f.first), document(&f.s, &f.second)];
        let old_accounts = revisions(&f.s);
        let protected = protected_accounts(&f.s);
        assert_eq!(
            error(super::dispatch(
                route(action),
                "bob",
                &body(&[&f.first, &f.second]),
                &mut f.s
            ))
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let ids = [f.first.as_str(), f.second.as_str()];
        let changed: Vec<_> = ids
            .iter()
            .copied()
            .filter(|id| {
                if matches!(action, Action::Delete) {
                    sharing::source(&f.s.db, id).unwrap().is_none()
                } else {
                    revision(&f.s, id) != "source-revision"
                }
            })
            .collect();
        assert_eq!(changed.len(), 1);
        let completed = changed[0];
        assert_eq!(journal(&f.s), ["alice", "bob", "carol"]);
        for (i, old) in old_accounts.iter().enumerate() {
            assert_eq!(revisions(&f.s)[i] != *old, i < 3)
        }
        assert_eq!(protected_accounts(&f.s), protected);
        let after = state(&f.s.db);
        for (name, rows) in before {
            if matches!(name.as_str(), "accounts" | "selected_lifecycle_journal") {
                continue;
            }
            let expected: Vec<_> = rows
                .into_iter()
                .filter(|r| match name.as_str() {
                    "items" => r[0] != SqlValue::Text(completed.into()),
                    "cipher_annotations" | "cipher_archives"
                        if matches!(action, Action::Delete) =>
                    {
                        r[0] != SqlValue::Text(completed.into())
                    }
                    "organization_collection_ciphers" | "attachments"
                        if matches!(action, Action::Delete) =>
                    {
                        r[1] != SqlValue::Text(completed.into())
                    }
                    "attachment_downloads" if matches!(action, Action::Delete) => {
                        r[1] != SqlValue::Text(format!("local-attachment-{completed}"))
                    }
                    _ => true,
                })
                .collect();
            let actual = &after.iter().find(|(n, _)| n == &name).unwrap().1;
            let actual: Vec<_> = actual
                .iter()
                .filter(|r| name != "items" || r[0] != SqlValue::Text(completed.into()))
                .cloned()
                .collect();
            assert_eq!(
                actual, expected,
                "Failing step or unrelated graph changed in {name}"
            );
        }
        if !matches!(action, Action::Delete) {
            let index = ids.iter().position(|id| *id == completed).unwrap();
            let now = document(&f.s, completed);
            assert_eq!(
                strip_lifecycle(now.clone()),
                strip_lifecycle(originals[index].clone())
            );
            assert_eq!(now["revisionDate"], revision(&f.s, completed));
            assert_eq!(
                now["deletedDate"].is_string(),
                matches!(action, Action::Trash)
            );
        }
        // Removing the injected fault permits the remaining step to succeed, showing
        // failed step did not destroy its source/children or retain a transaction lock.
        f.s.db
            .execute("DROP TRIGGER selected_lifecycle_fail_second", [])
            .unwrap();
        let remaining = ids.iter().find(|id| **id != completed).unwrap();
        assert!(super::dispatch(route(action), "bob", &body(&[remaining]), &mut f.s).is_ok());
    }
}

#[test]
fn selection_and_sql_material_budgets_reject_before_any_eligible_step() {
    let mut f = fixture();
    for request in [
        serde_json::to_vec(&json!({"ids":vec![f.first.as_str();4097]})).unwrap(),
        serde_json::to_vec(&json!({"ids":["x".repeat(8*1024*1024+1)]})).unwrap(),
    ] {
        let before = state(&f.s.db);
        assert_eq!(
            error(super::dispatch(
                Route::CipherBulkTrash,
                "bob",
                &request,
                &mut f.s
            ))
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(state(&f.s.db), before)
    }
    f.s.db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO organization_collections(id,organization_id,name,external_id) SELECT 'selected-bounded-'||x,?1,'opaque',NULL FROM n",[&f.org]).unwrap();
    f.s.db.execute("INSERT INTO organization_collection_ciphers SELECT id,?1 FROM organization_collections WHERE id LIKE 'selected-bounded-%'",[&f.second]).unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        error(super::dispatch(
            Route::CipherBulkTrash,
            "bob",
            &body(&[&f.first, &f.second]),
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
    f.s.db.execute("DELETE FROM organization_collection_ciphers WHERE collection_id LIKE 'selected-bounded-%'",[]).unwrap();
    let mut large = document(&f.s, &f.second);
    large["outerOpaque"] = Value::String("x".repeat(8 * 1024 * 1024));
    f.s.db
        .execute(
            "UPDATE items SET document=?1 WHERE id=?2",
            params![large.to_string(), f.second],
        )
        .unwrap();
    let before = state(&f.s.db);
    assert_eq!(
        error(super::dispatch(
            Route::CipherBulkTrash,
            "bob",
            &body(&[&f.first, &f.second]),
            &mut f.s
        ))
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state(&f.s.db), before);
}

async fn error_keys(response: Response, status: StatusCode, count: usize) {
    assert_eq!(response.status(), status);
    let v: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(v.as_object().unwrap().len(), count);
}
#[tokio::test]
async fn measured_lowercase_tuple_ignored_organization_and_distinct_error_categories() {
    let mut f = fixture();
    for (raw, status, count) in [
        (
            br#"{"Ids":[]}"#.as_slice(),
            StatusCode::UNPROCESSABLE_ENTITY,
            1,
        ),
        (br#"{"ids":null}"#, StatusCode::UNPROCESSABLE_ENTITY, 1),
        (br#"{"ids":[17]}"#, StatusCode::UNPROCESSABLE_ENTITY, 1),
        (b"{}", StatusCode::UNPROCESSABLE_ENTITY, 1),
        (
            br#"{"ids":[],"ids":[]}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            1,
        ),
        (b"[[],null]", StatusCode::BAD_REQUEST, 1),
        (br#"{"ids":["not-a-uuid"]}"#, StatusCode::BAD_REQUEST, 9),
    ] {
        let before = state(&f.s.db);
        let failure = error(super::dispatch(
            Route::CipherBulkTrash,
            "bob",
            raw,
            &mut f.s,
        ));
        error_keys(super::render_error(failure), status, count).await;
        assert_eq!(state(&f.s.db), before);
    }
    for org in [
        Value::Null,
        json!(17),
        json!("not-a-uuid"),
        json!(uuid::Uuid::new_v4().to_string()),
        json!(f.org),
    ] {
        let r = super::dispatch(
            Route::CipherBulkTrash,
            "bob",
            &serde_json::to_vec(
                &json!({"ids":[f.first],"organizationId":org,"ignored":{"opaque":[null,7]}}),
            )
            .unwrap(),
            &mut f.s,
        )
        .unwrap_or_else(|_| panic!("Valid parser control rejected"));
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get("content-type").is_none());
        assert!(to_bytes(r.into_body(), 1024).await.unwrap().is_empty());
    }
    let tuple = serde_json::to_vec(&json!([[f.first]])).unwrap();
    let r = super::dispatch(Route::CipherBulkRestore, "bob", &tuple, &mut f.s)
        .unwrap_or_else(|_| panic!("Valid tuple rejected"));
    assert_eq!(r.status(), StatusCode::OK);
    let list: Value =
        serde_json::from_slice(&to_bytes(r.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        list["data"][0],
        projection(&f.s.db, "bob", &f.first).unwrap()
    );
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
#[tokio::test]
async fn socket_all_eight_aliases_preserve_auth_device_and_native_response_error_shapes() {
    let f = fixture();
    let id = f.first.clone();
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
    let aliases = [
        (Method::PUT, "/api/ciphers/delete", false, false),
        (Method::PUT, "/api/ciphers/delete-admin", false, false),
        (Method::PUT, "/api/ciphers/restore", true, false),
        (Method::PUT, "/api/ciphers/restore-admin", true, false),
        (Method::DELETE, "/api/ciphers", false, true),
        (Method::DELETE, "/api/ciphers/admin", false, true),
        (Method::POST, "/api/ciphers/delete", false, true),
        (Method::POST, "/api/ciphers/delete-admin", false, true),
    ];
    for (method, path, restore, permanent) in aliases.clone() {
        let target = if permanent {
            let s = app.store.lock().unwrap();
            let source = sharing::source(&s.db, &id).unwrap().unwrap();
            add_source(&s, source.organization_id.as_ref().unwrap(), &f.collection)
        } else {
            id.clone()
        };
        let input = body(&[&target]);
        let before = state(&app.store.lock().unwrap().db);
        error_keys(
            socket(&app, method.clone(), path, HeaderMap::new(), b"{").await,
            StatusCode::UNAUTHORIZED,
            1,
        )
        .await;
        assert_eq!(state(&app.store.lock().unwrap().db), before);
        let r = socket(&app, method, path, headers.clone(), &input).await;
        assert_eq!(r.status(), StatusCode::OK);
        if restore {
            assert_eq!(r.headers().get("content-type").unwrap(), "application/json");
            let v: Value =
                serde_json::from_slice(&to_bytes(r.into_body(), 1024 * 1024).await.unwrap())
                    .unwrap();
            assert_eq!(v.as_object().unwrap().len(), 3);
            assert_eq!(v["data"][0].as_object().unwrap().len(), 30);
            assert_eq!(
                v["data"][0],
                projection(&app.store.lock().unwrap().db, "alice", &target).unwrap()
            );
        } else {
            assert!(r.headers().get("content-type").is_none());
            assert!(to_bytes(r.into_body(), 1024).await.unwrap().is_empty());
        }
        if permanent {
            assert!(
                sharing::source(&app.store.lock().unwrap().db, &target)
                    .unwrap()
                    .is_none()
            )
        }
    }
    let before = state(&app.store.lock().unwrap().db);
    error_keys(
        socket(
            &app,
            Method::POST,
            "/api/ciphers/restore",
            headers.clone(),
            b"{invalid",
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        1,
    )
    .await;
    assert_eq!(state(&app.store.lock().unwrap().db), before);
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    for (method, path, _, _) in aliases {
        let before = state(&app.store.lock().unwrap().db);
        error_keys(
            socket(&app, method, path, headers.clone(), &body(&[&id])).await,
            StatusCode::UNAUTHORIZED,
            1,
        )
        .await;
        assert_eq!(state(&app.store.lock().unwrap().db), before);
    }
}
