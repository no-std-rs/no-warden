// Independently authored MIT OR Apache-2.0 real SQL and socket regressions.
use super::*;
use axum::{
    body::{Bytes, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use no_warden::wire::AttachmentRequest;
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const USERS: [&str; 6] = ["alice", "bob", "carol", "david", "erin", "frank"];
const FILE: &str = "abcdef0123456789abcd";
const BASE: &str = "http://localhost";
struct Fixture {
    store: Store,
    org: String,
    collection: String,
    cipher: String,
    personal: String,
    bytes: Vec<u8>,
}
fn fixture() -> Fixture {
    let store = crate::organization_collections::tests::fixture(":memory:");
    let org = crate::organization_collections::tests::org(&store);
    let collection: String = store
        .db
        .query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    for user in &USERS[2..] {
        store.db.execute("INSERT INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",params![user,format!("{user}@example.test"),json!({"id":user,"key":"opaque account key","privateKey":"opaque private key","securityStamp":"unchanged"}).to_string()]).unwrap();
    }
    for (user, role, status) in [
        ("bob", 2, 2),
        ("carol", 2, 2),
        ("david", 2, 2),
        ("erin", 1, 1),
        ("frank", 1, -1),
    ] {
        store.db.execute("INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque organization key',?4,?5,0)",params![format!("{user}-member"),org,user,role,status]).unwrap();
    }
    for (user, manage) in [("bob", true), ("carol", false)] {
        store
            .db
            .execute(
                "INSERT INTO organization_collection_users VALUES(?1,?2,1,0,?3)",
                params![collection, user, manage],
            )
            .unwrap();
    }
    let cipher = uuid::Uuid::new_v4().to_string();
    let personal = uuid::Uuid::new_v4().to_string();
    for (id, owner, canonical) in [
        (&cipher, None, Some(org.as_str())),
        (&personal, Some("alice"), None),
    ] {
        let document = json!({"id":id,"organizationId":canonical,"type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","key":"opaque wrapped cipher key","secureNote":{"type":0,"futureNested":{"opaque":[null,17]}},"futureOuter":{"retained":[true,null]},"favorite":true,"folderId":null,"revisionDate":"source-revision","deletedDate":null});
        store.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,?3,'cipher',?4,'source-revision','source-created')",params![id,owner,canonical,document.to_string()]).unwrap();
    }
    store
        .db
        .execute(
            "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
            params![collection, cipher],
        )
        .unwrap();
    for (i, user) in USERS[..3].iter().enumerate() {
        let folder = uuid::Uuid::new_v4().to_string();
        store.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,'folder',?3,'folder-revision','folder-created')",params![folder,user,json!({"id":folder,"name":"opaque private folder"}).to_string()]).unwrap();
        store
            .db
            .execute(
                "INSERT INTO cipher_annotations VALUES(?1,?2,?3,?4)",
                params![cipher, user, folder, i != 1],
            )
            .unwrap();
        store
            .db
            .execute(
                "INSERT INTO cipher_archives VALUES(?1,?2,?3)",
                params![cipher, user, format!("200{}-01-01T00:00:00.000Z", i + 1)],
            )
            .unwrap();
    }
    let bytes: Vec<u8> = (0..257).map(|n| n as u8).collect();
    store.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES(?1,?2,'opaque encrypted filename','opaque wrapped attachment key',?3,?4)",params![FILE,cipher,bytes.len(),bytes]).unwrap();
    Fixture {
        store,
        org,
        collection,
        cipher,
        personal,
        bytes,
    }
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
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}
fn protected(store: &Store) -> Vec<(String, Vec<Vec<SqlValue>>)> {
    let names:Vec<String>=store.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='attachment_downloads' ORDER BY name").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    names
        .into_iter()
        .map(|n| {
            let rows = table(&store.db, &n);
            (n, rows)
        })
        .collect()
}
fn success(result: Result<Response, Failure>) -> Response {
    result.unwrap_or_else(|_| panic!("Expected authorized attachment response"))
}
fn rejected(result: Result<Response, Failure>) -> StatusCode {
    match result {
        Err(e) => e.0,
        Ok(_) => panic!("Unexpected attachment admission"),
    }
}
async fn value(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
async fn metadata(f: &mut Fixture, actor: &str) -> Value {
    value(success(super::metadata(
        &mut f.store,
        actor,
        &f.cipher,
        FILE,
        BASE,
    )))
    .await
}
fn query(v: &Value) -> String {
    url::Url::parse(v["url"].as_str().unwrap())
        .unwrap()
        .query()
        .unwrap()
        .to_owned()
}
fn capability(v: &Value) -> String {
    url::Url::parse(v["url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned()
}
fn require_metadata(v: &Value) {
    let mut keys: Vec<_> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["fileName", "id", "key", "object", "size", "sizeName", "url"]
    );
    assert!(
        v["id"] == FILE
            && v["object"] == "attachment"
            && v["fileName"] == "opaque encrypted filename"
            && v["key"] == "opaque wrapped attachment key",
        "Attachment metadata changed opaque fields"
    );
    assert!(
        v["size"] == "257" && v["sizeName"] == "257.00 bytes",
        "Attachment size representation changed"
    );
}

#[tokio::test]
async fn metadata_uses_current_core_read_authority_and_preserves_all_protected_sql_state() {
    let mut f = fixture();
    let before = protected(&f.store);
    for (i, user) in USERS.iter().enumerate() {
        let access = super::access(&f.store.db, user, &f.cipher)
            .unwrap()
            .unwrap();
        assert_eq!(access.readable, i < 3);
        assert!(!access.writable);
        if i < 3 {
            let v = metadata(&mut f, user).await;
            require_metadata(&v);
        } else {
            let caps = table(&f.store.db, "attachment_downloads");
            assert_eq!(
                rejected(super::metadata(&mut f.store, user, &f.cipher, FILE, BASE)),
                StatusCode::BAD_REQUEST
            );
            assert!(
                table(&f.store.db, "attachment_downloads") == caps,
                "Denied READ minted a capability"
            );
        }
        assert!(
            protected(&f.store) == before,
            "Attachment read mutated common/private/account/source data"
        );
    }
    // Writable and role-based readers share READ admission, without enabling writes.
    f.store
        .db
        .execute(
            "UPDATE organization_collection_users SET read_only=0 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    require_metadata(&metadata(&mut f, "bob").await);
    for (role, full) in [(1, false), (4, true)] {
        f.store
            .db
            .execute(
                "UPDATE organization_memberships SET role=?1,access_all=?2 WHERE user_id='david'",
                params![role, full],
            )
            .unwrap();
        require_metadata(&metadata(&mut f, "david").await);
        assert!(
            !super::access(&f.store.db, "david", &f.cipher)
                .unwrap()
                .unwrap()
                .writable
        );
    }
}

#[tokio::test]
async fn canonical_membership_is_live_and_historical_grants_reuse_read_rules_while_minted_caps_survive_revoke()
 {
    // Local resolver consistency: attachment historical-association admission has
    // no native route-specific proof in this slice.
    let mut f = fixture();
    let canonical = crate::organization_collections::tests::create_org(&mut f.store, "alice");
    f.store.db.execute("INSERT INTO organization_memberships VALUES('bob-current',?1,'bob','opaque organization key',2,2,0)",[&canonical]).unwrap();
    f.store
        .db
        .execute(
            "UPDATE items SET organization_id=?1 WHERE id=?2",
            params![canonical, f.cipher],
        )
        .unwrap();
    require_metadata(&metadata(&mut f, "bob").await);
    let v = metadata(&mut f, "bob").await;
    let token_query = query(&v);
    f.store
        .db
        .execute(
            "UPDATE organization_memberships SET status=-1 WHERE id='bob-current'",
            [],
        )
        .unwrap();
    let denied = protected(&f.store);
    assert_eq!(
        rejected(super::metadata(&mut f.store, "bob", &f.cipher, FILE, BASE)),
        StatusCode::BAD_REQUEST
    );
    let response = success(attachments::download(
        &mut f.store,
        &f.cipher,
        FILE,
        Some(&token_query),
    ));
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(
        bytes.as_ref() == f.bytes,
        "Revocation altered an already-issued capability"
    );
    assert!(
        protected(&f.store) == denied,
        "Revoked read/capability changed protected SQL state"
    );
    f.store
        .db
        .execute(
            "UPDATE organization_memberships SET status=2 WHERE id='bob-current'",
            [],
        )
        .unwrap();
    f.store.db.execute("UPDATE organization_memberships SET status=-1 WHERE organization_id=?1 AND user_id='bob'",[&f.org]).unwrap();
    require_metadata(&metadata(&mut f, "bob").await);
    f.store
        .db
        .execute(
            "DELETE FROM organization_collection_users WHERE collection_id=?1 AND user_id='bob'",
            [&f.collection],
        )
        .unwrap();
    assert_eq!(
        rejected(super::metadata(&mut f.store, "bob", &f.cipher, FILE, BASE)),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn metadata_checks_exact_cipher_scope_attachment_case_and_bounded_authorized_material_before_minting()
 {
    let mut f = fixture();
    let before = protected(&f.store);
    let caps = table(&f.store.db, "attachment_downloads");
    let uppercase_cipher = f.cipher.to_uppercase();
    for (cipher, file, status) in [
        (uppercase_cipher.as_str(), FILE, StatusCode::BAD_REQUEST),
        (f.personal.as_str(), FILE, StatusCode::BAD_REQUEST),
        (
            f.cipher.as_str(),
            "not-an-attachment",
            StatusCode::BAD_REQUEST,
        ),
        ("not-a-uuid", FILE, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        assert_eq!(
            rejected(super::metadata(&mut f.store, "alice", cipher, file, BASE)),
            status
        );
    }
    assert!(
        protected(&f.store) == before && table(&f.store.db, "attachment_downloads") == caps,
        "Invalid metadata path minted a grant or changed protected state"
    );
    for alternate in [
        f.cipher.replace('-', ""),
        format!("{{{}}}", f.cipher),
        format!("urn:uuid:{}", f.cipher),
    ] {
        assert_eq!(
            rejected(super::metadata(
                &mut f.store,
                "alice",
                &alternate,
                FILE,
                BASE
            )),
            StatusCode::BAD_REQUEST
        );
    }
    let uppercase = FILE.to_uppercase();
    let v = value(success(super::metadata(
        &mut f.store,
        "alice",
        &f.cipher,
        &uppercase,
        BASE,
    )))
    .await;
    require_metadata(&v);
    // Explicit adapter memory policy, not measured upstream capacity.
    let oversized = json!({"padding":"x".repeat(8*1024*1024)}).to_string();
    f.store
        .db
        .execute(
            "UPDATE items SET document=?1 WHERE id=?2",
            params![oversized, f.cipher],
        )
        .unwrap();
    let before = protected(&f.store);
    let caps = table(&f.store.db, "attachment_downloads");
    assert!(super::metadata(&mut f.store, "alice", &f.cipher, FILE, BASE).is_err());
    assert!(
        protected(&f.store) == before && table(&f.store.db, "attachment_downloads") == caps,
        "Bound failure mutated protected state or minted capability"
    );
    assert!(
        !super::access(&f.store.db, "erin", &f.cipher)
            .unwrap()
            .unwrap()
            .readable
    );
}

#[tokio::test]
async fn capability_scope_first_lowercase_token_headers_expiry_and_storage_errors_fail_closed() {
    let mut f = fixture();
    let v = metadata(&mut f, "carol").await;
    let token = capability(&v);
    let before = protected(&f.store);
    for (input, status) in [
        (format!("token={token}&token=forged"), StatusCode::OK),
        (format!("token=forged&token={token}"), StatusCode::NOT_FOUND),
        (format!("token=&token={token}"), StatusCode::NOT_FOUND),
        (format!("token={token}&token="), StatusCode::OK),
        (format!("Token={token}"), StatusCode::UNPROCESSABLE_ENTITY),
        (
            format!("Token=forged&token={token}&unknown=ignored"),
            StatusCode::OK,
        ),
    ] {
        let response = attachments::download(&mut f.store, &f.cipher, FILE, Some(&input));
        if status == StatusCode::OK {
            let response = success(response);
            assert!(
                response.headers().get(header::CONTENT_TYPE).is_none()
                    && response
                        .headers()
                        .get(header::CONTENT_DISPOSITION)
                        .is_none()
            );
            let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(
                bytes.as_ref() == f.bytes,
                "Capability did not return exact opaque bytes"
            );
        } else {
            assert_eq!(rejected(response), status);
        }
    }
    let q = query(&v);
    for (cipher, file) in [
        (&f.personal, FILE),
        (&f.cipher.to_uppercase(), FILE),
        (&f.cipher, FILE.to_uppercase().as_str()),
    ] {
        assert_eq!(
            rejected(attachments::download(&mut f.store, cipher, file, Some(&q))),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        rejected(attachments::download(&mut f.store, &f.cipher, FILE, None)),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    f.store
        .db
        .execute(
            "UPDATE attachment_downloads SET expires=?1",
            [chrono::Utc::now().timestamp() - 1],
        )
        .unwrap();
    assert_eq!(
        rejected(attachments::download(
            &mut f.store,
            &f.cipher,
            FILE,
            Some(&q)
        )),
        StatusCode::NOT_FOUND
    );
    assert!(
        protected(&f.store) == before,
        "Download changed protected source/private/account data"
    );
    f.store
        .db
        .execute("DROP TABLE attachment_downloads", [])
        .unwrap();
    assert_eq!(
        rejected(attachments::download(
            &mut f.store,
            &f.cipher,
            FILE,
            Some(&q)
        )),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn minted_expiry_policy_and_failed_mint_preserve_opaque_protected_state() {
    let mut f = fixture();
    let before = protected(&f.store);
    let start = chrono::Utc::now().timestamp();
    let v = metadata(&mut f, "alice").await;
    let end = chrono::Utc::now().timestamp();
    let token = capability(&v);
    let expires: i64 = f
        .store
        .db
        .query_row(
            "SELECT expires FROM attachment_downloads WHERE token=?1",
            [crate::digest(&token)],
            |r| r.get(0),
        )
        .unwrap();
    // Qualified opaque-token adapter policy: nominal60 seconds plus observed
    // inclusive integer30-second allowance; no copied JWT implementation.
    assert!(
        expires >= start + 91 && expires <= end + 91,
        "Minted capability expiry fell outside measured policy"
    );
    assert!(
        protected(&f.store) == before,
        "Capability mint altered vault state"
    );
    f.store.db.execute_batch("CREATE TRIGGER reject_download_mint BEFORE INSERT ON attachment_downloads BEGIN SELECT RAISE(ABORT,'local mint failure'); END;").unwrap();
    let caps = table(&f.store.db, "attachment_downloads");
    assert_eq!(
        rejected(super::metadata(
            &mut f.store,
            "alice",
            &f.cipher,
            FILE,
            BASE
        )),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(
        protected(&f.store) == before && table(&f.store.db, "attachment_downloads") == caps,
        "Mint failure changed protected state or existing grants"
    );
}

#[tokio::test]
async fn shared_writes_remain_denied_while_existing_personal_attachment_mutations_still_work() {
    let mut f = fixture();
    let before = protected(&f.store);
    let request = AttachmentRequest {
        key: "opaque key",
        file_name: "opaque filename",
        file_size: 257,
        admin_request: None,
    };
    for user in USERS[..3].iter() {
        let mut service = VaultService::new(&mut f.store);
        assert!(
            service
                .reserve_attachment(user, &f.cipher, "fresh", &request)
                .is_err()
        );
        assert!(
            service
                .upload_attachment(user, &f.cipher, FILE, 257)
                .is_err()
        );
        assert!(service.delete_attachment(user, &f.cipher, FILE).is_err());
        assert!(
            service
                .update_attachment_metadata(user, &f.cipher, FILE, "changed", "changed")
                .is_err()
        );
    }
    assert!(
        protected(&f.store) == before,
        "Denied shared attachment mutation changed SQL state"
    );
    VaultService::new(&mut f.store)
        .reserve_attachment("alice", &f.personal, "personal-file", &request)
        .unwrap();
    f.store.pending_attachment_data = f.bytes.clone();
    VaultService::new(&mut f.store)
        .upload_attachment("alice", &f.personal, "personal-file", 257)
        .unwrap();
    let record = attachments::load(&f.store.db, "personal-file")
        .unwrap()
        .unwrap();
    assert_eq!(record.size, 257);
    let v = attachments::wire(&f.store.db, BASE, &record).unwrap();
    let response = success(attachments::download(
        &mut f.store,
        &f.personal,
        "personal-file",
        Some(&query(&v)),
    ));
    assert!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref() == f.bytes,
        "Personal encrypted attachment changed"
    );
    assert!(
        !super::access(&f.store.db, "bob", &f.personal)
            .unwrap()
            .unwrap()
            .readable
    );
    VaultService::new(&mut f.store)
        .delete_attachment("alice", &f.personal, "personal-file")
        .unwrap();
    assert!(
        attachments::load(&f.store.db, "personal-file")
            .unwrap()
            .is_none()
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
async fn error_fields(response: Response, status: StatusCode, count: usize) {
    assert_eq!(response.status(), status);
    let v = value(response).await;
    assert_eq!(v.as_object().unwrap().len(), count);
}
#[tokio::test]
async fn scoped_socket_head_preserves_get_lengths_auth_uuid_guards_and_native_errors() {
    let f = fixture();
    let cipher = f.cipher.clone();
    let bytes = f.bytes.clone();
    let path = format!("/api/ciphers/{cipher}/attachment/{FILE}");
    let app = crate::App {
        store: Arc::new(Mutex::new(f.store)),
        base: BASE.into(),
        signing_key: [1; 32],
    };
    let mut auth = HeaderMap::new();
    auth.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let before = protected(&app.store.lock().unwrap());
    let caps = table(&app.store.lock().unwrap().db, "attachment_downloads");
    error_fields(
        socket(&app, Method::GET, &path, HeaderMap::new(), b"\xff\0").await,
        StatusCode::UNAUTHORIZED,
        1,
    )
    .await;
    error_fields(
        socket(
            &app,
            Method::GET,
            "/api/ciphers/not-a-uuid/attachment/no-file",
            HeaderMap::new(),
            b"{",
        )
        .await,
        StatusCode::UNAUTHORIZED,
        1,
    )
    .await;
    error_fields(
        socket(
            &app,
            Method::GET,
            "/api/ciphers/not-a-uuid/attachment/no-file",
            auth.clone(),
            b"{",
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        1,
    )
    .await;
    assert!(
        table(&app.store.lock().unwrap().db, "attachment_downloads") == caps,
        "Auth/path guards minted capability"
    );
    // Exercise the real URI classifier/auth/error dispatcher, not metadata()
    // directly: native compact/braced/URN source spellings are business400,
    // rather than aliases or a classifier404. URL construction represents the
    // braced form exactly as the portable reqwest client sends it on the wire.
    for alternate in [
        cipher.replace('-', ""),
        format!("{{{cipher}}}"),
        format!("urn:uuid:{cipher}"),
    ] {
        let url =
            url::Url::parse(&format!("{BASE}/api/ciphers/{alternate}/attachment/{FILE}")).unwrap();
        error_fields(
            socket(&app, Method::GET, url.path(), auth.clone(), b"\xff\0").await,
            StatusCode::BAD_REQUEST,
            9,
        )
        .await;
        assert!(
            protected(&app.store.lock().unwrap()) == before
                && table(&app.store.lock().unwrap().db, "attachment_downloads") == caps,
            "Alternate source spelling changed protected SQL state or minted capability"
        );
    }
    let get = socket(&app, Method::GET, &path, auth.clone(), b"\xff\0").await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let document = value(get).await;
    require_metadata(&document);
    let serialized_length = serde_json::to_vec(&document).unwrap().len();
    let head = socket(&app, Method::HEAD, &path, auth.clone(), b"ignored").await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        head.headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        serialized_length
    );
    assert!(to_bytes(head.into_body(), 1024).await.unwrap().is_empty());
    let u = url::Url::parse(document["url"].as_str().unwrap()).unwrap();
    let download = format!("{}?{}", u.path(), u.query().unwrap());
    for method in [Method::GET, Method::HEAD] {
        let r = socket(&app, method.clone(), &download, HeaderMap::new(), b"\xff\0").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(
            r.headers().get(header::CONTENT_TYPE).is_none()
                && r.headers().get(header::CONTENT_DISPOSITION).is_none()
        );
        if method == Method::HEAD {
            assert_eq!(r.headers().get(header::CONTENT_LENGTH).unwrap(), "257");
            assert!(to_bytes(r.into_body(), 1024).await.unwrap().is_empty());
        } else {
            assert!(
                to_bytes(r.into_body(), 1024).await.unwrap().as_ref() == bytes,
                "Socket encrypted download changed"
            );
        }
    }
    error_fields(
        socket(&app, Method::GET, u.path(), auth.clone(), b"").await,
        StatusCode::UNPROCESSABLE_ENTITY,
        1,
    )
    .await;
    error_fields(
        socket(
            &app,
            Method::GET,
            &format!("{}?token=forged", u.path()),
            HeaderMap::new(),
            b"",
        )
        .await,
        StatusCode::NOT_FOUND,
        1,
    )
    .await;
    error_fields(
        socket(&app, Method::PUT, &path, auth.clone(), b"{}").await,
        StatusCode::NOT_FOUND,
        1,
    )
    .await;
    for target in [
        format!("/attachments/not-a-uuid/{FILE}?{}", u.query().unwrap()),
        format!("/attachments/not-a-uuid/{FILE}"),
    ] {
        error_fields(
            socket(&app, Method::GET, &target, HeaderMap::new(), b"").await,
            StatusCode::UNPROCESSABLE_ENTITY,
            1,
        )
        .await;
    }
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let unbound = socket(&app, Method::GET, &path, auth, b"").await;
    assert_eq!(unbound.status(), StatusCode::OK);
    require_metadata(&value(unbound).await);
    let after = protected(&app.store.lock().unwrap());
    let changed_tables: Vec<_> = before
        .iter()
        .zip(&after)
        .filter(|(a, b)| a != b)
        .map(|(a, _)| a.0.as_str())
        .collect();
    assert_eq!(changed_tables, ["session_devices"]);
}
