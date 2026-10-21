// Independently authored MIT OR Apache-2.0 real SQL and HTTP-dispatch regressions.
use super::*;
use axum::{
    body::{Bytes, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
};
use no_warden::wire::AttachmentRequest;
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

const USERS: [&str; 6] = ["alice", "bob", "carol", "david", "erin", "frank"];
const FILE: &str = "abcdef0123456789abcd";
const BASE: &str = "http://localhost";
type SqlSnapshot = Vec<(String, Vec<Vec<SqlValue>>)>;
struct Fixture {
    store: Store,
    cipher: String,
    personal: String,
    bytes: Vec<u8>,
}
fn fixture() -> Fixture {
    fixture_at(":memory:")
}
fn fixture_at(path: &str) -> Fixture {
    let mut store = crate::organization_collections::tests::fixture(path);
    store.download_base = BASE.to_owned();
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
        let document = json!({"id":id,"organizationId":canonical,"type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","key":"opaque wrapped cipher key","secureNote":{"type":0,"futureNested":{"opaque":[null,17]}},"futureOuter":{"retained":[true,null]},"favorite":true,"folderId":null,"creationDate":"2000-01-01T00:00:00.000Z","revisionDate":"source-revision","deletedDate":null});
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
fn snapshot(store: &Store) -> SqlSnapshot {
    let names:Vec<String>=store.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    names
        .into_iter()
        .map(|n| {
            let rows = table(&store.db, &n);
            (n, rows)
        })
        .collect()
}
fn stable(store: &Store) -> SqlSnapshot {
    snapshot(store)
        .into_iter()
        .filter(|(n, _)| !["accounts", "attachments", "attachment_downloads"].contains(&n.as_str()))
        .collect()
}
fn account_material(store: &Store) -> Vec<(String, Value)> {
    let mut q = store
        .db
        .prepare("SELECT id,document FROM accounts ORDER BY id")
        .unwrap();
    q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .map(|r| {
            let (id, doc) = r.unwrap();
            let mut value: Value = serde_json::from_str(&doc).unwrap();
            value.as_object_mut().unwrap().remove("revisionDate");
            (id, value)
        })
        .collect()
}
fn revisions(store: &Store) -> Vec<String> {
    USERS
        .iter()
        .map(|u| {
            store
                .db
                .query_row("SELECT revision FROM accounts WHERE id=?1", [u], |r| {
                    r.get(0)
                })
                .unwrap()
        })
        .collect()
}
fn fanout(store: &Store, before: &[String]) {
    let after = revisions(store);
    for i in 0..USERS.len() {
        assert_eq!(
            after[i] != before[i],
            i < 3,
            "Incorrect current-reader revision fanout"
        );
    }
}
fn request() -> AttachmentRequest<'static> {
    AttachmentRequest {
        key: "opaque new wrapped file key",
        file_name: "opaque new encrypted filename",
        file_size: 257,
        admin_request: None,
    }
}
fn success(result: Result<Response, Failure>) -> Response {
    result.unwrap_or_else(|_| panic!("Expected shared attachment admission"))
}
fn denied(result: Result<Response, Failure>) -> Failure {
    match result {
        Err(e) => e,
        Ok(_) => panic!("Unexpected shared attachment admission"),
    }
}
async fn value(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
fn keys(value: &Value) -> Vec<&str> {
    let mut k: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    k.sort_unstable();
    k
}
fn normalize_urls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(s)) = m.get_mut("url") {
                let mut u = url::Url::parse(s).unwrap();
                let pairs: Vec<_> = u
                    .query_pairs()
                    .map(|(k, _)| (k.into_owned(), "<opaque>".to_owned()))
                    .collect();
                u.query_pairs_mut().clear().extend_pairs(pairs);
                *s = u.to_string();
            }
            for child in m.values_mut() {
                normalize_urls(child);
            }
        }
        Value::Array(a) => {
            for child in a {
                normalize_urls(child);
            }
        }
        _ => {}
    }
}
fn require_details(store: &Store, actor: &str, cipher: &str, reply: &Value) {
    let mut expected = project(store, actor, cipher)
        .unwrap_or_else(|_| panic!("Expected authorized cipher projection"));
    let mut actual = reply.clone();
    normalize_urls(&mut expected);
    normalize_urls(&mut actual);
    let mut known:Vec<_>="archivedDate attachments bankAccount card collectionIds creationDate deletedDate driversLicense edit favorite fields folderId id identity key login name notes object organizationId organizationUseTotp passport passwordHistory permissions reprompt revisionDate secureNote sshKey type viewPassword".split_whitespace().collect();
    known.sort_unstable();
    assert_eq!(keys(&actual), known);
    assert!(
        actual == expected,
        "Attachment response differed from actor GET projection"
    );
}
async fn business_fields(error: Failure) {
    assert_eq!(error.0, StatusCode::BAD_REQUEST);
    let r = crate::organization_cipher_lifecycle::render_error(error);
    let v = value(r).await;
    assert_eq!(
        keys(&v),
        [
            "error",
            "errorModel",
            "error_description",
            "exceptionMessage",
            "exceptionStackTrace",
            "innerExceptionMessage",
            "message",
            "object",
            "validationErrors"
        ]
    );
}
async fn empty(response: Response) {
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
}
fn cap(store: &Store, cipher: &str, id: &str) -> String {
    let record = attachments::load(&store.db, id).unwrap().unwrap();
    let v = attachments::wire(&store.db, BASE, &record).unwrap();
    let u = url::Url::parse(v["url"].as_str().unwrap()).unwrap();
    assert!(u.path().ends_with(&format!("/{cipher}/{id}")));
    u.query().unwrap().to_owned()
}
async fn bytes(store: &mut Store, cipher: &str, id: &str, query: &str) -> Vec<u8> {
    let response = success(attachments::download(store, cipher, id, Some(query)));
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn reservation_admits_measured_current_write_roles_with_exact_metadata_only_reply() {
    // Role substitutions are local SQL fixtures; their protocol admission is
    // independently established by the sealed native role matrix.
    for mode in 0..3 {
        let mut f = fixture();
        let actor = if mode == 0 { "alice" } else { "bob" };
        if mode == 1 {
            f.store.db.execute("UPDATE organization_collection_users SET read_only=0,manage=0 WHERE user_id='bob'",[]).unwrap();
        }
        let unchanged = stable(&f.store);
        let accounts = table(&f.store.db, "accounts");
        let files = table(&f.store.db, "attachments");
        let response = success(reserve(&mut f.store, actor, &f.cipher, &request()));
        assert_eq!(response.status(), StatusCode::OK);
        let r = value(response).await;
        assert_eq!(
            keys(&r),
            [
                "attachmentId",
                "cipherResponse",
                "fileUploadType",
                "object",
                "url"
            ]
        );
        assert!(
            r["object"] == "attachment-fileUpload" && r["fileUploadType"] == 0,
            "Reservation wire constants changed"
        );
        let id = r["attachmentId"].as_str().unwrap();
        assert_eq!(id.len(), 20);
        assert!(
            r["url"] == format!("/ciphers/{}/attachment/{id}", f.cipher),
            "Reservation upload URL changed scope"
        );
        require_details(&f.store, actor, &f.cipher, &r["cipherResponse"]);
        assert!(
            stable(&f.store) == unchanged && table(&f.store.db, "accounts") == accounts,
            "Reservation changed common/private/account state"
        );
        assert_eq!(table(&f.store.db, "attachments").len(), files.len() + 1);
        let row: (String, String, i64, Option<Vec<u8>>) = f
            .store
            .db
            .query_row(
                "SELECT file_name,key,size,data FROM attachments WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert!(
            row.0 == request().file_name
                && row.1 == request().key
                && row.2 == 257
                && row.3.is_none(),
            "Reservation did not preserve opaque metadata or published bytes prematurely"
        );
        let token = cap(&f.store, &f.cipher, id);
        assert_eq!(
            denied(attachments::download(
                &mut f.store,
                &f.cipher,
                id,
                Some(&token)
            ))
            .0,
            StatusCode::NOT_FOUND
        );
        let old: Vec<u8> = f
            .store
            .db
            .query_row("SELECT data FROM attachments WHERE id=?1", [FILE], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(old == f.bytes, "Reservation rewrote another encrypted file");
    }
}

#[tokio::test]
async fn upload_and_delete_preserve_opaque_vault_and_private_state_with_all_reader_fanout() {
    for mode in 0..3 {
        let actor = if mode == 0 { "alice" } else { "bob" };
        let mut f = fixture();
        if mode == 1 {
            f.store.db.execute("UPDATE organization_collection_users SET read_only=0,manage=0 WHERE user_id='bob'",[]).unwrap();
        }
        let r = value(success(reserve(&mut f.store, actor, &f.cipher, &request()))).await;
        let id = r["attachmentId"].as_str().unwrap().to_owned();
        let token = cap(&f.store, &f.cipher, &id);
        let stable_before = stable(&f.store);
        let account_before = account_material(&f.store);
        let rev = revisions(&f.store);
        let pending = project(&f.store, "carol", &f.cipher)
            .unwrap_or_else(|_| panic!("Expected readonly cipher projection"));
        empty(success(upload(
            &mut f.store,
            actor,
            &f.cipher,
            &id,
            f.bytes.clone(),
        )))
        .await;
        fanout(&f.store, &rev);
        let mut after = project(&f.store, "carol", &f.cipher)
            .unwrap_or_else(|_| panic!("Expected readonly cipher projection"));
        let mut pending = pending;
        normalize_urls(&mut after);
        normalize_urls(&mut pending);
        assert!(
            after == pending,
            "Publishing bytes changed cipher fields or attachment metadata"
        );
        assert!(
            bytes(&mut f.store, &f.cipher, &id, &token).await == f.bytes,
            "Uploaded opaque bytes changed"
        );
        assert!(
            stable(&f.store) == stable_before && account_material(&f.store) == account_before,
            "Upload changed common/private/key state"
        );
        let rev = revisions(&f.store);
        let r = value(success(delete(&mut f.store, actor, &f.cipher, &id))).await;
        assert_eq!(keys(&r), ["cipher"]);
        require_details(&f.store, actor, &f.cipher, &r["cipher"]);
        fanout(&f.store, &rev);
        assert!(attachments::load(&f.store.db, &id).unwrap().is_none());
        assert_eq!(
            denied(attachments::download(
                &mut f.store,
                &f.cipher,
                &id,
                Some(&token)
            ))
            .0,
            StatusCode::NOT_FOUND
        );
        assert!(
            stable(&f.store) == stable_before && account_material(&f.store) == account_before,
            "Delete changed common/private/key state"
        );
        let other_cap = cap(&f.store, &f.cipher, FILE);
        assert!(
            bytes(&mut f.store, &f.cipher, FILE, &other_cap).await == f.bytes,
            "Delete changed unrelated attachment bytes"
        );
    }
}

#[tokio::test]
async fn denied_roles_foreign_files_and_sources_never_mutate_or_mint_capabilities() {
    let mut f = fixture();
    let before = snapshot(&f.store);
    for actor in ["carol", "david", "erin", "frank"] {
        business_fields(denied(reserve(&mut f.store, actor, &f.cipher, &request()))).await;
        business_fields(denied(upload(
            &mut f.store,
            actor,
            &f.cipher,
            FILE,
            f.bytes.clone(),
        )))
        .await;
        business_fields(denied(delete(&mut f.store, actor, &f.cipher, FILE))).await;
        assert!(
            snapshot(&f.store) == before,
            "Denied role changed protected SQL state"
        );
    }
    for cipher in [f.personal.clone(), uuid::Uuid::new_v4().to_string()] {
        business_fields(denied(reserve(&mut f.store, "bob", &cipher, &request()))).await;
        business_fields(denied(upload(
            &mut f.store,
            "bob",
            &cipher,
            FILE,
            f.bytes.clone(),
        )))
        .await;
        business_fields(denied(delete(&mut f.store, "bob", &cipher, FILE))).await;
        assert!(
            snapshot(&f.store) == before,
            "Foreign source changed protected SQL state"
        );
    }
    f.store.db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size,data) VALUES('foreign-file',?1,'opaque foreign name','opaque foreign key',257,?2)",params![f.personal,f.bytes]).unwrap();
    let before = snapshot(&f.store);
    for id in ["foreign-file", "missing-file"] {
        business_fields(denied(upload(
            &mut f.store,
            "alice",
            &f.cipher,
            id,
            f.bytes.clone(),
        )))
        .await;
        business_fields(denied(delete(&mut f.store, "alice", &f.cipher, id))).await;
        assert!(
            snapshot(&f.store) == before,
            "Foreign/missing file caused a cross-source mutation"
        );
    }
}

#[tokio::test]
async fn account_bump_failure_rolls_back_bytes_cascades_and_revisions_then_retry_survives_reopen() {
    // This proves local SQLite atomicity only, not native backend failure behavior.
    let path = std::env::temp_dir().join(format!(
        "no-warden-shared-write-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let mut f = fixture_at(path.to_str().unwrap());
    let token = cap(&f.store, &f.cipher, FILE);
    f.store.db.execute_batch("CREATE TRIGGER reject_reader_bump BEFORE UPDATE OF revision ON accounts WHEN OLD.id='carol' BEGIN SELECT RAISE(ABORT,'controlled reader rollback'); END;").unwrap();
    for deleting in [false, true] {
        let before = snapshot(&f.store);
        let failed = if deleting {
            delete(&mut f.store, "bob", &f.cipher, FILE)
        } else {
            upload(&mut f.store, "bob", &f.cipher, FILE, vec![42; 257])
        };
        assert_eq!(denied(failed).0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            snapshot(&f.store) == before,
            "Reader bump failure leaked partial data/capability/account mutation"
        );
        assert!(
            bytes(&mut f.store, &f.cipher, FILE, &token).await == f.bytes,
            "Rollback lost old bytes or capability"
        );
    }
    f.store
        .db
        .execute_batch("DROP TRIGGER reject_reader_bump;")
        .unwrap();
    let before = revisions(&f.store);
    empty(success(upload(
        &mut f.store,
        "bob",
        &f.cipher,
        FILE,
        vec![42; 257],
    )))
    .await;
    fanout(&f.store, &before);
    let cipher = f.cipher.clone();
    drop(f);
    let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
    assert!(
        bytes(&mut reopened, &cipher, FILE, &token).await == vec![42; 257],
        "Committed upload did not survive reopen"
    );
    let before = revisions(&reopened);
    let response = success(delete(&mut reopened, "bob", &cipher, FILE));
    assert_eq!(response.status(), StatusCode::OK);
    fanout(&reopened, &before);
    drop(reopened);
    let mut reopened = Store::open(path.to_str().unwrap()).unwrap();
    assert!(attachments::load(&reopened.db, FILE).unwrap().is_none());
    assert_eq!(
        denied(attachments::download(
            &mut reopened,
            &cipher,
            FILE,
            Some(&token)
        ))
        .0,
        StatusCode::NOT_FOUND
    );
    drop(reopened);
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", path.display()));
        if p.exists() {
            std::fs::remove_file(p).unwrap();
        }
    }
}
#[derive(Clone, Copy)]
enum Race {
    Membership,
    Grant,
    Ownership,
    Revision,
    FileRewrap,
    FileScope,
    ReservationCollision,
    TooManyFiles,
}
struct Intercept<'a> {
    provider: Provider<'a>,
    race: Race,
    after_external_change: Option<SqlSnapshot>,
}
// A test-only Storage wrapper inserts an external state change after the core's
// checks but before delegating its sealed plan. Production has no race hooks.
impl Storage for Intercept<'_> {
    type Error = rusqlite::Error;
    fn map_error(e: Self::Error) -> ApiError {
        Store::map_error(e)
    }
    fn user_key_id(&mut self, o: &str) -> rusqlite::Result<Option<&str>> {
        self.provider.user_key_id(o)
    }
    fn account_exists(&mut self, e: &str) -> rusqlite::Result<bool> {
        self.provider.account_exists(e)
    }
    fn insert_account(&mut self, id: &str, r: &RegisterRequest<'_>) -> rusqlite::Result<()> {
        self.provider.insert_account(id, r)
    }
    fn folder_metadata(&mut self, id: &str) -> rusqlite::Result<Option<ItemMetadata<'_>>> {
        self.provider.folder_metadata(id)
    }
    fn save_folder(&mut self, o: &str, id: &str, r: &FolderRequest<'_>) -> rusqlite::Result<()> {
        self.provider.save_folder(o, id, r)
    }
    fn delete_folder(&mut self, o: &str, id: &str) -> rusqlite::Result<()> {
        self.provider.delete_folder(o, id)
    }
    fn cipher_metadata(&mut self, id: &str) -> rusqlite::Result<Option<ItemMetadata<'_>>> {
        self.provider.cipher_metadata(id)
    }
    fn save_cipher(&mut self, o: &str, id: &str, r: &CipherRequest<'_>) -> rusqlite::Result<()> {
        self.provider.save_cipher(o, id, r)
    }
    fn set_cipher_deleted(&mut self, o: &str, id: &str, d: bool) -> rusqlite::Result<()> {
        self.provider.set_cipher_deleted(o, id, d)
    }
    fn delete_cipher(&mut self, o: &str, id: &str) -> rusqlite::Result<()> {
        self.provider.delete_cipher(o, id)
    }
}
impl AttachmentStorage for Intercept<'_> {
    fn attachment_access(&mut self, a: &str, c: &str) -> rusqlite::Result<Option<CipherAccess>> {
        self.provider.attachment_access(a, c)
    }
    fn attachment_metadata(
        &mut self,
        id: &str,
    ) -> rusqlite::Result<Option<AttachmentMetadata<'_>>> {
        self.provider.attachment_metadata(id)
    }
    fn verify_attachment_download(
        &mut self,
        c: &str,
        id: &str,
        t: &Secret<'_>,
    ) -> rusqlite::Result<bool> {
        self.provider.verify_attachment_download(c, id, t)
    }
    fn commit_attachment(
        &mut self,
        a: &str,
        plan: &ValidatedAttachment<'_>,
    ) -> rusqlite::Result<()> {
        let db = &self.provider.store.db;
        match self.race {
            Race::Membership => {
                db.execute("UPDATE organization_memberships SET status=-1 WHERE user_id=?1 AND organization_id=?2",params![a,self.provider.source.organization_id])?;
            }
            Race::Grant => {
                db.execute("UPDATE organization_collection_users SET read_only=1,manage=0 WHERE user_id=?1",[a])?;
            }
            Race::Ownership => {
                db.execute(
                    "UPDATE items SET owner='alice',organization_id=NULL WHERE id=?1",
                    [plan.cipher_id()],
                )?;
            }
            Race::Revision => {
                db.execute(
                    "UPDATE items SET revision='externally-revised' WHERE id=?1",
                    [plan.cipher_id()],
                )?;
            }
            Race::FileRewrap => {
                db.execute("UPDATE attachments SET file_name='externally rewrapped name',key='externally rewrapped key' WHERE id=?1",[plan.attachment_id()])?;
            }
            Race::FileScope => {
                db.execute("UPDATE attachments SET cipher_id=(SELECT id FROM items WHERE owner='alice' AND kind='cipher' LIMIT 1) WHERE id=?1",[plan.attachment_id()])?;
            }
            Race::ReservationCollision => {
                db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size) VALUES(?1,?2,'external name','external key',257)",params![plan.attachment_id(),plan.cipher_id()])?;
            }
            Race::TooManyFiles => fill_files(db, plan.cipher_id(), MAX_ROWS + 1)?,
        }
        self.after_external_change = Some(snapshot(self.provider.store));
        self.provider.commit_attachment(a, plan)
    }
}
fn fill_files(db: &Connection, cipher: &str, total: usize) -> rusqlite::Result<()> {
    let current: usize = db.query_row(
        "SELECT count(*) FROM attachments WHERE cipher_id=?1",
        [cipher],
        |r| r.get(0),
    )?;
    for n in current..total {
        db.execute("INSERT INTO attachments(id,cipher_id,file_name,key,size) VALUES(?1,?2,'bounded name','bounded key',1)",params![format!("bounded-{n}"),cipher])?;
    }
    Ok(())
}
#[test]
fn sealed_commits_recheck_membership_grants_ownership_revision_file_scope_and_rewrap() {
    for action in 0..3 {
        let mut races = vec![
            Race::Membership,
            Race::Grant,
            Race::Ownership,
            Race::Revision,
        ];
        if action == 0 {
            races.push(Race::ReservationCollision);
        } else {
            races.extend([Race::FileRewrap, Race::FileScope]);
        }
        for race in races {
            let mut f = fixture();
            let cipher = f.cipher.clone();
            let provider = Provider::new(&mut f.store, "bob", &cipher, vec![33; 257])
                .unwrap_or_else(|_| panic!("Authorized test provider"));
            let mut intercept = Intercept {
                provider,
                race,
                after_external_change: None,
            };
            let mut service = VaultService::new(&mut intercept);
            let result = match action {
                0 => service.reserve_attachment("bob", &cipher, "new-reservation", &request()),
                1 => service.upload_attachment("bob", &cipher, FILE, 257),
                _ => service.delete_attachment("bob", &cipher, FILE),
            };
            assert!(result.is_err(), "Stale sealed write plan was committed");
            assert!(
                intercept
                    .after_external_change
                    .as_ref()
                    .is_some_and(|s| *s == snapshot(intercept.provider.store)),
                "Rejected stale plan changed state beyond external mutation"
            );
        }
    }
}

#[test]
fn local_material_and_row_budgets_reject_without_mutation_and_recheck_at_commit() {
    for mode in 0..3 {
        let mut f = fixture();
        if mode == 0 {
            fill_files(&f.store.db, &f.cipher, MAX_ROWS + 1).unwrap();
        } else if mode == 1 {
            f.store
                .db
                .execute(
                    "UPDATE attachments SET file_name=?1 WHERE id=?2",
                    params!["x".repeat(MAX_MATERIAL), FILE],
                )
                .unwrap();
        } else {
            let doc =
                json!({"type":2,"secureNote":{"type":0},"futureOpaque":"x".repeat(MAX_MATERIAL)});
            f.store
                .db
                .execute(
                    "UPDATE items SET document=?1 WHERE id=?2",
                    params![doc.to_string(), f.cipher],
                )
                .unwrap();
        }
        let before = snapshot(&f.store);
        for result in [
            reserve(&mut f.store, "bob", &f.cipher, &request()),
            upload(&mut f.store, "bob", &f.cipher, FILE, vec![55; 257]),
            delete(&mut f.store, "bob", &f.cipher, FILE),
        ] {
            assert!(result.is_err(), "Oversized local material admitted");
        }
        assert!(
            snapshot(&f.store) == before,
            "Local capacity rejection changed SQL state"
        );
    }
    // The last permitted existing row must not authorize an additional row.
    let mut full = fixture();
    fill_files(&full.store.db, &full.cipher, MAX_ROWS).unwrap();
    let before = snapshot(&full.store);
    assert!(
        reserve(&mut full.store, "bob", &full.cipher, &request()).is_err(),
        "Reservation exceeded prospective row budget"
    );
    assert!(
        snapshot(&full.store) == before,
        "Prospective row rejection mutated SQL state"
    );
    // Individually bounded fields still consume a cumulative prospective budget.
    let mut large = fixture();
    let name = "n".repeat(MAX_MATERIAL / 2);
    let key = "k".repeat(MAX_MATERIAL / 2);
    let input = AttachmentRequest {
        file_name: &name,
        key: &key,
        file_size: 257,
        admin_request: None,
    };
    let before = snapshot(&large.store);
    assert!(
        reserve(&mut large.store, "bob", &large.cipher, &input).is_err(),
        "Reservation exceeded prospective material budget"
    );
    assert!(
        snapshot(&large.store) == before,
        "Prospective metadata rejection mutated SQL state"
    );
    let mut f = fixture();
    let cipher = f.cipher.clone();
    let provider = Provider::new(&mut f.store, "bob", &cipher, vec![33; 257])
        .unwrap_or_else(|_| panic!("Authorized test provider"));
    let mut intercept = Intercept {
        provider,
        race: Race::TooManyFiles,
        after_external_change: None,
    };
    assert!(
        VaultService::new(&mut intercept)
            .upload_attachment("bob", &cipher, FILE, 257)
            .is_err()
    );
    assert!(
        intercept
            .after_external_change
            .as_ref()
            .is_some_and(|s| *s == snapshot(intercept.provider.store)),
        "Commit did not recheck bounded material"
    );
}

#[tokio::test]
async fn opt_in_shared_provider_leaves_personal_service_and_unimplemented_legacy_operations_isolated()
 {
    let mut f = fixture();
    let before = snapshot(&f.store);
    for actor in ["alice", "bob"] {
        let mut base = VaultService::new(&mut f.store);
        assert!(
            base.reserve_attachment(actor, &f.cipher, "base-provider-file", &request())
                .is_err()
        );
        assert!(base.upload_attachment(actor, &f.cipher, FILE, 257).is_err());
        assert!(base.delete_attachment(actor, &f.cipher, FILE).is_err());
        assert!(
            base.update_attachment_metadata(actor, &f.cipher, FILE, "new name", "new key")
                .is_err()
        );
        let provider = Provider::new(&mut f.store, actor, &f.cipher, vec![77; 257])
            .unwrap_or_else(|_| panic!("Authorized test provider"));
        let legacy = no_warden::wire::LegacyAttachmentRequest {
            file_name: Some("opaque legacy name"),
            key: Some("opaque legacy key"),
            file_size: 257,
        };
        assert!(
            VaultService::new(provider)
                .create_legacy_attachment(actor, &f.cipher, "legacy-file", &legacy)
                .is_err()
        );
        assert!(
            snapshot(&f.store) == before,
            "Unimplemented shared path broadened base storage behavior"
        );
    }
    VaultService::new(&mut f.store)
        .reserve_attachment("alice", &f.personal, "personal-file", &request())
        .unwrap();
    f.store.pending_attachment_data = f.bytes.clone();
    VaultService::new(&mut f.store)
        .upload_attachment("alice", &f.personal, "personal-file", 257)
        .unwrap();
    let q = cap(&f.store, &f.personal, "personal-file");
    assert!(
        bytes(&mut f.store, &f.personal, "personal-file", &q).await == f.bytes,
        "Existing personal upload changed"
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

async fn http(
    app: &crate::App,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: &[u8],
) -> Response {
    // Exercise transport dispatch, peer, classifier, authentication and error
    // rendering directly. This is not an actual-client or TCP trace claim.
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
async fn http_error(r: Response, status: StatusCode, fields: usize) {
    assert_eq!(r.status(), status);
    let v = value(r).await;
    assert_eq!(v.as_object().unwrap().len(), fields);
    if fields == 1 {
        assert_eq!(keys(&v), ["error"]);
        assert!(
            v["error"].is_object(),
            "Native guard error must be an object"
        );
    } else if fields == 9 {
        assert_eq!(
            keys(&v),
            [
                "error",
                "errorModel",
                "error_description",
                "exceptionMessage",
                "exceptionStackTrace",
                "innerExceptionMessage",
                "message",
                "object",
                "validationErrors"
            ]
        );
        for field in ["error", "error_description", "message", "object"] {
            assert!(
                v[field].is_string(),
                "Business error string field changed type"
            );
        }
        for field in ["errorModel", "validationErrors"] {
            assert!(
                v[field].is_object(),
                "Business error object field changed type"
            );
        }
        for field in [
            "exceptionMessage",
            "exceptionStackTrace",
            "innerExceptionMessage",
        ] {
            assert!(
                v[field].is_null(),
                "Business error exception field changed type"
            );
        }
    }
}
fn auth(actor: &str, store: &Store) -> HeaderMap {
    let token = if actor == "alice" {
        "collection-fixture-access".to_owned()
    } else {
        let token = format!("write-fixture-{actor}");
        let digest = crate::digest(&token);
        store
            .db
            .execute(
                "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5)",
                params![
                    digest,
                    crate::digest(&format!("{token}-refresh")),
                    actor,
                    chrono::Utc::now().timestamp() + 600,
                    chrono::Utc::now().timestamp() + 3600
                ],
            )
            .unwrap();
        token
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}
fn multipart(data: &[u8]) -> (HeaderMap, Vec<u8>) {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        "multipart/form-data; boundary=fixtureboundary"
            .parse()
            .unwrap(),
    );
    let mut body=b"--fixtureboundary\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n--fixtureboundary--\r\n");
    (h, body)
}
#[tokio::test]
async fn http_write_aliases_preserve_role_guards_and_native_reply_shapes() {
    for actor in ["alice", "bob"] {
        for alias in 0..4 {
            let f = fixture();
            let cipher = f.cipher.clone();
            let headers = auth(actor, &f.store);
            let app = crate::App {
                store: Arc::new(Mutex::new(f.store)),
                base: BASE.into(),
                signing_key: [1; 32],
            };
            let before = snapshot(&app.store.lock().unwrap());
            let admin = format!("/api/ciphers/{cipher}/attachment/{FILE}/admin");
            http_error(
                http(&app, Method::GET, &admin, headers.clone(), b"").await,
                StatusCode::NOT_FOUND,
                1,
            )
            .await;
            assert!(
                snapshot(&app.store.lock().unwrap()) == before,
                "Unsupported admin read changed state"
            );
            let (method, path) = match alias {
                0 => (
                    Method::DELETE,
                    format!("/api/ciphers/{cipher}/attachment/{FILE}"),
                ),
                1 => (Method::DELETE, admin),
                2 => (
                    Method::POST,
                    format!("/api/ciphers/{cipher}/attachment/{FILE}/delete"),
                ),
                _ => (
                    Method::POST,
                    format!("/api/ciphers/{cipher}/attachment/{FILE}/delete-admin"),
                ),
            };
            let r = http(&app, method, &path, headers, b"").await;
            assert_eq!(r.status(), StatusCode::OK);
            let r = value(r).await;
            assert_eq!(keys(&r), ["cipher"]);
            let store = app.store.lock().unwrap();
            require_details(&store, actor, &cipher, &r["cipher"]);
            assert!(attachments::load(&store.db, FILE).unwrap().is_none());
        }
    }
    let f = fixture();
    let cipher = f.cipher.clone();
    let alice = auth("alice", &f.store);
    let readonly = auth("carol", &f.store);
    let data = f.bytes.clone();
    let app = crate::App {
        store: Arc::new(Mutex::new(f.store)),
        base: BASE.into(),
        signing_key: [1; 32],
    };
    let reserve_path = format!("/api/ciphers/{cipher}/attachment/v2");
    let body = serde_json::to_vec(
        &json!({"fileName":request().file_name,"key":request().key,"fileSize":257}),
    )
    .unwrap();
    let before = snapshot(&app.store.lock().unwrap());
    // The separate real native guard companion measured absent/forged bearer
    // on all three actions, and auth before malformed source UUID rejection.
    for forged in [false, true] {
        let mut no_auth = HeaderMap::new();
        if forged {
            no_auth.insert(
                header::AUTHORIZATION,
                "Bearer forged-static-fixture".parse().unwrap(),
            );
        }
        http_error(
            http(&app, Method::POST, &reserve_path, no_auth.clone(), &body).await,
            StatusCode::UNAUTHORIZED,
            1,
        )
        .await;
        let (mut multipart_headers, multipart_body) = multipart(&data);
        multipart_headers.extend(no_auth.clone());
        http_error(
            http(
                &app,
                Method::POST,
                &format!("/api/ciphers/{cipher}/attachment/{FILE}"),
                multipart_headers,
                &multipart_body,
            )
            .await,
            StatusCode::UNAUTHORIZED,
            1,
        )
        .await;
        http_error(
            http(
                &app,
                Method::DELETE,
                &format!("/api/ciphers/{cipher}/attachment/{FILE}"),
                no_auth,
                b"",
            )
            .await,
            StatusCode::UNAUTHORIZED,
            1,
        )
        .await;
    }
    for authenticated in [false, true] {
        let headers = if authenticated {
            alice.clone()
        } else {
            HeaderMap::new()
        };
        let status = if authenticated {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::UNAUTHORIZED
        };
        http_error(
            http(
                &app,
                Method::POST,
                "/api/ciphers/not-a-uuid/attachment/v2",
                headers.clone(),
                &body,
            )
            .await,
            status,
            1,
        )
        .await;
        let (mut multipart_headers, multipart_body) = multipart(&data);
        multipart_headers.extend(headers.clone());
        http_error(
            http(
                &app,
                Method::POST,
                &format!("/api/ciphers/not-a-uuid/attachment/{FILE}"),
                multipart_headers,
                &multipart_body,
            )
            .await,
            status,
            1,
        )
        .await;
        http_error(
            http(
                &app,
                Method::DELETE,
                &format!("/api/ciphers/not-a-uuid/attachment/{FILE}"),
                headers,
                b"",
            )
            .await,
            status,
            1,
        )
        .await;
    }
    let absent_source = uuid::Uuid::new_v4().to_string();
    http_error(
        http(
            &app,
            Method::POST,
            &format!("/api/ciphers/{absent_source}/attachment/v2"),
            alice.clone(),
            &body,
        )
        .await,
        StatusCode::BAD_REQUEST,
        9,
    )
    .await;
    let (mut absent_headers, absent_body) = multipart(&data);
    absent_headers.extend(alice.clone());
    http_error(
        http(
            &app,
            Method::POST,
            &format!("/api/ciphers/{absent_source}/attachment/{FILE}"),
            absent_headers,
            &absent_body,
        )
        .await,
        StatusCode::BAD_REQUEST,
        9,
    )
    .await;
    http_error(
        http(
            &app,
            Method::DELETE,
            &format!("/api/ciphers/{absent_source}/attachment/{FILE}"),
            alice.clone(),
            b"",
        )
        .await,
        StatusCode::BAD_REQUEST,
        9,
    )
    .await;
    for field in ["fileName", "fileSize", "key"] {
        for invalid in 0..3 {
            let mut invalid_body: Value = serde_json::from_slice(&body).unwrap();
            let object = invalid_body.as_object_mut().unwrap();
            match invalid {
                0 => {
                    object.remove(field);
                }
                1 => {
                    object.insert(field.to_owned(), Value::Null);
                }
                _ => {
                    object.insert(field.to_owned(), json!({"unexpected":true}));
                }
            }
            let encoded = serde_json::to_vec(&invalid_body).unwrap();
            http_error(
                http(&app, Method::POST, &reserve_path, alice.clone(), &encoded).await,
                StatusCode::UNPROCESSABLE_ENTITY,
                1,
            )
            .await;
        }
    }
    http_error(
        http(&app, Method::POST, &reserve_path, alice.clone(), b"{").await,
        StatusCode::BAD_REQUEST,
        1,
    )
    .await;
    http_error(
        http(
            &app,
            Method::POST,
            &reserve_path,
            alice.clone(),
            br#"["one-field"]"#,
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        1,
    )
    .await;
    http_error(
        http(&app, Method::POST, &reserve_path, readonly.clone(), &body).await,
        StatusCode::BAD_REQUEST,
        9,
    )
    .await;
    let (mut headers, upload_body) = multipart(&data);
    headers.extend(readonly);
    http_error(
        http(
            &app,
            Method::POST,
            &format!("/api/ciphers/{cipher}/attachment/{FILE}"),
            headers,
            &upload_body,
        )
        .await,
        StatusCode::BAD_REQUEST,
        9,
    )
    .await;
    assert!(
        snapshot(&app.store.lock().unwrap()) == before,
        "HTTP denied write changed protected SQL state"
    );
    let reserve = http(&app, Method::POST, &reserve_path, alice.clone(), &body).await;
    assert_eq!(reserve.status(), StatusCode::OK);
    let reply = value(reserve).await;
    let id = reply["attachmentId"].as_str().unwrap();
    let (mut headers, body) = multipart(&data);
    headers.extend(alice);
    empty(
        http(
            &app,
            Method::POST,
            &format!("/api/ciphers/{cipher}/attachment/{id}"),
            headers,
            &body,
        )
        .await,
    )
    .await;
    let store = app.store.lock().unwrap();
    let stored: Vec<u8> = store
        .db
        .query_row("SELECT data FROM attachments WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        stored == data,
        "Multipart dispatch changed opaque encrypted bytes"
    );
}
