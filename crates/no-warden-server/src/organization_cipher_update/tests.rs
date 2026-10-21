use super::*;
fn fixture() -> (Store, String) {
    let s = crate::organization_collections::tests::fixture(":memory:");
    let org: String =
        s.db.query_row("SELECT id FROM organizations LIMIT 1", [], |r| r.get(0))
            .unwrap();
    let col: String =
        s.db.query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&org],
            |r| r.get(0),
        )
        .unwrap();
    s.db.execute(
        "INSERT INTO organization_memberships VALUES('member-bob',?1,'bob','opaque',2,2,0)",
        [&org],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,0)",
        [&col],
    )
    .unwrap();
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES('cipher',NULL,?1,'cipher',?2,'2026-01-01T00:00:00.000Z','original-created')",params![org,json!({"id":"cipher","name":"old opaque","notes":"old opaque","organizationId":org,"type":2,"secureNote":{"type":0},"creationDate":"original-date","deletedDate":null,"key":"old opaque key"}).to_string()]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_ciphers VALUES(?1,'cipher')",
        [&col],
    )
    .unwrap();
    for (user, folder) in [("alice", "alice-folder"), ("bob", "bob-folder")] {
        s.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,'folder','{}','r','r')",params![folder,user]).unwrap();
        s.db.execute("INSERT INTO cipher_annotations(cipher_id,user_id,folder_id,favorite) VALUES('cipher',?1,?2,1)",params![user,folder]).unwrap();
    }
    (s, org)
}
fn body(org: &str) -> Value {
    json!({"id":"ignored-body-id","type":2,"name":"new opaque","notes":"new opaque","organizationId":org,"encryptedFor":"independent opaque identity","secureNote":{"type":0},"key":"new opaque key","folderId":null,"opaqueExtension":{"ciphertext":"retained"}})
}
fn input(body: &Value) -> Input {
    Input::parse(&serde_json::to_vec(body).unwrap())
        .unwrap_or_else(|_| panic!("Valid independently authored update fixture rejected"))
}
fn snapshot(s: &Store) -> Value {
    type StoredItem = (
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
    );
    let rows: Vec<StoredItem> = s
        .db
        .prepare("SELECT id,owner,organization_id,document,revision,created FROM items ORDER BY id")
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let annotations:Vec<(String,String,Option<String>,bool)>=s.db.prepare("SELECT cipher_id,user_id,folder_id,favorite FROM cipher_annotations ORDER BY cipher_id,user_id").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap().collect::<Result<_,_>>().unwrap();
    let revisions: Vec<(String, String)> =
        s.db.prepare("SELECT id,revision FROM accounts ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let links:Vec<(String,String)>=s.db.prepare("SELECT collection_id,cipher_id FROM organization_collection_ciphers ORDER BY collection_id,cipher_id").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
    json!([rows, annotations, revisions, links])
}
#[test]
fn shared_updates_preserve_other_viewer_annotations_ownership_links_and_opaque_data() {
    for actor in ["alice", "bob"] {
        for favorite in [None, Some(Value::Null), Some(json!(false))] {
            let (mut s, org) = fixture();
            let other = if actor == "alice" { "bob" } else { "alice" };
            let other_before = sharing::project(&s.db, other, "cipher", false)
                .unwrap()
                .unwrap();
            let before = snapshot(&s);
            let mut request = body(&org);
            if let Some(v) = favorite.clone() {
                request["favorite"] = v;
            }
            input(&request)
                .execute(&mut s, actor, "cipher")
                .unwrap_or_else(|_| panic!("Authorized update rejected"));
            let after = sharing::project(&s.db, actor, "cipher", false)
                .unwrap()
                .unwrap();
            let other_after = sharing::project(&s.db, other, "cipher", false)
                .unwrap()
                .unwrap();
            assert_eq!(
                after["favorite"],
                favorite.filter(|v| !v.is_null()).unwrap_or(json!(true))
            );
            assert_eq!(after["folderId"], Value::Null);
            assert_eq!(other_after["favorite"], other_before["favorite"]);
            assert_eq!(other_after["folderId"], other_before["folderId"]);
            let raw: (Option<String>, String, String, String) =
                s.db.query_row(
                    "SELECT owner,organization_id,document,created FROM items WHERE id='cipher'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert!(raw.0.is_none());
            assert_eq!(raw.1, org);
            assert_eq!(raw.3, "original-created");
            let doc: Value = serde_json::from_str(&raw.2).unwrap();
            assert_eq!(doc["opaqueExtension"], request["opaqueExtension"]);
            assert_eq!(doc["key"], request["key"]);
            assert_eq!(doc["id"], "cipher");
            assert_eq!(doc["creationDate"], "original-date");
            let now = snapshot(&s);
            assert_eq!(before[3], now[3]);
            assert_ne!(before[2], now[2]);
        }
    }
}
#[test]
fn schema_and_native_decision_order_reject_without_mutation() {
    let (mut s, org) = fixture();
    let before = snapshot(&s);
    let mut empty_containers = body(&org);
    empty_containers["attachments"] = json!({});
    empty_containers["attachments2"] = json!({});
    assert!(Input::parse(&serde_json::to_vec(&empty_containers).unwrap()).is_ok());
    empty_containers["attachments2"] = json!({"unsupported": "opaque"});
    assert_eq!(
        Input::parse(&serde_json::to_vec(&empty_containers).unwrap())
            .err()
            .unwrap()
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for (field, value) in [
        ("encryptedFor", Value::Null),
        ("type", json!("expected fewer elements")),
        ("name", Value::Null),
    ] {
        let mut v = body(&org);
        v[field] = value;
        assert_eq!(
            Input::parse(&serde_json::to_vec(&v).unwrap())
                .err()
                .unwrap()
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(snapshot(&s), before);
    }
    let mut v = body("foreign");
    v["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z");
    v["folderId"] = json!("bob-folder");
    let e = input(&v).execute(&mut s, "alice", "cipher").err().unwrap();
    assert!(e.1.contains("revision"));
    assert_eq!(snapshot(&s), before);
    v["lastKnownRevisionDate"] = Value::Null;
    let e = input(&v).execute(&mut s, "alice", "cipher").err().unwrap();
    assert!(e.1.starts_with("Organization mismatch"));
    assert_eq!(snapshot(&s), before);
    v["organizationId"] = json!(org);
    let e = input(&v).execute(&mut s, "alice", "cipher").err().unwrap();
    assert_eq!(e.1, "Invalid folder");
    assert_eq!(snapshot(&s), before);
    s.db.execute(
        "UPDATE organization_collection_users SET read_only=1 WHERE user_id='bob'",
        [],
    )
    .unwrap();
    v["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z");
    let e = input(&v).execute(&mut s, "bob", "cipher").err().unwrap();
    assert_eq!(e.1, "Cipher is not write accessible");
}
#[test]
fn mutation_and_deferred_commit_failures_roll_back_payload_annotations_and_fanout() {
    for deferred in [false, true] {
        let (mut s, org) = fixture();
        let before = snapshot(&s);
        s.db.execute_batch(if deferred {"CREATE TABLE failed_update(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_shared_update AFTER UPDATE OF document ON items WHEN NEW.id='cipher' BEGIN INSERT INTO failed_update VALUES('absent'); END;"}else{"CREATE TRIGGER fail_shared_update AFTER UPDATE OF document ON items WHEN NEW.id='cipher' BEGIN SELECT RAISE(FAIL,'fixture'); END;"}).unwrap();
        let request = input(&body(&org));
        assert!(request.execute(&mut s, "bob", "cipher").is_err());
        assert_eq!(snapshot(&s), before);
        s.db.execute_batch("DROP TRIGGER fail_shared_update")
            .unwrap();
        request
            .execute(&mut s, "bob", "cipher")
            .unwrap_or_else(|_| panic!("Retry after rollback failed"));
        assert_ne!(snapshot(&s), before);
    }
}

#[test]
fn shared_get_list_and_sync_projection_preserves_all_raw_extensions_and_personal_behavior() {
    let (mut s, org) = fixture();
    let mut request = body(&org);
    request["secureNote"] = json!({"type":17,"futureEncrypted":"opaque nested extension"});
    input(&request)
        .execute(&mut s, "bob", "cipher")
        .unwrap_or_else(|_| panic!("Valid update failed"));
    let raw: String =
        s.db.query_row("SELECT document FROM items WHERE id='cipher'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["opaqueExtension"], request["opaqueExtension"]);
    assert_eq!(stored["secureNote"], request["secureNote"]);
    for user in ["alice", "bob"] {
        let get = s.item(user, "cipher", "cipher").unwrap().unwrap();
        let list = sharing::list(&s.db, user).unwrap();
        let sync = s.items(user, "cipher").unwrap();
        for value in std::iter::once(&get)
            .chain(list.iter().filter(|v| v["id"] == "cipher"))
            .chain(sync.iter().filter(|v| v["id"] == "cipher"))
        {
            assert_eq!(value.as_object().unwrap().len(), 30);
            assert!(value.get("opaqueExtension").is_none());
            assert_eq!(value["secureNote"], request["secureNote"]);
            assert_eq!(value["key"], request["key"]);
        }
    }
    s.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES('personal','alice','cipher',?1,'r','r')",[json!({"id":"personal","organizationId":null,"type":2,"name":"opaque","secureNote":{"type":0},"opaqueExtension":{"ciphertext":"personal retained"}}).to_string()]).unwrap();
    let personal = s.item("alice", "personal", "cipher").unwrap().unwrap();
    assert_eq!(
        personal["opaqueExtension"]["ciphertext"],
        "personal retained"
    );
    assert!(
        s.items("alice", "cipher")
            .unwrap()
            .iter()
            .any(|v| v["id"] == "personal" && v["opaqueExtension"] == personal["opaqueExtension"])
    );
}
