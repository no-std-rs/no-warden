use super::*;
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method},
};
use no_warden::route::{self, Route};
use std::sync::{Arc, Mutex};

fn fixture() -> (Store, String, String) {
    let s = crate::organization_collections::tests::fixture(":memory:");
    let org: String =
        s.db.query_row("SELECT id FROM organizations LIMIT 1", [], |r| r.get(0))
            .unwrap();
    let collection: String =
        s.db.query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&org],
            |r| r.get(0),
        )
        .unwrap();
    s.db.execute(
        "INSERT INTO organization_memberships VALUES('bob-membership',?1,'bob','opaque',2,2,0)",
        [&org],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,0)",
        [&collection],
    )
    .unwrap();
    (s, org, collection)
}
fn seed(s: &Store, id: &str, owner: &str) {
    let doc = json!({"id":id,"type":2,"name":"original","notes":"opaque original","secureNote":{"type":0},"key":"opaque preserved key","creationDate":"2000-01-01T00:00:00.000Z","revisionDate":"2000-01-01T00:00:00.000Z","deletedDate":null,"organizationId":null,"folderId":null,"favorite":true});
    s.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,'cipher',?3,'original-revision','original-created')",params![id,owner,doc.to_string()]).unwrap();
}
fn request(ids: &[&str], org: Option<&str>, collections: &[&str]) -> Value {
    json!({"ciphers":ids.iter().map(|id|json!({"id":id,"type":2,"name":"plain bulk name","notes":"opaque submitted","secureNote":{"type":0},"organizationId":org,"favorite":false,"folderId":null,"encryptedFor":"ignored other account","opaqueExtension":{"ciphertext":"preserve-exactly"}})).collect::<Vec<_>>(),"collectionIds":collections,"encryptedFor":"ignored outer account"})
}
fn parse(body: &Value) -> Input {
    Input::parse(&serde_json::to_vec(body).unwrap())
        .unwrap_or_else(|_| panic!("Valid bulk fixture rejected"))
}
fn raw(s: &Store, id: &str) -> (Option<String>, Option<String>, String, String) {
    s.db.query_row(
        "SELECT owner,organization_id,document,revision FROM items WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .unwrap()
}
fn links(s: &Store, id: &str) -> i64 {
    s.db.query_row(
        "SELECT count(*) FROM organization_collection_ciphers WHERE cipher_id=?1",
        [id],
        |r| r.get(0),
    )
    .unwrap()
}
fn revision(s: &Store, user: &str) -> String {
    s.db.query_row("SELECT revision FROM accounts WHERE id=?1", [user], |r| {
        r.get(0)
    })
    .unwrap()
}
fn execute(input: &Input, s: &mut Store, owner: &str) -> Result<(), Failure> {
    input.execute(s, owner)
}

#[test]
fn untrusted_field_text_cannot_change_schema_failure_status() {
    for value in [
        "wrong type",
        "expected fewer elements",
        "prefix expected fewer elements suffix",
    ] {
        let mut body = request(&["one"], None, &["unused"]);
        body["ciphers"][0]["type"] = json!(value);
        let error = Input::parse(&serde_json::to_vec(&body).unwrap())
            .err()
            .expect("Invalid field type must fail before execution");
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let valid = request(&["one"], None, &["unused"]);
    let extra_slot = json!([valid["ciphers"], valid["collectionIds"], null]);
    let error = Input::parse(&serde_json::to_vec(&extra_slot).unwrap())
        .err()
        .expect("Extra positional slot must fail before execution");
    assert_eq!(error.0, StatusCode::BAD_REQUEST);
}

#[test]
fn encrypted_for_is_a_required_string_without_authority_or_uuid_validation() {
    let mut body = request(&["one"], None, &["unused"]);
    for value in [Value::Null, json!(7)] {
        body["ciphers"][0]["encryptedFor"] = value;
        let error = Input::parse(&serde_json::to_vec(&body).unwrap())
            .err()
            .expect("Invalid required string must fail before execution");
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
    body["ciphers"][0]
        .as_object_mut()
        .unwrap()
        .remove("encryptedFor");
    let error = Input::parse(&serde_json::to_vec(&body).unwrap())
        .err()
        .expect("Missing required string must fail before execution");
    assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
    for value in ["", "not-a-uuid"] {
        body["ciphers"][0]["encryptedFor"] = json!(value);
        assert!(Input::parse(&serde_json::to_vec(&body).unwrap()).is_ok());
    }
}

#[test]
fn absent_or_null_favorite_preserves_the_actor_in_each_ownership_transition() {
    for context in ["personal", "move", "shared"] {
        for null in [false, true] {
            let (mut store, org, collection) = fixture();
            seed(&store, "one", "alice");
            if context == "shared" {
                let mut initial = request(&["one"], Some(&org), &[&collection]);
                initial["ciphers"][0]["favorite"] = json!(true);
                execute(&parse(&initial), &mut store, "alice")
                    .unwrap_or_else(|_| panic!("Initial sharing must succeed"));
            }
            let target = (context != "personal").then_some(org.as_str());
            let mut body = request(&["one"], target, &[&collection]);
            if null {
                body["ciphers"][0]["favorite"] = Value::Null;
            } else {
                body["ciphers"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("favorite");
            }
            execute(&parse(&body), &mut store, "alice")
                .unwrap_or_else(|_| panic!("Annotation-preserving update must succeed"));
            let projected = sharing::project(&store.db, "alice", "one", false)
                .unwrap()
                .unwrap();
            assert_eq!(projected["favorite"], true);
            assert_eq!(projected["folderId"], Value::Null);
            assert_eq!(raw(&store, "one").1.as_deref(), target);
        }
    }
}

#[test]
fn streaming_count_and_product_budgets_reject_before_execution_without_size_hint_reserve() {
    let mut visited = 0;
    let rows = std::iter::repeat_n("id", 5_000_000).inspect(|_| visited += 1);
    let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(rows);
    assert!(bounded_vec::<_, String, MAX_BULK_COLLECTIONS>(decoder).is_err());
    assert_eq!(visited, MAX_BULK_COLLECTIONS + 1);
    let mut visited = 0;
    let rows = std::iter::repeat_n("cipher", 5_000_000).inspect(|_| visited += 1);
    let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(rows);
    assert!(bounded_vec::<_, Value, MAX_BULK_CIPHERS>(decoder).is_err());
    assert_eq!(visited, MAX_BULK_CIPHERS + 1);
    let valid = request(&["one", "two"], Some("org"), &vec!["id"; 4096]);
    assert!(Input::parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
    let invalid = request(&["one", "two", "three"], Some("org"), &vec!["id"; 4096]);
    let e = Input::parse(&serde_json::to_vec(&invalid).unwrap())
        .err()
        .unwrap();
    assert_eq!(e.0, StatusCode::UNPROCESSABLE_ENTITY);
}
#[test]
fn schema_global_presence_and_wrapper_aliases_are_checked_before_mutation() {
    let (mut s, org, col) = fixture();
    seed(&s, "one", "alice");
    let before = raw(&s, "one");
    let mut d = request(&["one", "missing"], Some(&org), &[&col]);
    d["ciphers"][1]["name"] = json!(7);
    assert_eq!(
        Input::parse(&serde_json::to_vec(&d).unwrap())
            .err()
            .unwrap()
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    d["ciphers"][1]["name"] = json!("");
    d["ciphers"][1].as_object_mut().unwrap().remove("id");
    let e = Input::parse(&serde_json::to_vec(&d).unwrap())
        .err()
        .unwrap();
    assert_eq!(e.1, "Request missing ids field");
    assert_eq!(raw(&s, "one"), before);
    assert_eq!(links(&s, "one"), 0);
    for raw in [
        r#"{"Ciphers":[],"collectionIds":[]}"#,
        r#"{"ciphers":[],"CollectionIds":[]}"#,
        r#"{"ciphers":[],"collectionIds":null}"#,
        r#"[[],[],null]"#,
    ] {
        assert!(Input::parse(raw.as_bytes()).is_err());
    }
    let d =
        parse(&json!([[{"id":"one","type":2,"name":"","encryptedFor":"ignored"}],["nonexistent"]]));
    execute(&d, &mut s, "alice")
        .unwrap_or_else(|_| panic!("Native personal positional request rejected"));
    assert_eq!(raw(&s, "one").0.as_deref(), Some("alice"));
}
#[test]
fn reverse_suffix_and_duplicate_updates_use_fresh_canonical_source_facts() {
    let (mut s, org, col) = fixture();
    seed(&s, "one", "alice");
    seed(&s, "three", "alice");
    let before = raw(&s, "one");
    let e = execute(
        &parse(&request(&["one", "missing", "three"], Some(&org), &[&col])),
        &mut s,
        "alice",
    )
    .err()
    .unwrap();
    assert_eq!(e.1, "Cipher doesn't exist");
    assert_eq!(raw(&s, "one"), before);
    assert_eq!(raw(&s, "three").1.as_deref(), Some(org.as_str()));
    let mut d = request(&["one", "one", "one"], Some(&org), &[&col, &col]);
    for (i, name) in ["first", "middle", "last"].iter().enumerate() {
        d["ciphers"][i]["name"] = json!(name);
    }
    execute(&parse(&d), &mut s, "alice").unwrap_or_else(|_| panic!("Duplicate updates rejected"));
    let row = raw(&s, "one");
    let doc: Value = serde_json::from_str(&row.2).unwrap();
    assert_eq!(doc["name"], "first");
    assert_eq!(doc["opaqueExtension"]["ciphertext"], "preserve-exactly");
    assert_eq!(links(&s, "one"), 1);
    assert!(s.pending.is_null());
}
#[test]
fn collection_and_folder_failures_keep_durable_prefix_and_account_fanout_only() {
    for bad_folder in [false, true] {
        let (mut s, org, col) = fixture();
        seed(&s, "one", "alice");
        let before = raw(&s, "one");
        let old_alice = revision(&s, "alice");
        let old_bob = revision(&s, "bob");
        let selections = if bad_folder {
            vec![col.as_str()]
        } else {
            vec![col.as_str(), "missing"]
        };
        let mut d = request(&["one"], Some(&org), &selections);
        if bad_folder {
            d["ciphers"][0]["folderId"] = json!("missing-folder");
        }
        let e = execute(&parse(&d), &mut s, "alice").err().unwrap();
        assert_eq!(
            e.1,
            if bad_folder {
                "Invalid folder"
            } else {
                "Invalid collection ID provided"
            }
        );
        assert_eq!(raw(&s, "one"), before);
        assert_eq!(links(&s, "one"), 1);
        assert_ne!(revision(&s, "alice"), old_alice);
        assert_ne!(revision(&s, "bob"), old_bob);
        assert!(s.pending.is_null());
    }
}
#[test]
fn final_failure_rolls_back_payload_and_annotations_but_not_previous_association_phase() {
    let (mut s, org, col) = fixture();
    seed(&s, "one", "alice");
    let before = raw(&s, "one");
    s.db.execute_batch("CREATE TRIGGER fail_bulk_final BEFORE UPDATE OF document ON items WHEN NEW.id='one' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(
        execute(
            &parse(&request(&["one"], Some(&org), &[&col])),
            &mut s,
            "alice"
        )
        .err()
        .unwrap()
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(links(&s, "one"), 1);
    assert_eq!(raw(&s, "one"), before);
    assert_eq!(
        s.db.query_row(
            "SELECT count(*) FROM cipher_annotations WHERE cipher_id='one'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn final_live_checks_reject_revoked_membership_and_changed_source_revision() {
    for action in [
        "UPDATE organization_memberships SET status=-1 WHERE user_id='alice';",
        "UPDATE items SET revision='concurrent-revision' WHERE id='one';",
    ] {
        let (mut s, org, col) = fixture();
        seed(&s, "one", "alice");
        let old_payload = raw(&s, "one").2;
        s.db.execute_batch(&format!("CREATE TRIGGER revoke_during_prefix AFTER INSERT ON organization_collection_ciphers BEGIN {action} END;")).unwrap();
        assert_eq!(
            execute(
                &parse(&request(&["one"], Some(&org), &[&col])),
                &mut s,
                "alice"
            )
            .err()
            .unwrap()
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(links(&s, "one"), 1);
        assert_eq!(raw(&s, "one").2, old_payload);
    }
}
#[test]
fn existing_source_manage_permission_is_separate_from_new_selection_and_private_annotations() {
    let (mut s, org, col) = fixture();
    seed(&s, "one", "alice");
    s.db.execute(
        "INSERT INTO organization_collections VALUES('readonly',?1,'opaque readonly',NULL)",
        [&org],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES('readonly','bob',1,0,1)",
        [],
    )
    .unwrap();
    execute(
        &parse(&request(&["one"], Some(&org), &["readonly"])),
        &mut s,
        "alice",
    )
    .unwrap_or_else(|_| panic!("Owner initial share failed"));
    s.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES('bob-folder','bob','folder','{}','r','r')",[]).unwrap();
    let read = sharing::project(&s.db, "bob", "one", true)
        .unwrap()
        .unwrap();
    assert_eq!(read["edit"], false);
    let mut d = request(&["one"], Some(&org), &[&col]);
    d["ciphers"][0]["favorite"] = json!(true);
    d["ciphers"][0]["folderId"] = json!("bob-folder");
    execute(&parse(&d), &mut s, "bob").unwrap_or_else(|_| panic!("Manage source authority failed"));
    let bob = sharing::project(&s.db, "bob", "one", true)
        .unwrap()
        .unwrap();
    let alice = sharing::project(&s.db, "alice", "one", true)
        .unwrap()
        .unwrap();
    assert_eq!(bob["favorite"], true);
    assert_eq!(bob["folderId"], "bob-folder");
    assert_eq!(alice["favorite"], false);
    assert_eq!(alice["folderId"], Value::Null);
    let before = raw(&s, "one");
    let e = execute(
        &parse(&request(&["one"], Some(&org), &["readonly"])),
        &mut s,
        "bob",
    )
    .err()
    .unwrap();
    assert_eq!(e.1, "No rights to modify the collection");
    assert_eq!(raw(&s, "one"), before);
    let e = execute(&parse(&request(&["one"], None, &[&col])), &mut s, "bob")
        .err()
        .unwrap();
    assert!(e.1.starts_with("Organization mismatch."));
    assert_eq!(raw(&s, "one"), before);
}
#[tokio::test]
async fn error_shapes_are_bulk_socket_scoped_and_preserve_unrelated_folder_rendering() {
    let failure = Failure(StatusCode::BAD_REQUEST, "Invalid folder");
    let ordinary = to_bytes(failure.into_response().into_body(), 8192)
        .await
        .unwrap();
    let ordinary: Value = serde_json::from_slice(&ordinary).unwrap();
    assert!(ordinary.get("ErrorModel").is_some());
    let response = render_error(Failure(StatusCode::BAD_REQUEST, "Invalid folder"));
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc.as_object().unwrap().len(), 9);
    assert_eq!(doc["object"], "error");
    let response = render_error(Failure(StatusCode::UNPROCESSABLE_ENTITY, SCHEMA_ERROR));
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc.as_object().unwrap().len(), 1);
    assert!(doc.get("error").is_some());
}
#[tokio::test]
async fn dispatcher_keeps_device_guards_before_body_and_returns_empty_native_success_without_media()
{
    let (s, org, col) = fixture();
    seed(&s, "one", "alice");
    let app = crate::App {
        store: Arc::new(Mutex::new(s)),
        base: "http://127.0.0.1".into(),
        signing_key: [1; 32],
    };
    let result = crate::dispatch(
        State(app.clone()),
        Method::PUT,
        "/api/ciphers/share".parse().unwrap(),
        HeaderMap::new(),
        Bytes::from_static(b"not json"),
    )
    .await;
    assert_eq!(result.err().unwrap().0, StatusCode::UNAUTHORIZED);
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let d = request(&["one"], Some(&org), &[&col]);
    let response = crate::dispatch(
        State(app.clone()),
        Method::PUT,
        "/api/ciphers/share".parse().unwrap(),
        headers,
        Bytes::from(serde_json::to_vec(&d).unwrap()),
    )
    .await
    .unwrap_or_else(|_| panic!("Bulk dispatch failed"));
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        to_bytes(response.into_body(), 8192)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        route::classify(route::Method::Put, "/api/ciphers/share"),
        Some(Route::CipherBulkShare)
    );
}
