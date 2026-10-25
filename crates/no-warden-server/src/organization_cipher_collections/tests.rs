use super::*;
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method},
};
use std::sync::{Arc, Mutex};
fn fixture() -> (Store, String, String, String) {
    let s = crate::organization_collections::tests::fixture(":memory:");
    let org: String =
        s.db.query_row("SELECT id FROM organizations LIMIT 1", [], |r| r.get(0))
            .unwrap();
    let old: String =
        s.db.query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let new = uuid::Uuid::new_v4().to_string();
    let cipher = uuid::Uuid::new_v4().to_string();
    s.db.execute(
        "INSERT INTO organization_collections VALUES(?1,?2,'opaque name',NULL)",
        params![new, org],
    )
    .unwrap();
    s.db.execute("INSERT INTO organization_memberships VALUES('bob-member',?1,'bob','opaque wrapped key',2,2,0)",[&org]).unwrap();
    for id in [&old, &new] {
        s.db.execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,0)",
            [id],
        )
        .unwrap();
    }
    let doc = json!({"id":cipher,"type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","secureNote":{"type":0,"nestedOpaque":{"unchanged":[null,"opaque encrypted extension",7]}},"key":null,"fields":null,"passwordHistory":null,"favorite":false,"folderId":null,"creationDate":"2000-01-01T00:00:00Z","revisionDate":"2000-01-01T00:00:00Z","deletedDate":null,"organizationId":org,"outerOpaque":{"unchanged":"opaque encrypted extension"}});
    s.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,NULL,?2,'cipher',?3,'initial-revision','initial-created')",params![cipher,org,doc.to_string()]).unwrap();
    s.db.execute(
        "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
        params![old, cipher],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO cipher_annotations VALUES(?1,'alice',NULL,1)",
        [&cipher],
    )
    .unwrap();
    s.db.execute(
        "INSERT INTO cipher_annotations VALUES(?1,'bob',NULL,0)",
        [&cipher],
    )
    .unwrap();
    (s, org, cipher, new)
}
fn parse(v: &Value) -> Input {
    Input::parse(&serde_json::to_vec(v).unwrap())
        .unwrap_or_else(|_| panic!("Valid collection fixture rejected"))
}
fn raw(s: &Store, id: &str) -> (Option<String>, String, String, String) {
    s.db.query_row(
        "SELECT owner,document,revision,created FROM items WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .unwrap()
}
fn annotations(s: &Store, id: &str) -> Vec<(String, Option<String>, bool)> {
    s.db.prepare("SELECT user_id,folder_id,favorite FROM cipher_annotations WHERE cipher_id=?1 ORDER BY user_id").unwrap().query_map([id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}
fn revision(s: &Store, user: &str) -> String {
    s.db.query_row("SELECT revision FROM accounts WHERE id=?1", [user], |r| {
        r.get(0)
    })
    .unwrap()
}
fn links(s: &Store, id: &str) -> Vec<String> {
    s.db.prepare("SELECT collection_id FROM organization_collection_ciphers WHERE cipher_id=?1 ORDER BY collection_id").unwrap().query_map([id],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}
#[test]
fn replacement_preserves_raw_payload_private_annotations_and_nested_projection_extensions() {
    let (mut s, org, id, new) = fixture();
    let before = raw(&s, &id);
    let private = annotations(&s, &id);
    let protected = uuid::Uuid::new_v4().to_string();
    let unassigned = uuid::Uuid::new_v4().to_string();
    for collection in [&protected, &unassigned] {
        s.db.execute(
            "INSERT INTO organization_collections VALUES(?1,?2,'opaque collection',NULL)",
            params![collection, org],
        )
        .unwrap();
        s.db.execute(
            "INSERT INTO organization_collection_ciphers VALUES(?1,?2)",
            params![collection, id],
        )
        .unwrap();
    }
    s.db.execute(
        "INSERT INTO organization_collection_users VALUES(?1,'bob',1,0,1)",
        [&protected],
    )
    .unwrap();
    let value = parse(
        &json!({"CollectionIds":[new,new],"organizationId":"ignored","cipher":{"name":"ignored"}}),
    )
    .execute(&mut s, "bob", &id)
    .unwrap_or_else(|_| panic!("Valid replacement failed"));
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["object"], "optionalCipherDetails");
    assert_eq!(value["unavailable"], false);
    let cipher = &value["cipher"];
    assert_eq!(cipher.as_object().unwrap().len(), 30);
    assert_eq!(cipher["collectionIds"], json!([new]));
    assert_eq!(cipher["favorite"], false);
    assert!(cipher.get("outerOpaque").is_none());
    assert_eq!(
        cipher["secureNote"]["nestedOpaque"],
        json!({"unchanged":[null,"opaque encrypted extension",7]})
    );
    let mut expected = vec![new, protected, unassigned];
    expected.sort();
    assert_eq!(links(&s, &id), expected);
    assert_eq!(raw(&s, &id), before);
    assert_eq!(annotations(&s, &id), private);
    assert_eq!(
        sharing::project(&s.db, "bob", &id, true).unwrap().unwrap(),
        *cipher
    );
    assert!(
        sharing::project(&s.db, "alice", &id, true)
            .unwrap()
            .unwrap()["favorite"]
            .as_bool()
            .unwrap()
    );
}
#[test]
fn losing_last_link_still_returns_cipher_and_forces_actor_revision_then_noop_owner_advances() {
    let (mut s, _org, id, _new) = fixture();
    let before = raw(&s, &id);
    let old_bob = revision(&s, "bob");
    let old_alice = revision(&s, "alice");
    let value = parse(&json!([[]]))
        .execute(&mut s, "bob", &id)
        .unwrap_or_else(|_| panic!("Loss-of-read response was incorrectly denied"));
    assert_eq!(value["object"], "optionalCipherDetails");
    assert_eq!(value["unavailable"], false);
    assert_eq!(value["cipher"]["collectionIds"], json!([]));
    assert_eq!(value["cipher"]["edit"], false);
    assert_eq!(value["cipher"]["viewPassword"], false);
    assert!(value["cipher"].is_object());
    assert!(sharing::project(&s.db, "bob", &id, true).unwrap().is_none());
    assert!(s.item("bob", &id, "cipher").unwrap().is_none());
    assert_ne!(revision(&s, "bob"), old_bob);
    assert_ne!(revision(&s, "alice"), old_alice);
    assert_eq!(raw(&s, &id), before);
    let previous = revision(&s, "alice");
    parse(&json!({"collectionIds":[]}))
        .execute(&mut s, "alice", &id)
        .unwrap_or_else(|_| panic!("Full owner no-op denied"));
    assert_ne!(revision(&s, "alice"), previous);
    assert_eq!(raw(&s, &id), before);
}
#[test]
fn owner_removing_recipient_access_advances_removed_account_without_touching_payload() {
    let (mut s, _org, id, _new) = fixture();
    let before = raw(&s, &id);
    let old_bob = revision(&s, "bob");
    assert!(
        sharing::access(&s.db, "bob", &id)
            .unwrap()
            .unwrap()
            .readable()
    );
    parse(&json!({"collectionIds":[]}))
        .execute(&mut s, "alice", &id)
        .unwrap_or_else(|_| panic!("Owner replacement rejected"));
    assert!(
        !sharing::access(&s.db, "bob", &id)
            .unwrap()
            .unwrap()
            .readable()
    );
    assert_ne!(revision(&s, "bob"), old_bob);
    assert_eq!(raw(&s, &id), before);
}
#[test]
fn durable_add_survives_late_failure_and_final_sql_failure_rolls_back_removal() {
    let (mut s, _org, id, new) = fixture();
    let before = raw(&s, &id);
    let old = links(&s, &id);
    let old_revision = revision(&s, "bob");
    let ids = [new.as_str(), "missing"];
    assert!(
        VaultService::new(&mut s)
            .reassign_cipher_collections("bob", &id, ids.as_slice(), [0, 1].as_slice())
            .is_err()
    );
    let mut expected = old.clone();
    expected.push(new.clone());
    expected.sort();
    assert_eq!(links(&s, &id), expected);
    assert_ne!(revision(&s, "bob"), old_revision);
    assert_eq!(raw(&s, &id), before);
    let (mut s, _org, id, new) = fixture();
    let before = raw(&s, &id);
    let old = links(&s, &id);
    assert_eq!(old.len(), 1);
    // The Add commits two links first. Finish deletes the old link, then this
    // guard aborts the following revision update: the deletion must roll back.
    s.db.execute_batch("CREATE TRIGGER deny_final_collection_revision BEFORE UPDATE OF revision ON accounts WHEN (SELECT count(*) FROM organization_collection_ciphers)=1 BEGIN SELECT RAISE(ABORT,'local fixture rollback'); END;").unwrap();
    assert!(
        parse(&json!({"collectionIds":[new]}))
            .execute(&mut s, "bob", &id)
            .is_err()
    );
    let mut expected = old;
    expected.push(new.clone());
    expected.sort();
    assert_eq!(links(&s, &id), expected);
    assert_eq!(raw(&s, &id), before);
    s.db.execute_batch("DROP TRIGGER deny_final_collection_revision;")
        .unwrap();
    parse(&json!({"collectionIds":[new]}))
        .execute(&mut s, "bob", &id)
        .unwrap_or_else(|_| panic!("Retry after final transaction rollback failed"));
    assert_eq!(links(&s, &id), vec![new]);
    assert_eq!(raw(&s, &id), before);
}
#[test]
fn complete_schema_and_local_resource_budgets_reject_before_mutation() {
    let (mut s, _org, id, new) = fixture();
    let before = raw(&s, &id);
    let old = links(&s, &id);
    for body in [
        json!({}),
        json!({"collectionIds":null}),
        json!({"collectionids":[]}),
        json!({"collectionIds":[new,7]}),
    ] {
        let error = Input::parse(&serde_json::to_vec(&body).unwrap())
            .err()
            .expect("Malformed structure accepted");
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let mut consumed = 0;
    let iter = std::iter::repeat_n("id", MAX_IDS + 2).inspect(|_| consumed += 1);
    let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(iter);
    assert!(selected_ids(decoder).is_err());
    assert_eq!(consumed, MAX_IDS + 1);
    let many = (0..200)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    let error = match parse(&json!({"collectionIds":many})).execute(&mut s, "bob", &id) {
        Err(error) => error,
        Ok(_) => panic!("Local comparison-work budget ignored"),
    };
    assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(links(&s, &id), old);
    assert_eq!(raw(&s, &id), before);
}
#[tokio::test]
async fn put_route_accepts_native_body_without_media_header_and_rejects_alias_methods() {
    let (s, _org, id, new) = fixture();
    let app = crate::App {
        store: Arc::new(Mutex::new(s)),
        base: "http://localhost".into(),
        signing_key: [1; 32],
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let uri = format!("/api/ciphers/{id}/collections_v2")
        .parse::<axum::http::Uri>()
        .unwrap();
    let response = crate::dispatch(
        State(app.clone()),
        Method::PUT,
        uri.clone(),
        headers.clone(),
        Bytes::from(json!({"collectionIds":[new]}).to_string()),
    )
    .await
    .unwrap_or_else(|_| panic!("Native PUT without media type rejected"));
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(value["object"], "optionalCipherDetails");
    for method in [Method::POST, Method::GET, Method::DELETE] {
        let error = match crate::dispatch(
            State(app.clone()),
            method,
            uri.clone(),
            headers.clone(),
            Bytes::new(),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("Unimplemented alias exposed"),
        };
        assert_eq!(error.0, StatusCode::NOT_FOUND);
    }
}
