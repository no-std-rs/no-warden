use super::*;
use crate::organization_collections::tests::{
    add_bob, create, create_org, fixture, grant_input, input, org, snapshot,
};
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method},
    response::IntoResponse,
};
use no_warden::VaultService;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

fn update(store: &mut Store, org: &str, col: &str, input: &Input) -> Value {
    serde_json::to_value(
        VaultService::new(store)
            .update_org_collection("alice", org, col, input)
            .unwrap(),
    )
    .unwrap()
}
fn count(store: &Store, table: &str) -> i64 {
    store
        .db
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn collection_update_keeps_ids_opaque_names_and_unicode_external_id_rules() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    let created = create(&mut store, &org);
    let id = created["id"].as_str().unwrap();
    let before_bob = store.account("id", "bob").unwrap().unwrap();
    for (external, expected) in [
        (None, None),
        (Some(""), None),
        (Some(" \t\n"), None),
        (Some("\u{a0}\u{2003}\u{3000}"), None),
        (Some(" \u{200b} "), Some(" \u{200b} ")),
        (Some(" \0雪 "), Some(" \0雪 ")),
    ] {
        let mut request = input();
        request.external_id = external.map(str::to_owned);
        request.name = "replacement 雪\0".into();
        let previous = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
        let response = update(&mut store, &org, id, &request);
        assert!(
            response["id"] == id
                && response["organizationId"] == org
                && response["name"] == "replacement 雪\0"
                && response.as_object().unwrap().len() == 10
        );
        assert!(response["externalId"] == expected.map_or(Value::Null, |v| json!(v)));
        assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] != previous);
        assert!(store.account("id", "bob").unwrap().unwrap() == before_bob);
    }
    let previous = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
    let request = input();
    update(&mut store, &org, id, &request);
    let changed = store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone();
    assert!(changed != previous);
    update(&mut store, &org, id, &request);
    assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] != changed);
}

#[test]
fn collection_update_replaces_all_grants_and_advances_removed_and_new_recipients() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    add_bob(&store, &org, false);
    let grant = grant_input(&store, &org);
    let created = serde_json::to_value(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &grant)
            .unwrap(),
    )
    .unwrap();
    let id = created["id"].as_str().unwrap();
    assert!(count(&store, "organization_collection_users") == 1);
    let previous = store.account("id", "bob").unwrap().unwrap()["revisionDate"].clone();
    update(&mut store, &org, id, &input());
    assert!(count(&store, "organization_collection_users") == 0);
    assert!(store.account("id", "bob").unwrap().unwrap()["revisionDate"] != previous);
    let previous = store.account("id", "bob").unwrap().unwrap()["revisionDate"].clone();
    update(&mut store, &org, id, &grant);
    assert!(
        count(&store, "organization_collection_users") == 1
            && store.account("id", "bob").unwrap().unwrap()["revisionDate"] != previous
    );
    let fetched = serde_json::to_value(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, id)
            .unwrap(),
    )
    .unwrap();
    assert!(
        fetched["users"]
            == json!([{"id":"bob-membership","readOnly":true,"hidePasswords":false,"manage":true}])
    );
}

#[test]
fn imported_manager_can_remove_own_last_grant_and_receive_nonreadable_update_response() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    add_bob(&store, &org, false);
    store
        .db
        .execute(
            "UPDATE organization_memberships SET role=3 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    let created = create(&mut store, &org);
    let id = created["id"].as_str().unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',1,1,1)",
            [id],
        )
        .unwrap();
    let previous = store.account("id", "bob").unwrap().unwrap()["revisionDate"].clone();
    let response = serde_json::to_value(
        VaultService::new(&mut store)
            .update_org_collection("bob", &org, id, &input())
            .unwrap(),
    )
    .unwrap();
    assert!(
        response["readOnly"] == true
            && response["hidePasswords"] == false
            && response["manage"] == false
            && response.as_object().unwrap().len() == 10
    );
    assert!(
        store.account("id", "bob").unwrap().unwrap()["revisionDate"] != previous
            && count(&store, "organization_collection_users") == 0
    );
    assert!(
        VaultService::new(&mut store)
            .get_org_collection_details("bob", &org, id)
            .err()
            .is_some_and(|e| e.status_code() == 401)
    );
    assert!(
        VaultService::new(&mut store)
            .update_org_collection("bob", &org, id, &input())
            .err()
            .is_some_and(|e| e.status_code() == 401)
    );
}

#[test]
fn collection_mutations_reject_cross_organization_after_global_guard_and_reference_checks() {
    let mut store = fixture(":memory:");
    let first = org(&store);
    let created = create(&mut store, &first);
    let id = created["id"].as_str().unwrap();
    let second = create_org(&mut store, "alice");
    let foreign = create_org(&mut store, "bob");
    let stable = snapshot(&store);
    for operation in [0, 1] {
        let error = if operation == 0 {
            VaultService::new(&mut store)
                .update_org_collection("alice", &second, id, &input())
                .err()
                .unwrap()
        } else {
            VaultService::new(&mut store)
                .delete_org_collection("alice", &second, id)
                .unwrap_err()
        };
        assert!(error.status_code() == 400 && error.message == "Collection not found");
    }
    let mut invalid = input();
    invalid.groups.push(Selection {
        hide_passwords: false,
        id: "unknown".into(),
        read_only: false,
        manage: false,
    });
    assert!(
        VaultService::new(&mut store)
            .update_org_collection("alice", &second, id, &invalid)
            .err()
            .is_some_and(|e| e.message == "Invalid group")
    );
    assert!(
        VaultService::new(&mut store)
            .delete_org_collection("alice", &foreign, id)
            .err()
            .is_some_and(|e| e.status_code() == 401)
    );
    assert!(snapshot(&store) == stable);
}

#[test]
fn collection_replacement_rolls_back_name_acl_revision_and_cached_response_on_each_failure() {
    for (table, operation) in [
        ("organization_collections", "UPDATE"),
        ("organization_collection_users", "DELETE"),
        ("organization_collection_users", "INSERT"),
        ("accounts", "UPDATE"),
    ] {
        let mut store = fixture(":memory:");
        let org = org(&store);
        add_bob(&store, &org, false);
        let request = grant_input(&store, &org);
        let created = serde_json::to_value(
            VaultService::new(&mut store)
                .create_org_collection("alice", &org, &request)
                .unwrap(),
        )
        .unwrap();
        let id = created["id"].as_str().unwrap();
        let before = snapshot(&store);
        let mut new = request;
        new.name = "replacement".into();
        store.db.execute_batch(&format!("CREATE TRIGGER fail_replacement BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'rollback fixture'); END")).unwrap();
        assert!(
            VaultService::new(&mut store)
                .update_org_collection("alice", &org, id, &new)
                .is_err()
        );
        assert!(snapshot(&store) == before);
        assert!(
            store
                .organization_collection_cache
                .detail
                .as_ref()
                .unwrap()
                .row
                .name
                == "opaque"
        );
    }
}

fn seed_links(store: &Store, org: &str, col: &str, sibling: &str) {
    store.db.execute("INSERT INTO items VALUES('linked-cipher','alice','cipher',?1,0,'fixed-cipher-revision','fixed-created')",[json!({"id":"linked-cipher","organizationId":org,"name":"opaque-encrypted-name","notes":"opaque-ciphertext","future":{"nested":true}}).to_string()]).unwrap();
    store.db.execute("INSERT INTO attachments VALUES('attachment','linked-cipher','opaque-file-name','opaque-file-key',4,?1)",[&[0_u8,1,127,255][..]]).unwrap();
    for collection in [col, sibling] {
        store
            .db
            .execute(
                "INSERT INTO organization_collection_ciphers VALUES(?1,'linked-cipher')",
                [collection],
            )
            .unwrap();
    }
}
fn cipher_state(store: &Store) -> (String, String, Vec<u8>) {
    store.db.query_row("SELECT i.document,i.revision,a.data FROM items i JOIN attachments a ON a.cipher_id=i.id WHERE i.id='linked-cipher'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap()
}

#[test]
fn collection_delete_removes_only_selected_links_and_grants_preserving_cipher_and_attachments() {
    let mut store = fixture(":memory:");
    let org = org(&store);
    add_bob(&store, &org, false);
    let request = grant_input(&store, &org);
    let created = serde_json::to_value(
        VaultService::new(&mut store)
            .create_org_collection("alice", &org, &request)
            .unwrap(),
    )
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let sibling = create(&mut store, &org);
    let sibling = sibling["id"].as_str().unwrap();
    seed_links(&store, &org, id, sibling);
    let cipher = cipher_state(&store);
    let previous = store.account("id", "bob").unwrap().unwrap()["revisionDate"].clone();
    VaultService::new(&mut store)
        .delete_org_collection("alice", &org, id)
        .unwrap();
    assert!(
        count(&store, "organization_collection_users") == 0
            && count(&store, "organization_collection_ciphers") == 1
            && cipher_state(&store) == cipher
    );
    assert!(store.account("id", "bob").unwrap().unwrap()["revisionDate"] != previous);
    assert!(
        VaultService::new(&mut store)
            .get_org_collection_details("alice", &org, sibling)
            .is_ok()
    );
    assert!(
        VaultService::new(&mut store)
            .delete_org_collection("alice", &org, id)
            .err()
            .is_some_and(|e| e.status_code() == 401)
    );
}

#[test]
fn collection_delete_rolls_back_cascades_and_revisions_when_any_step_fails() {
    for (table, operation) in [
        ("organization_collections", "DELETE"),
        ("organization_collection_ciphers", "DELETE"),
        ("organization_collection_users", "DELETE"),
        ("accounts", "UPDATE"),
    ] {
        let mut store = fixture(":memory:");
        let org = org(&store);
        add_bob(&store, &org, false);
        let input = grant_input(&store, &org);
        let created = serde_json::to_value(
            VaultService::new(&mut store)
                .create_org_collection("alice", &org, &input)
                .unwrap(),
        )
        .unwrap();
        let id = created["id"].as_str().unwrap();
        let sibling = create(&mut store, &org);
        seed_links(&store, &org, id, sibling["id"].as_str().unwrap());
        let state = snapshot(&store);
        store.db.execute_batch(&format!("CREATE TRIGGER fail_deletion BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'rollback fixture'); END")).unwrap();
        assert!(
            VaultService::new(&mut store)
                .delete_org_collection("alice", &org, id)
                .is_err()
        );
        assert!(snapshot(&store) == state);
    }
}

#[tokio::test]
async fn collection_mutation_dispatch_checks_auth_device_and_paths_before_body_and_returns_empty_delete()
 {
    let mut store = fixture(":memory:");
    let org = org(&store);
    let created = create(&mut store, &org);
    let col = created["id"].as_str().unwrap();
    let path = format!("/api/organizations/{org}/collections/{col}");
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://localhost".into(),
        signing_key: [3; 32],
    };
    for (method, uri, authorized, body, expected) in [
        (
            Method::PUT,
            path.clone(),
            false,
            Bytes::from_static(b"{"),
            401,
        ),
        (
            Method::PUT,
            path.clone(),
            true,
            Bytes::from_static(b"{"),
            400,
        ),
        (
            Method::DELETE,
            format!("/api/organizations/{org}/collections/bad.id?collectionId={col}"),
            true,
            Bytes::new(),
            422,
        ),
        (
            Method::PUT,
            format!("/api/organizations/bad.id/collections/{col}?organizationId={org}"),
            true,
            Bytes::from_static(b"{"),
            422,
        ),
    ] {
        let mut headers = HeaderMap::new();
        if authorized {
            headers.insert(
                "authorization",
                "Bearer collection-fixture-access".parse().unwrap(),
            );
        }
        let response = dispatch(
            State(app.clone()),
            method,
            uri.parse().unwrap(),
            headers,
            body,
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert!(response.status().as_u16() == expected);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let response = dispatch(
        State(app.clone()),
        Method::DELETE,
        path.parse().unwrap(),
        headers.clone(),
        Bytes::from_static(b"not-json\xff"),
    )
    .await
    .unwrap_or_else(|_| panic!("Collection delete dispatch"));
    assert!(
        response.status() == StatusCode::OK
            && to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
    );
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    let error = dispatch(
        State(app),
        Method::PUT,
        path.parse().unwrap(),
        headers,
        Bytes::from_static(b"{"),
    )
    .await
    .err()
    .unwrap();
    assert!(error.0 == StatusCode::UNAUTHORIZED);
}
