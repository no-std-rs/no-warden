use super::*;
use crate::organization_collections::tests::{create_org, fixture, org};
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};
use no_warden::VaultService;
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn accepted(store: &Store, organization: &str, role: i32, status: i32) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,'bob','old-opaque-key',?3,?4,0)",
            params![id, organization, role, status],
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_member_inviters VALUES(?1,'alice@example.test')",
            [&id],
        )
        .unwrap();
    id
}
fn request() -> OrganizationConfirmRequest<'static> {
    OrganizationConfirmRequest {
        id: Some("ignored-body-id"),
        key: Some(Secret::new("opaque\0wrapped-organization-key雪")),
    }
}
fn snapshot(store: &Store) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
    let mut names = store
        .db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    names
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|name| {
            let name = name.unwrap();
            // Names originate from this adapter's fixed schema, never a request.
            assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            let mut statement = store
                .db
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap();
            let count = statement.column_count();
            let rows = statement
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}
#[test]
fn confirmation_decoder_preserves_optional_tuple_fields_opaque_keys_and_ignored_body_id() {
    for body in [
        br#"{}"#.as_slice(),
        br#"[null,null]"#,
        br#"{"id":"not-a-uuid","Key":"ignored"}"#,
    ] {
        let input = Input::parse(body).unwrap_or_else(|_| panic!("Optional confirmation schema"));
        assert!(input.request().key.is_none());
    }
    let positional = Input::parse(br#"["not-a-uuid"," \u0000opaque\u96ea"]"#)
        .unwrap_or_else(|_| panic!("Positional confirmation"));
    assert!(
        positional.request().id == Some("not-a-uuid")
            && positional
                .request()
                .key
                .is_some_and(|k| k.expose_secret() == " \0opaque雪")
    );
    for body in [
        br#"{"key":3}"#.as_slice(),
        br#"{"id":false,"key":"opaque"}"#,
        br#"{"key":"a","key":"b"}"#,
        br#"{"id":"a","id":"b"}"#,
        br#"[]"#,
        br#"[null]"#,
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for body in [b"{".as_slice(), br#"[null,"opaque",false]"#] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
}
#[test]
fn confirmation_changes_only_selected_key_status_and_recipient_revision() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let sibling = create_org(&mut store, "alice");
    let member = accepted(&store, &organization, 2, 1);
    accepted(&store, &sibling, 2, 1);
    let collection: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&organization],
            |r| r.get(0),
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',1,1,1)",
            [&collection],
        )
        .unwrap();
    store.db.execute("UPDATE accounts SET revision='2100-01-01T00:00:00.000Z',document=json_set(document,'$.revisionDate','2100-01-01T00:00:00.000Z','$.keys',json('{\"publicKey\":\"opaque-public\",\"encryptedPrivateKey\":\"opaque-private\"}'),'$.future',json('{\"retained\":true}')) WHERE id='bob'",[]).unwrap();
    let before = snapshot(&store);
    VaultService::new(&mut store)
        .confirm_org_member("alice", &organization, &member, &request())
        .unwrap();
    let after = snapshot(&store);
    let mut expected = before.clone();
    let selected = expected
        .get_mut("organization_memberships")
        .unwrap()
        .iter_mut()
        .find(|r| r[0] == SqlValue::Text(member.clone()))
        .unwrap();
    selected[3] = SqlValue::Text("opaque\0wrapped-organization-key雪".into());
    selected[5] = SqlValue::Integer(2);
    let account = expected
        .get_mut("accounts")
        .unwrap()
        .iter_mut()
        .find(|r| r[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let actual = after["accounts"]
        .iter()
        .find(|r| r[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let SqlValue::Text(revision) = &actual[4] else {
        panic!("Account revision type")
    };
    assert!(revision.as_str() > "2100-01-01T00:00:00.000Z");
    let SqlValue::Text(raw) = &account[2] else {
        panic!("Account document type")
    };
    let mut document: Value = serde_json::from_str(raw).unwrap();
    document["revisionDate"] = json!(revision);
    let SqlValue::Text(actual_raw) = &actual[2] else {
        panic!("Account document type")
    };
    assert!(serde_json::from_str::<Value>(actual_raw).unwrap() == document);
    account[2] = actual[2].clone();
    account[4] = actual[4].clone();
    assert!(after == expected);
    let response = serde_json::to_value(
        VaultService::new(&mut store)
            .list_user_collections("bob")
            .unwrap()
            .details(),
    )
    .unwrap();
    assert!(
        response.as_array().unwrap().len() == 1
            && response[0]["id"] == collection
            && response[0]["readOnly"] == true
            && response[0]["hidePasswords"] == true
            && response[0]["manage"] == false
    );
}
#[test]
fn confirmation_backend_failure_rolls_back_membership_and_complete_private_state() {
    for failure in ["membership", "revision"] {
        let mut store = fixture(":memory:");
        let organization = org(&store);
        let member = accepted(&store, &organization, 2, 1);
        let trigger = if failure == "membership" {
            "CREATE TRIGGER reject_confirmation AFTER UPDATE ON organization_memberships BEGIN SELECT RAISE(ABORT,'injected confirmation failure'); END;"
        } else {
            "CREATE TRIGGER reject_confirmation AFTER UPDATE ON accounts BEGIN SELECT RAISE(ABORT,'injected revision failure'); END;"
        };
        store.db.execute_batch(trigger).unwrap();
        let before = snapshot(&store);
        let error = VaultService::new(&mut store)
            .confirm_org_member("alice", &organization, &member, &request())
            .err()
            .unwrap();
        assert!(error.status_code() == 500 && snapshot(&store) == before);
    }
}

#[test]
fn confirmation_survives_reopening_without_changing_other_persistent_state() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "no-warden-confirmation-reopen-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("vault.db");
    let expected = {
        let mut store = fixture(path.to_str().unwrap());
        let organization = org(&store);
        let member = accepted(&store, &organization, 2, 1);
        VaultService::new(&mut store)
            .confirm_org_member("alice", &organization, &member, &request())
            .unwrap();
        snapshot(&store)
    };
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == expected);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn confirmation_role_state_and_scope_rejections_never_mutate_storage() {
    for actor in [0, 1, 2, 3] {
        for target in [0, 1, 2, 3] {
            for status in [-1, 0, 1, 2] {
                let mut store = fixture(":memory:");
                let organization = org(&store);
                let member = accepted(&store, &organization, target, status);
                store
                    .db
                    .execute(
                        "UPDATE organization_memberships SET role=?1 WHERE user_id='alice'",
                        [actor],
                    )
                    .unwrap();
                let before = snapshot(&store);
                let result = VaultService::new(&mut store).confirm_org_member(
                    "alice",
                    &organization,
                    &member,
                    &request(),
                );
                let allowed = matches!(actor, 0 | 1) && (actor == 0 || target == 2) && status == 1;
                assert!(result.is_ok() == allowed);
                if !allowed {
                    assert!(snapshot(&store) == before);
                }
            }
        }
    }
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let foreign = create_org(&mut store, "alice");
    let member = accepted(&store, &foreign, 2, 1);
    let before = snapshot(&store);
    for id in [member.as_str(), "missing"] {
        assert!(
            VaultService::new(&mut store)
                .confirm_org_member("alice", &organization, id, &request())
                .err()
                .is_some_and(
                    |e| e.message == "The specified user isn't a member of the organization"
                )
        );
        assert!(snapshot(&store) == before);
    }
}
#[test]
fn confirmed_collection_visibility_and_sync_flags_follow_stored_grants_separately() {
    for (role, access_all, grant, read_only, hide, stored_manage) in [
        (0, false, false, false, false, false),
        (1, false, false, false, false, false),
        (0, false, true, true, true, false),
        (1, false, true, true, true, false),
        (2, true, false, false, false, false),
        (3, true, false, false, false, false),
        (2, false, true, true, true, true),
        (2, false, true, false, false, true),
        (3, false, true, true, true, true),
        (3, false, true, false, false, false),
        (3, false, true, true, false, false),
        (2, false, false, false, false, false),
    ] {
        for status in [0, 1, 2, -1] {
            let mut store = fixture(":memory:");
            let organization = org(&store);
            accepted(&store, &organization, role, status);
            store
                .db
                .execute(
                    "UPDATE organization_memberships SET access_all=?1 WHERE user_id='bob'",
                    [access_all],
                )
                .unwrap();
            if grant {
                let collection: String = store
                    .db
                    .query_row(
                        "SELECT id FROM organization_collections WHERE organization_id=?1",
                        [&organization],
                        |r| r.get(0),
                    )
                    .unwrap();
                store
                    .db
                    .execute(
                        "INSERT INTO organization_collection_users VALUES(?1,'bob',?2,?3,?4)",
                        params![collection, read_only, hide, stored_manage],
                    )
                    .unwrap();
            }
            let rows = serde_json::to_value(
                VaultService::new(&mut store)
                    .list_user_collections("bob")
                    .unwrap()
                    .details(),
            )
            .unwrap();
            let visible = status == 2 && (access_all || grant);
            assert!(rows.as_array().unwrap().len() == usize::from(visible));
            if visible {
                let full = access_all || matches!(role, 0 | 1);
                let manage = matches!(role, 0 | 1)
                    || (role == 3 && (full || stored_manage || (!read_only && !hide)));
                assert!(
                    rows[0]["readOnly"] == (!full && read_only)
                        && rows[0]["hidePasswords"] == (!full && hide)
                        && rows[0]["manage"] == manage
                );
            }
        }
    }
}
#[tokio::test]
async fn confirmation_dispatch_preserves_guard_order_and_nine_field_errors() {
    let store = fixture(":memory:");
    let organization = org(&store);
    let member = accepted(&store, &organization, 2, 1);
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let valid = format!("/api/organizations/{organization}/users/{member}/confirm");
    let before = snapshot(&app.store.lock().unwrap());
    for (path, token, body, status) in [
        (valid.clone(), None, b"{invalid".as_slice(), 401),
        (
            "/api/organizations/invalid/users/invalid/confirm".to_owned(),
            Some("collection-fixture-access"),
            b"{invalid",
            401,
        ),
        (
            format!(
                "/api/organizations/invalid/users/invalid/confirm?organizationId={organization}"
            ),
            Some("collection-fixture-access"),
            b"{invalid",
            422,
        ),
        (
            format!("/api/organizations/{organization}/users/invalid/confirm"),
            Some("collection-fixture-access"),
            b"{invalid",
            422,
        ),
        (
            valid.clone(),
            Some("collection-fixture-access"),
            br#"{"key":3}"#,
            422,
        ),
        (valid.clone(), Some("collection-fixture-access"), b"{}", 400),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        let response = dispatch(
            State(app.clone()),
            Method::POST,
            path.parse().unwrap(),
            headers,
            Bytes::copy_from_slice(body),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert!(response.status().as_u16() == status);
        if body == b"{}" {
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap())
                    .unwrap();
            assert!(
                value.as_object().unwrap().len() == 9
                    && value["message"] == "Key or UserId is not set, unable to process request"
            );
        }
    }
    assert!(snapshot(&app.store.lock().unwrap()) == before);
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM device_registry WHERE owner='alice'", [])
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let response = dispatch(
        State(app),
        Method::POST,
        valid.parse().unwrap(),
        headers,
        Bytes::from_static(br#"{"key":"opaque"}"#),
    )
    .await
    .unwrap_or_else(IntoResponse::into_response);
    assert!(response.status() == StatusCode::UNAUTHORIZED);
}
