use super::*;
use crate::organization_collections::tests::{create_org, fixture, org};
use crate::organization_confirmations::tests::snapshot;
use crate::{App, Store, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};
use no_warden::{ApiError, VaultService};
use rusqlite::{params, types::Value as SqlValue};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn member(store: &Store, organization: &str, user: &str) -> String {
    let doc = json!({"id":user,"email":format!("{user}@example.test"),"key":"opaque-account-key","keys":{"publicKey":"opaque-public","encryptedPrivateKey":"opaque-private"},"revisionDate":"2000-01-01T00:00:00.000Z","future":{"retained":true}});
    store.db.execute("INSERT OR IGNORE INTO accounts VALUES(?1,?2,?3,'opaque-verifier','2000-01-01T00:00:00.000Z')",params![user,format!("{user}@example.test"),doc.to_string()]).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,?3,'old-wrapped-key',2,1,0)",
            params![id, organization, user],
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_member_inviters VALUES(?1,'alice@example.test')",
            [&id],
        )
        .unwrap();
    let collection: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [organization],
            |r| r.get(0),
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,?2,1,1,1)",
            params![collection, user],
        )
        .unwrap();
    id
}
fn input(value: Value) -> Input {
    Input::parse(&serde_json::to_vec(&value).unwrap())
        .unwrap_or_else(|_| panic!("Bulk confirmation fixture schema"))
}
fn run(store: &mut Store, organization: &str, input: &Input) -> Result<Value, ApiError> {
    let mut scratch = vec![None; input.len()];
    let result = VaultService::new(store)
        .bulk_confirm_org_members("alice", organization, input, &mut scratch)
        .map_err(|e| e.cause())?;
    Ok(serde_json::to_value(result).unwrap())
}
fn only_changes(
    store: &Store,
    mut before: BTreeMap<String, Vec<Vec<SqlValue>>>,
    changes: &[(&str, &str, &str)],
) {
    let after = snapshot(store);
    for &(user, member, key) in changes {
        let row = before
            .get_mut("organization_memberships")
            .unwrap()
            .iter_mut()
            .find(|r| r[0] == SqlValue::Text(member.into()))
            .unwrap();
        row[3] = SqlValue::Text(key.into());
        row[5] = SqlValue::Integer(2);
        let account = before
            .get_mut("accounts")
            .unwrap()
            .iter_mut()
            .find(|r| r[0] == SqlValue::Text(user.into()))
            .unwrap();
        let actual = after["accounts"]
            .iter()
            .find(|r| r[0] == SqlValue::Text(user.into()))
            .unwrap();
        assert!(account[4] != actual[4]);
        let (SqlValue::Text(raw), SqlValue::Text(new_raw), SqlValue::Text(revision)) =
            (&account[2], &actual[2], &actual[4])
        else {
            panic!("Bulk account document type")
        };
        let mut expected: Value = serde_json::from_str(raw).unwrap();
        expected["revisionDate"] = json!(revision);
        assert!(serde_json::from_str::<Value>(new_raw).unwrap() == expected);
        account[2] = actual[2].clone();
        account[4] = actual[4].clone();
    }
    assert!(after == before);
}

#[test]
fn bulk_decoder_validates_entire_nested_schema_and_retains_raw_positional_ids() {
    for body in [
        br#"{}"#.as_slice(),
        br#"{"keys":null}"#,
        br#"{"keys":[]}"#,
        br#"[null]"#,
        br#"[[]]"#,
        br#"{"Keys":[{"id":3}]}"#,
    ] {
        assert!(
            Input::parse(body)
                .unwrap_or_else(|_| panic!("Optional bulk input"))
                .len()
                == 0
        );
    }
    let data = Input::parse(br#"[[["RAW\u0000id","opaque\u0000key"],[null,null]]]"#)
        .unwrap_or_else(|_| panic!("Positional bulk input"));
    assert!(
        data.len() == 2
            && data.get(0).unwrap().id == Some("RAW\0id")
            && data
                .get(0)
                .unwrap()
                .key
                .is_some_and(|k| k.expose_secret() == "opaque\0key")
            && data.get(1).unwrap().id.is_none()
    );
    for body in [
        br#"[]"#.as_slice(),
        br#"{"keys":false}"#,
        br#"{"keys":[{"id":"first","key":"opaque"},{"id":3}]}"#,
        br#"{"keys":[[]]}"#,
        br#"{"keys":null,"keys":[]}"#,
    ] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for body in [b"{".as_slice(), br#"[[],false]"#] {
        assert!(
            Input::parse(body)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
}
#[test]
fn bulk_empty_results_have_exact_list_shape_and_never_mutate_private_state() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let before = snapshot(&store);
    for body in [json!({}), json!({"keys":null}), json!({"keys":[]})] {
        assert!(
            run(&mut store, &organization, &input(body)).unwrap()
                == json!({"data":[],"object":"list","continuationToken":null})
        );
        assert!(snapshot(&store) == before);
    }
}
#[test]
fn bulk_preserves_order_duplicates_errors_and_only_successful_member_changes() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let foreign = create_org(&mut store, "alice");
    let bob = member(&store, &organization, "bob");
    let carol = member(&store, &organization, "carol");
    let foreign_member = member(&store, &foreign, "dave");
    let missing = uuid::Uuid::new_v4().to_string();
    let before = snapshot(&store);
    let ids = [
        bob.as_str(),
        bob.as_str(),
        foreign_member.as_str(),
        "",
        carol.as_str(),
        carol.as_str(),
        missing.as_str(),
    ];
    let data = input(
        json!({"keys":[{"id":bob,"key":"first-opaque-key"},{"id":bob,"key":"must-not-overwrite"},{"id":foreign_member,"key":"opaque"},{"id":"","key":"opaque"},{"id":carol,"key":null},{"id":carol,"key":"later\u{0}wrapped-key"},{"id":missing,"key":"opaque"}]}),
    );
    let value = run(&mut store, &organization, &data).unwrap();
    assert!(
        value.as_object().unwrap().len() == 3
            && value["object"] == "list"
            && value["continuationToken"].is_null()
    );
    let errors = [
        "",
        "User in invalid state",
        "The specified user isn't a member of the organization",
        "Key or UserId is not set, unable to process request",
        "Key or UserId is not set, unable to process request",
        "",
        "The specified user isn't a member of the organization",
    ];
    let rows = value["data"].as_array().unwrap();
    assert!(rows.len() == ids.len());
    for ((row, id), error) in rows.iter().zip(ids).zip(errors) {
        assert!(
            row == &json!({"id":id,"object":"OrganizationBulkConfirmResponseModel","error":error})
        );
    }
    only_changes(
        &store,
        before,
        &[
            ("bob", &bob, "first-opaque-key"),
            ("carol", &carol, "later\0wrapped-key"),
        ],
    );
}
#[test]
fn bulk_missing_member_id_aborts_after_the_committed_prefix_without_processing_suffix() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let bob = member(&store, &organization, "bob");
    let carol = member(&store, &organization, "carol");
    let before = snapshot(&store);
    let data = input(
        json!({"keys":[{"id":bob,"key":"prefix-key"},{"key":"missing-id"},{"id":carol,"key":"must-not-commit"}]}),
    );
    let error = run(&mut store, &organization, &data).err().unwrap();
    assert!(error.status_code() == 400 && error.message == "Member id is required");
    only_changes(&store, before, &[("bob", &bob, "prefix-key")]);
}
#[test]
fn bulk_backend_failure_rolls_back_that_item_and_continues_without_private_diagnostics() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let bob = member(&store, &organization, "bob");
    let carol = member(&store, &organization, "carol");
    store.db.execute_batch("CREATE TRIGGER reject_bulk_item AFTER UPDATE ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'private injected backend diagnostic'); END;").unwrap();
    let before = snapshot(&store);
    let value = run(
        &mut store,
        &organization,
        &input(json!({"keys":[{"id":bob,"key":"rolled-back"},{"id":carol,"key":"committed"}]})),
    )
    .unwrap();
    let error = value["data"][0]["error"].as_str().unwrap();
    assert!(
        !error.is_empty()
            && !error.contains("private")
            && !error.contains("injected")
            && !error.contains("rolled-back")
            && value["data"][1]["error"] == ""
    );
    only_changes(&store, before, &[("carol", &carol, "committed")]);
}
#[tokio::test]
async fn bulk_dispatch_authentication_uuid_and_whole_json_guards_precede_all_writes() {
    let store = fixture(":memory:");
    let organization = org(&store);
    let bob = member(&store, &organization, "bob");
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let path = format!("/api/organizations/{organization}/users/confirm");
    let before = snapshot(&app.store.lock().unwrap());
    let bad_batch = serde_json::to_vec(
        &json!({"keys":[{"id":bob,"key":"must-not-commit"},{"id":3,"key":"wrong-type"}]}),
    )
    .unwrap();
    for (uri, token, body, status) in [
        (path.clone(), None, b"{invalid".as_slice(), 401),
        (
            "/api/organizations/invalid/users/confirm".to_owned(),
            Some("collection-fixture-access"),
            b"{invalid",
            401,
        ),
        (
            format!("/api/organizations/invalid/users/confirm?organizationId={organization}"),
            Some("collection-fixture-access"),
            b"{invalid",
            422,
        ),
        (
            path.clone(),
            Some("collection-fixture-access"),
            bad_batch.as_slice(),
            422,
        ),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        let response = dispatch(
            State(app.clone()),
            Method::POST,
            uri.parse().unwrap(),
            headers,
            Bytes::copy_from_slice(body),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert!(response.status().as_u16() == status);
        assert!(snapshot(&app.store.lock().unwrap()) == before);
    }
    let body = serde_json::to_vec(&json!({"keys":[{"id":bob,"key":"prefix"},{}]})).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer collection-fixture-access".parse().unwrap(),
    );
    let response = dispatch(
        State(app.clone()),
        Method::POST,
        path.parse().unwrap(),
        headers,
        Bytes::from(body),
    )
    .await
    .unwrap_or_else(IntoResponse::into_response);
    assert!(response.status() == StatusCode::BAD_REQUEST);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert!(
        value.as_object().unwrap().len() == 9
            && value["message"] == "Member id is required"
            && value.get("data").is_none()
    );
    only_changes(
        &app.store.lock().unwrap(),
        before,
        &[("bob", &bob, "prefix")],
    );
}

#[test]
fn bulk_committed_prefix_survives_reopening_after_missing_id_aborts_the_batch() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "no-warden-bulk-confirmation-reopen-{}",
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
        let bob = member(&store, &organization, "bob");
        let carol = member(&store, &organization, "carol");
        let before = snapshot(&store);
        let error=run(&mut store,&organization,&input(json!({"keys":[{"id":bob,"key":"durable-prefix"},{"id":null,"key":"missing"},{"id":carol,"key":"skipped"}]}))).err().unwrap();
        assert!(error.message == "Member id is required");
        only_changes(&store, before, &[("bob", &bob, "durable-prefix")]);
        snapshot(&store)
    };
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == expected);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}
