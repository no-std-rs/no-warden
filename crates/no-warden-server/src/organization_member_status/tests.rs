use super::*;
use crate::organization_collections::tests::{create_org, fixture, org};
use crate::organization_confirmations::tests::snapshot;
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

struct Setup {
    store: Store,
    organization: String,
    sibling: String,
    target: String,
}

fn setup(path: &str, role: i32, status: i32) -> Setup {
    let mut store = fixture(path);
    let organization = org(&store);
    let sibling = create_org(&mut store, "alice");
    let target = uuid::Uuid::new_v4().to_string();
    for (id, selected, raw_status) in [
        (target.clone(), &organization, status),
        (uuid::Uuid::new_v4().to_string(), &sibling, 2),
    ] {
        store.db.execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,'bob','opaque-retained-key',?3,?4,0)",
            params![id, selected, role, raw_status],
        ).unwrap();
        store
            .db
            .execute(
                "INSERT INTO organization_member_inviters VALUES(?1,'alice@example.test')",
                [&id],
            )
            .unwrap();
        store.db.execute("INSERT INTO organization_collection_users SELECT id,'bob',1,1,0 FROM organization_collections WHERE organization_id=?1", [selected]).unwrap();
    }
    store
        .db
        .execute(
            "INSERT INTO organization_invitations VALUES('bob@example.test')",
            [],
        )
        .unwrap();
    store.db.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES('preserved-personal','bob','cipher','{\"name\":\"opaque-private-ciphertext\"}',0,'2000','2000')", []).unwrap();
    store.db.execute("INSERT INTO device_registry VALUES('bob','recipient-device','opaque',23,'2000','2000')", []).unwrap();
    store.db.execute("INSERT INTO sessions VALUES('recipient-access','recipient-refresh','bob',9999999999,9999999999)", []).unwrap();
    store
        .db
        .execute(
            "INSERT INTO session_devices VALUES('recipient-access','bob','recipient-device')",
            [],
        )
        .unwrap();
    Setup {
        store,
        organization,
        sibling,
        target,
    }
}

fn only_status(
    store: &Store,
    target: &str,
    mut before: BTreeMap<String, Vec<Vec<SqlValue>>>,
    status: i32,
) {
    let after = snapshot(store);
    let row = before
        .get_mut("organization_memberships")
        .unwrap()
        .iter_mut()
        .find(|row| row[0] == SqlValue::Text(target.into()))
        .unwrap();
    row[5] = SqlValue::Integer(status.into());
    let account = before
        .get_mut("accounts")
        .unwrap()
        .iter_mut()
        .find(|row| row[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let actual = after["accounts"]
        .iter()
        .find(|row| row[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let (
        SqlValue::Text(old),
        SqlValue::Text(new),
        SqlValue::Text(old_rev),
        SqlValue::Text(new_rev),
    ) = (&account[2], &actual[2], &account[4], &actual[4])
    else {
        panic!("Account schema")
    };
    assert!(new_rev > old_rev);
    let mut expected: Value = serde_json::from_str(old).unwrap();
    expected["revisionDate"] = json!(new_rev);
    assert!(expected == serde_json::from_str::<Value>(new).unwrap());
    account[2] = actual[2].clone();
    account[4] = actual[4].clone();
    assert!(
        before == after,
        "Only selected status and recipient revision may change"
    );
}

#[test]
fn status_roundtrips_preserve_private_state_and_restore_original_visibility() {
    for status in [0, 1, 2] {
        let mut data = setup(":memory:", 2, status);
        let initial_collections = serde_json::to_value(
            VaultService::new(&mut data.store)
                .list_user_collections("bob")
                .unwrap()
                .details(),
        )
        .unwrap();
        let initial_profiles = serde_json::to_value(
            VaultService::new(&mut data.store)
                .profile_organizations("bob")
                .unwrap()
                .accepted_and_confirmed(),
        )
        .unwrap();
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .revoke_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, status - 128);
        let collections = serde_json::to_value(
            VaultService::new(&mut data.store)
                .list_user_collections("bob")
                .unwrap()
                .details(),
        )
        .unwrap();
        assert!(collections.as_array().unwrap().len() == 1);
        assert!(collections[0]["organizationId"] == data.sibling);
        let profiles = serde_json::to_value(
            VaultService::new(&mut data.store)
                .profile_organizations("bob")
                .unwrap()
                .accepted_and_confirmed(),
        )
        .unwrap();
        assert!(profiles.as_array().unwrap().len() == 1 && profiles[0]["id"] == data.sibling);
        let before = snapshot(&data.store);
        assert!(
            VaultService::new(&mut data.store)
                .revoke_org_member("alice", &data.organization, &data.target)
                .unwrap_err()
                .message
                == "User is already revoked"
        );
        assert!(snapshot(&data.store) == before);
        VaultService::new(&mut data.store)
            .restore_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, status);
        assert!(
            serde_json::to_value(
                VaultService::new(&mut data.store)
                    .list_user_collections("bob")
                    .unwrap()
                    .details()
            )
            .unwrap()
                == initial_collections
        );
        assert!(
            serde_json::to_value(
                VaultService::new(&mut data.store)
                    .profile_organizations("bob")
                    .unwrap()
                    .accepted_and_confirmed()
            )
            .unwrap()
                == initial_profiles
        );
    }
}

#[test]
fn restoring_ordinary_invited_member_repeatedly_saves_and_advances_revision() {
    let mut data = setup(":memory:", 2, 0);
    for _ in 0..2 {
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .restore_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, 0);
    }
}

#[test]
fn status_hierarchy_allows_admin_targets_but_protects_every_unconfirmed_owner() {
    for role in [1, 2, 3] {
        let mut data = setup(":memory:", role, 2);
        data.store.db.execute("UPDATE organization_memberships SET role=1 WHERE organization_id=?1 AND user_id='alice'", [&data.organization]).unwrap();
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .revoke_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, -126);
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .restore_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, 2);
    }
    for status in [0, 1, 2] {
        let mut data = setup(":memory:", 0, status);
        let before = snapshot(&data.store);
        let result = VaultService::new(&mut data.store).revoke_org_member(
            "alice",
            &data.organization,
            &data.target,
        );
        if status == 2 {
            result.unwrap();
            only_status(&data.store, &data.target, before, -126);
        } else {
            assert!(
                result.unwrap_err().message
                    == "Organization must have at least one confirmed owner"
            );
            assert!(snapshot(&data.store) == before);
        }
        data.store.db.execute("UPDATE organization_memberships SET role=1 WHERE organization_id=?1 AND user_id='alice'", [&data.organization]).unwrap();
        for (raw, restoring, message) in [
            (1, false, "Only owners can revoke other owners"),
            (-127, true, "Only owners can restore other owners"),
        ] {
            data.store
                .db
                .execute(
                    "UPDATE organization_memberships SET status=?1 WHERE id=?2",
                    params![raw, data.target],
                )
                .unwrap();
            let before = snapshot(&data.store);
            let mut service = VaultService::new(&mut data.store);
            let error = if restoring {
                service.restore_org_member("alice", &data.organization, &data.target)
            } else {
                service.revoke_org_member("alice", &data.organization, &data.target)
            }
            .unwrap_err();
            assert!(error.message == message);
            assert!(snapshot(&data.store) == before);
        }
    }
}

#[test]
fn status_actor_authority_and_scoped_targets_fail_without_mutation() {
    for (role, status) in [(2, 2), (3, 2), (0, 1), (0, -126)] {
        let mut data = setup(":memory:", 2, 2);
        data.store.db.execute("UPDATE organization_memberships SET role=?1,status=?2 WHERE organization_id=?3 AND user_id='alice'", params![role, status, data.organization]).unwrap();
        let before = snapshot(&data.store);
        assert!(
            VaultService::new(&mut data.store)
                .revoke_org_member("alice", &data.organization, &data.target)
                .unwrap_err()
                .status_code()
                == 401
        );
        assert!(snapshot(&data.store) == before);
    }
    let mut data = setup(":memory:", 2, 2);
    let before = snapshot(&data.store);
    for restoring in [false, true] {
        let mut service = VaultService::new(&mut data.store);
        let error = if restoring {
            service.restore_org_member("alice", &data.sibling, &data.target)
        } else {
            service.revoke_org_member("alice", &data.sibling, &data.target)
        }
        .unwrap_err();
        assert!(error.message == "User not found in organization" && error.status_code() == 400);
        assert!(snapshot(&data.store) == before);
    }
}

#[test]
fn failed_status_or_revision_write_rolls_back_complete_private_state() {
    for (status, restoring) in [(2, false), (-126, true), (0, true)] {
        for table in ["organization_memberships", "accounts"] {
            let mut data = setup(":memory:", 2, status);
            data.store.db.execute_batch(&format!("CREATE TRIGGER reject_status AFTER UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'private-status-diagnostic'); END;")).unwrap();
            let before = snapshot(&data.store);
            let mut service = VaultService::new(&mut data.store);
            let error = if restoring {
                service.restore_org_member("alice", &data.organization, &data.target)
            } else {
                service.revoke_org_member("alice", &data.organization, &data.target)
            }
            .unwrap_err();
            assert!(error.status_code() == 500 && !error.message.contains("private-"));
            assert!(snapshot(&data.store) == before);
        }
    }
}

async fn call(app: &App, path: &str, authorized: bool, body: &[u8]) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/octet-stream".parse().unwrap());
    if authorized {
        headers.insert(
            "authorization",
            "Bearer collection-fixture-access".parse().unwrap(),
        );
    }
    dispatch(
        State(app.clone()),
        Method::PUT,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

#[tokio::test]
async fn status_http_guards_precede_paths_and_all_three_routes_ignore_body() {
    let data = setup(":memory:", 2, 2);
    let app = App {
        store: Arc::new(Mutex::new(data.store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    for suffix in ["revoke", "restore", "restore/vnext"] {
        for (path, auth, status) in [
            (
                format!(
                    "/api/organizations/{}/users/{}/{suffix}",
                    data.organization, data.target
                ),
                false,
                401,
            ),
            (
                format!("/api/organizations/not-a-uuid/users/not-a-uuid/{suffix}"),
                true,
                401,
            ),
            (
                format!(
                    "/api/organizations/not-a-uuid/users/{}/{suffix}?organizationId={}",
                    data.target, data.organization
                ),
                true,
                422,
            ),
            (
                format!(
                    "/api/organizations/{}/users/not-a-uuid/{suffix}",
                    data.organization
                ),
                true,
                422,
            ),
            (
                format!(
                    "/api/organizations/{}/users/{}/{suffix}",
                    data.sibling, data.target
                ),
                true,
                400,
            ),
        ] {
            let before = snapshot(&app.store.lock().unwrap());
            let response = call(&app, &path, auth, b"{\xff").await;
            assert!(response.status().as_u16() == status);
            if status == 400 {
                let value: Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap())
                        .unwrap();
                assert!(
                    value.as_object().unwrap().len() == 9
                        && value["message"] == "User not found in organization"
                );
            }
            assert!(snapshot(&app.store.lock().unwrap()) == before);
        }
    }
    for suffix in ["revoke", "restore", "revoke", "restore/vnext"] {
        let path = format!(
            "/api/organizations/{}/users/{}/{suffix}",
            data.organization, data.target
        );
        let before = snapshot(&app.store.lock().unwrap());
        let response = call(&app, &path, true, b"{\xff").await;
        assert!(response.status() == StatusCode::OK);
        assert!(
            to_bytes(response.into_body(), 16384)
                .await
                .unwrap()
                .is_empty()
        );
        only_status(
            &app.store.lock().unwrap(),
            &data.target,
            before,
            if suffix == "revoke" { -126 } else { 2 },
        );
    }
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices WHERE owner='alice'", [])
        .unwrap();
    let before = snapshot(&app.store.lock().unwrap());
    assert!(
        call(
            &app,
            &format!(
                "/api/organizations/{}/users/{}/revoke",
                data.organization, data.target
            ),
            true,
            b"ignored"
        )
        .await
        .status()
            == StatusCode::UNAUTHORIZED
    );
    assert!(snapshot(&app.store.lock().unwrap()) == before);
}

#[test]
fn revoked_membership_and_retained_grants_survive_reopen_then_restore() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "no-warden-member-status-reopen-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("vault.db");
    let (organization, target, expected) = {
        let mut data = setup(path.to_str().unwrap(), 2, 2);
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .revoke_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_status(&data.store, &data.target, before, -126);
        (data.organization, data.target, snapshot(&data.store))
    };
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == expected);
    VaultService::new(&mut store)
        .restore_org_member("alice", &organization, &target)
        .unwrap();
    only_status(&store, &target, expected, 2);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}
