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

fn member(store: &Store, organization: &str, user: &str, role: i32, status: i32) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,?3,'opaque-retained-key',?4,?5,0)",
            params![id, organization, user, role, status],
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

struct Setup {
    store: Store,
    organization: String,
    sibling: String,
    target: String,
    collection: String,
}
fn setup(path: &str, role: i32, status: i32) -> Setup {
    let mut store = fixture(path);
    let organization = org(&store);
    let sibling = create_org(&mut store, "alice");
    let target = member(&store, &organization, "bob", role, status);
    member(&store, &sibling, "bob", 2, 2);
    let collection = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&organization],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    for id in [&organization, &sibling] {
        store.db.execute("INSERT INTO organization_collection_users SELECT id,'bob',1,1,0 FROM organization_collections WHERE organization_id=?1",[id]).unwrap();
    }
    store
        .db
        .execute(
            "INSERT INTO organization_invitations VALUES('bob@example.test')",
            [],
        )
        .unwrap();
    store.db.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES('preserved-personal','bob','cipher','{\"name\":\"opaque-private-ciphertext\"}',0,'2000','2000')",[]).unwrap();
    store.db.execute("INSERT INTO device_registry VALUES('bob','recipient-device','opaque',23,'2000','2000')",[]).unwrap();
    store.db.execute("INSERT INTO sessions VALUES('recipient-access','recipient-refresh','bob',9999999999,9999999999)",[]).unwrap();
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
        collection,
    }
}

fn only_removal(
    data: &Setup,
    mut before: BTreeMap<String, Vec<Vec<SqlValue>>>,
    marker_removed: bool,
) {
    let after = snapshot(&data.store);
    before
        .get_mut("organization_memberships")
        .unwrap()
        .retain(|row| row[0] != SqlValue::Text(data.target.clone()));
    before
        .get_mut("organization_member_inviters")
        .unwrap()
        .retain(|row| row[0] != SqlValue::Text(data.target.clone()));
    before
        .get_mut("organization_collection_users")
        .unwrap()
        .retain(|row| {
            !(row[0] == SqlValue::Text(data.collection.clone())
                && row[1] == SqlValue::Text("bob".into()))
        });
    if marker_removed {
        before
            .get_mut("organization_invitations")
            .unwrap()
            .retain(|row| row[0] != SqlValue::Text("bob@example.test".into()));
    }
    let old = before
        .get_mut("accounts")
        .unwrap()
        .iter_mut()
        .find(|row| row[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let new = after["accounts"]
        .iter()
        .find(|row| row[0] == SqlValue::Text("bob".into()))
        .unwrap();
    let (
        SqlValue::Text(old_doc),
        SqlValue::Text(new_doc),
        SqlValue::Text(old_rev),
        SqlValue::Text(new_rev),
    ) = (&old[2], &new[2], &old[4], &new[4])
    else {
        panic!("Account fixture schema")
    };
    assert!(new_rev > old_rev);
    let mut expected: Value = serde_json::from_str(old_doc).unwrap();
    let actual: Value = serde_json::from_str(new_doc).unwrap();
    expected["revisionDate"] = json!(new_rev);
    assert!(expected == actual);
    old[2] = new[2].clone();
    old[4] = new[4].clone();
    assert!(
        before == after,
        "Only selected membership, scoped grants, inviter, invitation marker and recipient revision may change"
    );
}

#[test]
fn removal_cleans_only_selected_organization_for_all_member_states() {
    for status in [-128, -1, 0, 1, 2] {
        let mut data = setup(":memory:", 2, status);
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_removal(&data, before, true);
        let before = snapshot(&data.store);
        let error = VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap_err();
        assert!(
            error.message == "User to delete isn't member of the organization"
                && error.status_code() == 400
        );
        assert!(snapshot(&data.store) == before);
    }
}

#[test]
fn removal_keeps_global_invitation_only_for_another_raw_invited_membership() {
    for other_status in [-128, -1, 0, 1, 2] {
        let mut data = setup(":memory:", 2, 0);
        data.store.db.execute("UPDATE organization_memberships SET status=?1 WHERE organization_id=?2 AND user_id='bob'",params![other_status,data.sibling]).unwrap();
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_removal(&data, before, other_status != 0);
    }
}

#[test]
fn removal_owner_protection_counts_only_confirmed_owners_and_admin_cannot_remove_manager() {
    for role in [0, 1, 3] {
        let mut data = setup(":memory:", role, 1);
        data.store.db.execute("UPDATE organization_memberships SET role=1 WHERE organization_id=?1 AND user_id='alice'",[&data.organization]).unwrap();
        let before = snapshot(&data.store);
        let error = VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap_err();
        assert!(error.message == "Only Owners can delete Admins or Owners");
        assert!(snapshot(&data.store) == before);
    }
    for second_owner_status in [-128, -1, 0, 1, 2] {
        let mut data = setup(":memory:", 0, second_owner_status);
        let self_id:String=data.store.db.query_row("SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='alice'",[&data.organization],|row|row.get(0)).unwrap();
        let before = snapshot(&data.store);
        let result = VaultService::new(&mut data.store).remove_org_member(
            "alice",
            &data.organization,
            &self_id,
        );
        if second_owner_status == 2 {
            result.unwrap();
            assert!(
                !data
                    .store
                    .db
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE id=?1)",
                        [self_id],
                        |row| row.get::<_, bool>(0)
                    )
                    .unwrap()
            );
            assert!(
                VaultService::new(&mut data.store)
                    .authorize_org_member_admin("alice", &data.organization)
                    .is_err()
            );
            assert!(
                VaultService::new(&mut data.store)
                    .authorize_org_member_admin("bob", &data.organization)
                    .is_ok()
            );
        } else {
            assert!(result.unwrap_err().message == "Can't delete the last owner");
            assert!(snapshot(&data.store) == before);
        }
    }
}

#[test]
fn removal_rolls_back_grants_marker_inviter_membership_and_revision_on_provider_failure() {
    for trigger in [
        "CREATE TRIGGER reject_remove BEFORE DELETE ON organization_memberships BEGIN SELECT RAISE(ABORT,'private-membership-diagnostic'); END;",
        "CREATE TRIGGER reject_marker BEFORE DELETE ON organization_invitations BEGIN SELECT RAISE(ABORT,'private-marker-diagnostic'); END;",
        "CREATE TRIGGER reject_revision BEFORE UPDATE ON accounts WHEN NEW.id='bob' BEGIN SELECT RAISE(ABORT,'private-account-diagnostic'); END;",
    ] {
        let mut data = setup(":memory:", 2, 2);
        data.store.db.execute_batch(trigger).unwrap();
        let before = snapshot(&data.store);
        let error = VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap_err();
        assert!(error.status_code() == 500 && !error.message.contains("private-"));
        assert!(snapshot(&data.store) == before);
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
        Method::DELETE,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

#[tokio::test]
async fn removal_http_authority_precedes_paths_and_returns_exact_error_family() {
    let data = setup(":memory:", 2, 2);
    let own_id: String = data
        .store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='alice'",
            [&data.organization],
            |row| row.get(0),
        )
        .unwrap();
    let base = format!("/api/organizations/{}/users", data.organization);
    let app = App {
        store: Arc::new(Mutex::new(data.store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    for (path, auth, status) in [
        (format!("{base}/{}", data.target), false, 401),
        (
            "/api/organizations/not-a-uuid/users/not-a-uuid".into(),
            true,
            401,
        ),
        (
            format!(
                "/api/organizations/not-a-uuid/users/{}?organizationId={}",
                data.target, data.organization
            ),
            true,
            422,
        ),
        (format!("{base}/confirm"), true, 422),
        (format!("{base}/invite"), true, 422),
        (format!("{base}/mini-details"), true, 422),
        (
            format!("{base}/not-a-uuid?memberId={}", data.target),
            true,
            422,
        ),
        (format!("{base}/{}", data.target.to_uppercase()), true, 400),
        (
            format!("/api/organizations/{}/users/{}", data.sibling, data.target),
            true,
            400,
        ),
    ] {
        let before = snapshot(&app.store.lock().unwrap());
        let response = call(&app, &path, auth, b"{\xff").await;
        assert!(response.status().as_u16() == status);
        assert!(snapshot(&app.store.lock().unwrap()) == before);
    }
    let response = call(&app, &format!("{base}/{own_id}"), true, b"ignored").await;
    assert!(response.status() == StatusCode::BAD_REQUEST);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert!(
        value.as_object().unwrap().len() == 9 && value["message"] == "Can't delete the last owner"
    );
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices WHERE owner='alice'", [])
        .unwrap();
    let before = snapshot(&app.store.lock().unwrap());
    assert!(
        call(&app, &format!("{base}/{}", data.target), true, b"ignored")
            .await
            .status()
            == StatusCode::UNAUTHORIZED
    );
    assert!(snapshot(&app.store.lock().unwrap()) == before);
}

#[tokio::test]
async fn removal_http_ignores_body_and_preserves_personal_authority() {
    let data = setup(":memory:", 2, 2);
    let path = format!(
        "/api/organizations/{}/users/{}?organizationId={}",
        data.organization, data.target, data.sibling
    );
    let before = snapshot(&data.store);
    let app = App {
        store: Arc::new(Mutex::new(data.store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let response = call(&app, &path, true, b"{\xff").await;
    assert!(response.status() == StatusCode::OK);
    assert!(
        to_bytes(response.into_body(), 16384)
            .await
            .unwrap()
            .is_empty()
    );
    let data = Setup {
        store: Arc::try_unwrap(app.store)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap(),
        organization: data.organization,
        sibling: data.sibling,
        target: data.target,
        collection: data.collection,
    };
    only_removal(&data, before, true);
}

#[test]
fn removal_cleanup_survives_reopening_without_deleting_the_account() {
    use std::os::unix::fs::DirBuilderExt;
    let directory = std::env::temp_dir().join(format!(
        "no-warden-member-removal-reopen-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("vault.db");
    let expected = {
        let mut data = setup(path.to_str().unwrap(), 2, 0);
        data.store
            .db
            .execute("UPDATE accounts SET password='' WHERE id='bob'", [])
            .unwrap();
        let before = snapshot(&data.store);
        VaultService::new(&mut data.store)
            .remove_org_member("alice", &data.organization, &data.target)
            .unwrap();
        only_removal(&data, before, true);
        snapshot(&data.store)
    };
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(snapshot(&store) == expected);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}
