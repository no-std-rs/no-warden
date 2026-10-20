use super::*;
use crate::organization_collections::tests::{create_org, fixture, org, snapshot};
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};
use no_warden::{
    VaultService,
    wire::{AvatarUpdateRequest, ProfileUpdateRequest},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

fn document(store: &mut Store, organization: &str, raw_query: Option<&str>) -> Value {
    serde_json::to_value(
        VaultService::new(store)
            .list_org_members("alice", organization, &query(raw_query))
            .unwrap(),
    )
    .unwrap()
}
fn single(store: &mut Store, organization: &str, member: &str, raw_query: Option<&str>) -> Value {
    serde_json::to_value(
        VaultService::new(store)
            .get_org_member("alice", organization, member, &detail_query(raw_query))
            .unwrap(),
    )
    .unwrap()
}
fn add_bob(store: &Store, organization: &str, role: i32, status: i32, access_all: bool) {
    store.db.execute("INSERT INTO organization_memberships VALUES('bob-member',?1,'bob','opaque-org-key',?2,?3,?4)",params![organization,role,status,access_all]).unwrap();
    store.db.execute("UPDATE accounts SET document=json_set(document,'$.name','Member 雪','$.avatarColor','#123456') WHERE id='bob'",[]).unwrap();
}
fn assign(store: &Store, organization: &str) -> String {
    let id: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [organization],
            |row| row.get(0),
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,0)",
            [&id],
        )
        .unwrap();
    id
}

#[test]
fn member_discovery_returns_public_joined_rows_without_persisted_changes() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    let before = snapshot(&store);
    let response = document(&mut store, &organization, None);
    assert!(
        response.as_object().unwrap().len() == 3
            && response["object"] == "list"
            && response["continuationToken"].is_null()
    );
    let data = response["data"].as_array().unwrap();
    assert!(data.len() == 2 && data.iter().all(|row| row.as_object().unwrap().len() == 19));
    assert!(
        data[1]
            == json!({"id":"bob-member","userId":"bob","name":"Member 雪","email":"bob@example.test","externalId":null,"avatarColor":"#123456","groups":[],"collections":[],"status":2,"type":2,"twoFactorEnabled":false,"resetPasswordEnrolled":false,"hasMasterPassword":true,"permissions":null,"ssoBound":false,"claimedByOrganization":false,"usesKeyConnector":false,"accessSecretsManager":false,"object":"organizationUserUserDetails"})
    );
    assert!(snapshot(&store) == before);
}

#[test]
fn single_member_is_the_same_public_projection_without_a_list_wrapper() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 3, -126, false);
    assign(&store, &organization);
    let before = snapshot(&store);
    let list = document(
        &mut store,
        &organization,
        Some("includeCollections=true&includeGroups=true"),
    );
    let detail = single(
        &mut store,
        &organization,
        "bob-member",
        Some("includeCollections=true&includeGroups=true"),
    );
    assert!(
        detail == list["data"][1]
            && detail.as_object().unwrap().len() == 19
            && detail.get("data").is_none()
    );
    assert!(snapshot(&store) == before);
}

#[test]
fn single_member_query_preserves_optional_collection_fallback_and_list_defaults() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    assign(&store, &organization);
    for raw in [
        "includeGroups=true",
        "includeGroups=yes&includeCollections=invalid",
        "includeGroups=ON&includeCollections=true&includeCollections=false",
        "[includeGroups]=true&.includeCollections=+false+",
    ] {
        let detail = single(&mut store, &organization, "bob-member", Some(raw));
        let list = document(&mut store, &organization, Some(raw));
        assert!(
            detail["collections"].as_array().unwrap().len() == 1 && detail["groups"] == json!([])
        );
        assert!(list["data"][1]["collections"] == json!([]));
    }
    for value in ["false", "off", "NO", "False"] {
        let raw = format!("includeGroups=true&includeCollections={value}");
        assert!(
            single(&mut store, &organization, "bob-member", Some(&raw))["collections"] == json!([])
        );
    }
    assert!(single(&mut store, &organization, "bob-member", None)["collections"] == json!([]));
    let detail = single(
        &mut store,
        &organization,
        "bob-member",
        Some("includeCollections=true&includeGroups=true&includeGroups=false"),
    );
    assert!(detail["collections"].as_array().unwrap().len() == 1 && detail["groups"] == json!([]));
}

#[test]
fn single_member_scoped_lookup_rejects_missing_foreign_and_account_ids_identically() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    let other = create_org(&mut store, "bob");
    let foreign: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1",
            [other],
            |row| row.get(0),
        )
        .unwrap();
    assert!(single(&mut store, &organization, "bob-member", None)["userId"] == "bob");
    let before = snapshot(&store);
    for member in ["does-not-exist", "alice", "bob", foreign.as_str()] {
        let error = VaultService::new(&mut store)
            .get_org_member(
                "alice",
                &organization,
                member,
                &OrganizationMemberDetailQuery::default(),
            )
            .unwrap_err();
        assert!(
            error.status_code() == 400
                && error.message == "The specified user isn't a member of the organization"
        );
        assert!(store.organization_members_cache.0.is_empty());
    }
    assert!(single(&mut store, &organization, "bob-member", None)["userId"] == "bob");
    assert!(snapshot(&store) == before);
}

#[test]
fn single_member_requester_must_be_admin_or_owner_even_when_manager_has_full_access() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    for (role, status, access_all, expected) in [
        (0, 2, false, 200),
        (1, 2, false, 200),
        (3, 2, true, 401),
        (3, 2, false, 401),
        (2, 2, true, 401),
        (0, 1, true, 401),
        (1, -126, true, 401),
    ] {
        store.db.execute("UPDATE organization_memberships SET role=?1,status=?2,access_all=?3 WHERE user_id='alice'",params![role,status,access_all]).unwrap();
        let before = snapshot(&store);
        let mut service = VaultService::new(&mut store);
        match service.get_org_member(
            "alice",
            &organization,
            "bob-member",
            &OrganizationMemberDetailQuery::default(),
        ) {
            Ok(response) => assert!(
                expected == 200 && serde_json::to_value(response).unwrap()["userId"] == "bob"
            ),
            Err(error) => assert!(error.status_code() == expected),
        }
        assert!(snapshot(&store) == before);
    }
}

#[test]
fn single_member_refreshes_profile_avatar_flags_without_revisions_or_authority_changes() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    assert!(single(&mut store, &organization, "bob-member", None)["name"] == "Member 雪");
    VaultService::new(&mut store)
        .update_profile(
            "bob",
            &ProfileUpdateRequest {
                name: "Changed 雪"
            },
        )
        .unwrap();
    VaultService::new(&mut store)
        .update_avatar(
            "bob",
            &AvatarUpdateRequest {
                avatar_color: Some("#abcdef"),
            },
        )
        .unwrap();
    store
        .db
        .execute("UPDATE accounts SET password='' WHERE id='bob'", [])
        .unwrap();
    let before = snapshot(&store);
    let response = single(&mut store, &organization, "bob-member", None);
    assert!(
        response["name"] == "Changed 雪"
            && response["avatarColor"] == "#abcdef"
            && response["hasMasterPassword"] == false
    );
    assert!(snapshot(&store) == before);
}

#[tokio::test]
async fn single_member_dispatch_keeps_admin_before_uuid_guards_and_ignores_target_query_fallback() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let other = create_org(&mut store, "bob");
    let member: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1",
            [&organization],
            |row| row.get(0),
        )
        .unwrap();
    let foreign: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1",
            [&other],
            |row| row.get(0),
        )
        .unwrap();
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let valid = format!("/api/organizations/{organization}/users/{member}");
    let before = snapshot(&app.store.lock().unwrap());
    for (path, token, status) in [
        (valid.clone(), None, 401),
        (
            format!("/api/organizations/{other}/users/{foreign}"),
            Some("collection-fixture-access"),
            401,
        ),
        (
            format!("/api/organizations/invalid/users/{member}"),
            Some("collection-fixture-access"),
            401,
        ),
        (
            format!("/api/organizations/invalid/users/invalid?organizationId={organization}"),
            Some("collection-fixture-access"),
            422,
        ),
        (
            format!("/api/organizations/{organization}/users/invalid?memberId={member}"),
            Some("collection-fixture-access"),
            422,
        ),
        (
            format!("/api/organizations/{organization}/users/{foreign}"),
            Some("collection-fixture-access"),
            400,
        ),
        (
            format!("{valid}/?includeGroups=true&includeCollections=invalid"),
            Some("collection-fixture-access"),
            200,
        ),
    ] {
        let response = request(&app, &path, token, b"{invalid ignored body").await;
        assert!(response.status().as_u16() == status);
    }
    assert!(snapshot(&app.store.lock().unwrap()) == before);
    app.store
        .lock()
        .unwrap()
        .db
        .execute(
            "UPDATE organization_memberships SET role=3,access_all=1 WHERE user_id='alice'",
            [],
        )
        .unwrap();
    let path = format!("/api/organizations/{organization}/users/invalid");
    assert!(
        request(&app, &path, Some("collection-fixture-access"), b"")
            .await
            .status()
            == StatusCode::UNAUTHORIZED
    );
    app.store
        .lock()
        .unwrap()
        .db
        .execute(
            "UPDATE organization_memberships SET role=0 WHERE user_id='alice'",
            [],
        )
        .unwrap();
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    assert!(
        request(&app, &valid, Some("collection-fixture-access"), b"")
            .await
            .status()
            == StatusCode::UNAUTHORIZED
    );
}

#[test]
fn member_discovery_keeps_invited_revoked_and_manager_direct_grants_as_metadata() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 3, 2, false);
    let collection = assign(&store, &organization);
    for (status, name_visible, wire_status) in [
        (-128, false, -1),
        (-127, true, -1),
        (-126, true, -1),
        (-1, true, -1),
        (0, false, 0),
        (1, true, 1),
        (2, true, 2),
    ] {
        store
            .db
            .execute(
                "UPDATE organization_memberships SET status=?1 WHERE user_id='bob'",
                [status],
            )
            .unwrap();
        let before = snapshot(&store);
        let response = document(
            &mut store,
            &organization,
            Some("includeCollections=true&includeGroups=true"),
        );
        let row = &response["data"][1];
        assert!(
            row["status"] == wire_status
                && row["type"] == 4
                && row["name"].is_string() == name_visible
                && row["groups"] == json!([])
        );
        assert!(
            row["collections"]
                == json!([{"id":collection,"readOnly":false,"hidePasswords":false,"manage":true}])
        );
        assert!(row["permissions"].is_null() && snapshot(&store) == before);
    }
    store
        .db
        .execute(
            "UPDATE organization_memberships SET access_all=1 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    let response = document(&mut store, &organization, Some("includeCollections=true"));
    let row = &response["data"][1];
    assert!(row["collections"] == json!([]));
    let permissions = row["permissions"].as_object().unwrap();
    assert!(
        permissions.len() == 12
            && permissions
                .values()
                .filter(|value| **value == json!(true))
                .count()
                == 3
    );
    for key in [
        "createNewCollections",
        "editAnyCollection",
        "deleteAnyCollection",
    ] {
        assert!(row["permissions"][key] == true);
    }
    store
        .db
        .execute(
            "UPDATE organization_memberships SET access_all=0 WHERE user_id='bob'",
            [],
        )
        .unwrap();
    for (read_only, hide_passwords, stored_manage, expected) in [
        (true, false, false, false),
        (false, true, false, false),
        (true, true, true, true),
    ] {
        store.db.execute("UPDATE organization_collection_users SET read_only=?1,hide_passwords=?2,manage=?3 WHERE user_id='bob'",params![read_only,hide_passwords,stored_manage]).unwrap();
        let response = document(&mut store, &organization, Some("includeCollections=true"));
        assert!(response["data"][1]["collections"][0]["manage"] == expected);
    }
}

#[test]
fn member_query_option_booleans_exercise_real_direct_grant_projection() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    assign(&store, &organization);
    for name in [
        "includeCollections",
        "includeCollections.x",
        "includeCollections[x]",
        ".includeCollections",
        "[includeCollections]",
        "[includeCollections",
    ] {
        for value in ["", "TRUE", "on", "YeS"] {
            let raw = format!("{name}={value}&includeGroups=true");
            let response = document(&mut store, &organization, Some(&raw));
            assert!(response["data"][1]["collections"].as_array().unwrap().len() == 1);
        }
    }
    for raw in [
        "includeCollections=false",
        "includeCollections=no",
        "includeCollections=off",
        "includeCollections=1",
        "includeCollections=invalid",
        "includeCollections=+true+",
        "IncludeCollections=true",
        "includeCollections=true&includeCollections=true",
        "includeCollections=true&includeCollections[x]=false",
        "includeCollections=invalid&includeCollections=true",
        "includeCollections=true&includeCollections=true&includeCollections=true",
    ] {
        let response = document(&mut store, &organization, Some(raw));
        assert!(response["data"][1]["collections"] == json!([]));
    }
}

#[test]
fn member_discovery_refreshes_public_profile_fields_and_scopes_every_join() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 2, 2, false);
    let collection = assign(&store, &organization);
    let other = create_org(&mut store, "bob");
    let foreign: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&other],
            |row| row.get(0),
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_collection_users VALUES(?1,'bob',0,0,1)",
            [&foreign],
        )
        .unwrap();
    let response = document(&mut store, &organization, Some("includeCollections=true"));
    assert!(
        response["data"].as_array().unwrap().len() == 2
            && response["data"][1]["collections"]
                == json!([{"id":collection,"readOnly":false,"hidePasswords":false,"manage":false}])
    );
    VaultService::new(&mut store)
        .update_profile(
            "alice",
            &ProfileUpdateRequest {
                name: "Fresh name 雪",
            },
        )
        .unwrap();
    VaultService::new(&mut store)
        .update_avatar(
            "alice",
            &AvatarUpdateRequest {
                avatar_color: Some("#654321"),
            },
        )
        .unwrap();
    store
        .db
        .execute("UPDATE accounts SET password='' WHERE id='bob'", [])
        .unwrap();
    let before = snapshot(&store);
    let response = document(&mut store, &organization, None);
    assert!(
        response["data"][0]["name"] == "Fresh name 雪"
            && response["data"][0]["avatarColor"] == "#654321"
            && response["data"][1]["hasMasterPassword"] == false
    );
    assert!(snapshot(&store) == before);
}

#[test]
fn member_request_actor_requires_confirmed_manager_and_direct_full_access() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    add_bob(&store, &organization, 3, 2, false);
    assign(&store, &organization);
    for (role, status, access_all, expected_status) in [
        (3, 2, false, 404),
        (3, 2, true, 200),
        (1, 2, false, 200),
        (0, 2, false, 200),
        (2, 2, true, 401),
        (3, 1, true, 401),
        (0, -126, true, 401),
    ] {
        store.db.execute("UPDATE organization_memberships SET role=?1,status=?2,access_all=?3 WHERE user_id='bob' AND organization_id=?4",params![role,status,access_all,organization]).unwrap();
        let before = snapshot(&store);
        let mut service = VaultService::new(&mut store);
        let result =
            service.list_org_members("bob", &organization, &OrganizationMemberQuery::default());
        match result {
            Ok(response) => {
                assert!(
                    expected_status == 200
                        && serde_json::to_value(response).unwrap()["data"]
                            .as_array()
                            .unwrap()
                            .len()
                            == 2
                );
            }
            Err(error) => {
                assert!(error.status_code() == expected_status);
                if expected_status == 404 {
                    assert!(error.message == "Resource not found.");
                }
            }
        }
        assert!(snapshot(&store) == before);
    }
}

async fn request(
    app: &App,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    dispatch(
        State(app.clone()),
        Method::GET,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    .into_response()
}
#[tokio::test]
async fn member_dispatch_keeps_device_then_membership_then_uuid_guards_and_ignores_body() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let foreign = create_org(&mut store, "bob");
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let before = snapshot(&app.store.lock().unwrap());
    let valid = format!("/api/organizations/{organization}/users");
    for (path, token, status) in [
        (valid.clone(), None, 401),
        (
            format!("/api/organizations/{foreign}/users"),
            Some("collection-fixture-access"),
            401,
        ),
        (
            "/api/organizations/invalid/users".into(),
            Some("collection-fixture-access"),
            401,
        ),
        (
            format!("/api/organizations/invalid/users?organizationId={organization}"),
            Some("collection-fixture-access"),
            422,
        ),
        (
            format!("{valid}?organizationId={foreign}&includeCollections=invalid"),
            Some("collection-fixture-access"),
            200,
        ),
        (
            format!("{valid}/?includeCollections=true&includeCollections=true"),
            Some("collection-fixture-access"),
            200,
        ),
    ] {
        let response = request(&app, &path, token, b"not JSON; ignored GET body").await;
        assert!(response.status().as_u16() == status);
    }
    let response = request(&app, &valid, Some("collection-fixture-access"), b"{invalid").await;
    assert!(response.status() == StatusCode::OK);
    let data: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(data["data"].as_array().unwrap().len() == 1 && data["data"][0]["userId"] == "alice");
    assert!(snapshot(&app.store.lock().unwrap()) == before);
    app.store
        .lock()
        .unwrap()
        .db
        .execute("DELETE FROM session_devices", [])
        .unwrap();
    assert!(
        request(&app, &valid, Some("collection-fixture-access"), b"")
            .await
            .status()
            == StatusCode::UNAUTHORIZED
    );
}
