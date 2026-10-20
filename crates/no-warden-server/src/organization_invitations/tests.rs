use super::*;
use crate::organization_collections::tests::{create_org, fixture, org};
use crate::{App, dispatch};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Method},
};
use rusqlite::types::Value as SqlValue;
use std::sync::{Arc, Mutex};

fn input(emails: &[&str], role: Value) -> Input {
    Input::parse(
        &serde_json::to_vec(&json!({"emails":emails,"groups":[],"type":role,"collections":[]}))
            .unwrap(),
    )
    .unwrap_or_else(|_| panic!("Invitation fixture schema failed"))
}
fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut output = Vec::new();
    for table in [
        "accounts",
        "items",
        "attachments",
        "sessions",
        "session_devices",
        "device_registry",
        "organizations",
        "organization_memberships",
        "organization_collections",
        "organization_collection_users",
        "organization_collection_ciphers",
        "organization_invitations",
        "organization_member_inviters",
        "registration_metadata",
        "account_security",
    ] {
        let mut statement = store
            .db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let count = statement.column_count();
        output.extend(
            statement
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    output
}
#[test]
fn invitation_decoder_preserves_distinct_tuple_order_required_flags_and_strict_permissions() {
    let positional=Input::parse(br#"[["mixed@example.test"],[],4,[["raw-id",true,false,true]],{"createNewCollections":true,"editAnyCollection":"true","deleteAnyCollection":1}]"#).unwrap_or_else(|_|panic!("Positional invitation failed"));
    let c = positional.collection(0).unwrap();
    assert!(c.id == "raw-id" && c.read_only && !c.hide_passwords && c.manage);
    let permissions = positional.permissions();
    assert!(
        permissions.create_new_collections
            && !permissions.edit_any_collection
            && !permissions.delete_any_collection
    );
    let duplicate=Input::parse(br#"{"emails":[],"groups":[],"type":2,"permissions":{"createNewCollections":true,"createNewCollections":false}}"#).unwrap_or_else(|_|panic!("Permission map failed"));
    assert!(!duplicate.permissions().create_new_collections);
    for body in [br#"{"emails":[],"type":2}"#.as_slice(),br#"{"emails":[],"groups":[],"type":2,"collections":[{"id":"raw","readOnly":false,"hidePasswords":false}]}"#,br#"{"emails":[],"groups":[],"type":2.5}"#,br#"{"emails":[],"groups":[],"type":2,"permissions":null}"#,br#"{"emails":[],"groups":[1],"type":2}"#,br#"{"emails":[],"groups":[],"type":2,"type":2}"#] {
        let Err(error)=Input::parse(body) else {panic!("Invalid invitation schema accepted")};assert!(error.0==StatusCode::UNPROCESSABLE_ENTITY);
    }
    let many = json!({"emails":vec!["same@example.test";3000],"groups":[],"type":2});
    assert!(
        Input::parse(&serde_json::to_vec(&many).unwrap())
            .unwrap_or_else(|_| panic!("Uncapped view failed"))
            .emails_len()
            == 3000
    );
}

#[test]
fn invitation_registered_user_is_accepted_with_exact_last_grants_and_preserved_credentials() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let collection: String = store
        .db
        .query_row(
            "SELECT id FROM organization_collections WHERE organization_id=?1",
            [&organization],
            |r| r.get(0),
        )
        .unwrap();
    let alice = store.account("id", "alice").unwrap();
    let before = store.account("id", "bob").unwrap().unwrap();
    let document = json!({"emails":["BOB@EXAMPLE.TEST"],"groups":[],"type":2,"collections":[{"id":collection,"readOnly":false,"hidePasswords":false,"manage":false},{"id":collection,"readOnly":true,"hidePasswords":true,"manage":true}],"invitedByEmail":"forged@example.test"});
    let input = Input::parse(&serde_json::to_vec(&document).unwrap())
        .unwrap_or_else(|_| panic!("Invitation input"));
    assert!(
        VaultService::new(&mut store)
            .invite_org_members("alice", &organization, &input)
            .unwrap()
            == 1
    );
    let row:(String,i32,i32,bool,String)=store.db.query_row("SELECT key,role,status,access_all,id FROM organization_memberships WHERE organization_id=?1 AND user_id='bob'",[&organization],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert!(row.0.is_empty() && row.1 == 2 && row.2 == 1 && !row.3);
    let flags:(bool,bool,bool)=store.db.query_row("SELECT read_only,hide_passwords,manage FROM organization_collection_users WHERE collection_id=?1 AND user_id='bob'",[&collection],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert!(flags == (true, true, true));
    let inviter: String = store
        .db
        .query_row(
            "SELECT email FROM organization_member_inviters WHERE membership_id=?1",
            [row.4],
            |r| r.get(0),
        )
        .unwrap();
    assert!(inviter == "alice@example.test");
    let mut after = store.account("id", "bob").unwrap().unwrap();
    assert!(after["revisionDate"] != before["revisionDate"]);
    after["revisionDate"] = before["revisionDate"].clone();
    assert!(
        after == before
            && store.account("id", "alice").unwrap() == alice
            && !registration::invitation_exists(&store.db, "bob@example.test").unwrap()
    );
    let verifier: String = store
        .db
        .query_row("SELECT password FROM accounts WHERE id='bob'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(verifier == "opaque-verifier");
}

#[test]
fn invitation_custom_raw_four_controls_access_all_and_full_access_skips_valid_direct_grants() {
    for (role, expected_role, all) in [
        (json!(0), 0, true),
        (json!("Admin"), 1, true),
        (json!("User"), 2, false),
        (json!(3), 3, false),
        (json!("Custom"), 3, false),
        (json!("4"), 3, true),
        (json!(4), 3, true),
    ] {
        let mut store = fixture(":memory:");
        let organization = org(&store);
        let collection: String = store
            .db
            .query_row(
                "SELECT id FROM organization_collections WHERE organization_id=?1",
                [&organization],
                |r| r.get(0),
            )
            .unwrap();
        let document = json!({"emails":["bob@example.test"],"groups":[],"type":role,"collections":[{"id":collection,"readOnly":false,"hidePasswords":false,"manage":true}],"permissions":{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}});
        let input = Input::parse(&serde_json::to_vec(&document).unwrap())
            .unwrap_or_else(|_| panic!("Role fixture"));
        VaultService::new(&mut store)
            .invite_org_members("alice", &organization, &input)
            .unwrap();
        let actual: (i32, bool) = store
            .db
            .query_row(
                "SELECT role,access_all FROM organization_memberships WHERE user_id='bob'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(actual == (expected_role, all));
        let grants: i64 = store
            .db
            .query_row(
                "SELECT COUNT(*) FROM organization_collection_users WHERE user_id='bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(grants == i64::from(!all));
    }
}

#[test]
fn invitation_new_user_is_canonical_passwordless_and_repeat_org_invitation_preserves_identity() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let other = create_org(&mut store, "alice");
    let input = input(&["MiXeD@EXAMPLE.TEST"], json!(2));
    VaultService::new(&mut store)
        .invite_org_members("alice", &organization, &input)
        .unwrap();
    let first = store
        .account("email", "mixed@example.test")
        .unwrap()
        .unwrap();
    VaultService::new(&mut store)
        .invite_org_members("alice", &other, &input)
        .unwrap();
    let after = store
        .account("email", "mixed@example.test")
        .unwrap()
        .unwrap();
    assert!(
        first["id"] == after["id"]
            && first["creationDate"] == after["creationDate"]
            && after["name"] == "mixed@example.test"
            && after["key"] == ""
            && after["keys"].is_null()
            && after["kdfIterations"] == 600000
    );
    let id = after["id"].as_str().unwrap();
    let state:(bool,i64)=store.db.query_row("SELECT password='',(SELECT COUNT(*) FROM organization_memberships WHERE user_id=accounts.id AND status=0 AND key='') FROM accounts WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(
        state == (true, 2)
            && registration::invitation_exists(&store.db, "MIXED@EXAMPLE.TEST").unwrap()
    );
}

#[test]
fn invitation_validates_all_references_before_role_or_emails_and_empty_batch_never_mutates() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let before = snapshot(&store);
    for (collections, groups, message) in [
        (
            json!([{"id":"missing","readOnly":false,"hidePasswords":false,"manage":false}]),
            json!(["missing"]),
            "Invalid collection",
        ),
        (json!([]), json!(["missing"]), "Invalid group"),
        (json!([]), json!([]), "Invalid type"),
    ] {
        let body = json!({"emails":[],"groups":groups,"type":"invalid","collections":collections});
        let input = Input::parse(&serde_json::to_vec(&body).unwrap())
            .unwrap_or_else(|_| panic!("Prevalidation fixture"));
        let error = VaultService::new(&mut store)
            .invite_org_members("alice", &organization, &input)
            .unwrap_err();
        assert!(
            error.cause().message == message
                && error.completed() == 0
                && snapshot(&store) == before
        );
    }
    let changes = store.db.total_changes();
    assert!(
        VaultService::new(&mut store)
            .invite_org_members("alice", &organization, &input(&[], json!(2)))
            .unwrap()
            == 0
            && store.db.total_changes() == changes
    );
}

#[test]
fn invitation_later_duplicate_and_invalid_email_preserve_the_committed_prefix_only() {
    for (second, kind) in [
        (
            "prefix@example.test",
            OrganizationInviteErrorKind::AlreadyMember,
        ),
        ("not-an-email", OrganizationInviteErrorKind::Api),
        ("@example.test", OrganizationInviteErrorKind::Api),
        ("user@", OrganizationInviteErrorKind::Api),
        ("", OrganizationInviteErrorKind::Api),
        (
            "bad space@example.test",
            OrganizationInviteErrorKind::InvalidInvitationEmail,
        ),
    ] {
        let mut store = fixture(":memory:");
        let organization = org(&store);
        let input = input(
            &["prefix@example.test", second, "unprocessed@example.test"],
            json!(2),
        );
        let error = VaultService::new(&mut store)
            .invite_org_members("alice", &organization, &input)
            .unwrap_err();
        assert!(error.index() == Some(1) && error.completed() == 1 && error.kind() == kind);
        if kind == OrganizationInviteErrorKind::Api {
            assert!(error.cause().message == "Email domain not eligible for invitations");
        }
        assert!(
            store
                .account("email", "prefix@example.test")
                .unwrap()
                .is_some()
                && store
                    .account("email", "unprocessed@example.test")
                    .unwrap()
                    .is_none()
        );
        let response = error_response(error);
        assert!(response.status() == StatusCode::BAD_REQUEST);
        assert!(
            registration::invitation_exists(&store.db, "prefix@example.test").unwrap()
                && (kind == OrganizationInviteErrorKind::AlreadyMember
                    || !registration::invitation_exists(&store.db, second).unwrap())
        );
    }
}

#[test]
fn invitation_per_email_write_and_deferred_commit_failures_roll_back_without_consuming_input() {
    for phase in 0..8 {
        let mut store = fixture(":memory:");
        let organization = org(&store);
        let collection: String = store
            .db
            .query_row(
                "SELECT id FROM organization_collections WHERE organization_id=?1",
                [&organization],
                |r| r.get(0),
            )
            .unwrap();
        let body = json!({"emails":["pending@example.test"],"groups":[],"type":2,"collections":[{"id":collection,"readOnly":false,"hidePasswords":false,"manage":true}]});
        let input = Input::parse(&serde_json::to_vec(&body).unwrap())
            .unwrap_or_else(|_| panic!("Rollback fixture"));
        let before = snapshot(&store);
        store.db.execute_batch(match phase {
            0=>"CREATE TRIGGER reject_invitation BEFORE INSERT ON organization_invitations BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            1=>"CREATE TRIGGER reject_invitation BEFORE INSERT ON accounts BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            2=>"CREATE TRIGGER reject_invitation AFTER INSERT ON accounts BEGIN SELECT RAISE(FAIL,'fixture'); END;",
            3=>"CREATE TRIGGER reject_invitation BEFORE INSERT ON organization_memberships BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            4=>"CREATE TRIGGER reject_invitation BEFORE INSERT ON organization_member_inviters BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            5=>"CREATE TRIGGER reject_invitation BEFORE INSERT ON organization_collection_users BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            6=>"CREATE TRIGGER reject_invitation BEFORE UPDATE OF revision ON accounts BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            _=>"CREATE TABLE failed_invitation(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_invitation AFTER INSERT ON organization_memberships BEGIN INSERT INTO failed_invitation VALUES('missing-owner'); END;",
        }).unwrap();
        assert!(
            VaultService::new(&mut store)
                .invite_org_members("alice", &organization, &input)
                .is_err()
                && snapshot(&store) == before,
            "Failed invitation escaped its per-email savepoint"
        );
        store
            .db
            .execute_batch("DROP TRIGGER reject_invitation")
            .unwrap();
        assert!(
            VaultService::new(&mut store)
                .invite_org_members("alice", &organization, &input)
                .unwrap()
                == 1
        );
    }
}

async fn request(app: &App, path: &str, token: Option<&str>, body: &[u8]) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    dispatch(
        State(app.clone()),
        Method::POST,
        path.parse().unwrap(),
        headers,
        Bytes::copy_from_slice(body),
    )
    .await
    .into_response()
}
#[tokio::test]
async fn invitation_dispatch_orders_device_admin_uuid_and_json_guards_before_writes() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let foreign = create_org(&mut store, "bob");
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let valid = format!("/api/organizations/{organization}/users/invite");
    let before = snapshot(&app.store.lock().unwrap());
    for (path, token, body, status) in [
        (valid.clone(), None, b"{invalid".as_slice(), 401),
        (
            format!("/api/organizations/{foreign}/users/invite"),
            Some("collection-fixture-access"),
            b"{invalid".as_slice(),
            401,
        ),
        (
            "/api/organizations/invalid/users/invite".into(),
            Some("collection-fixture-access"),
            b"{invalid".as_slice(),
            401,
        ),
        (
            format!("/api/organizations/invalid/users/invite?organizationId={organization}"),
            Some("collection-fixture-access"),
            b"{invalid".as_slice(),
            422,
        ),
        (
            valid.clone(),
            Some("collection-fixture-access"),
            b"{invalid".as_slice(),
            400,
        ),
        (
            valid.clone(),
            Some("collection-fixture-access"),
            b"{}".as_slice(),
            422,
        ),
    ] {
        assert!(request(&app, &path, token, body).await.status().as_u16() == status);
    }
    assert!(snapshot(&app.store.lock().unwrap()) == before);
    let response = request(
        &app,
        &valid,
        Some("collection-fixture-access"),
        br#"{"emails":["bob@example.test"],"groups":[],"type":"invalid"}"#,
    )
    .await;
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(body.as_object().unwrap().len() == 9 && body["message"] == "Invalid type");
    app.store
        .lock()
        .unwrap()
        .db
        .execute(
            "UPDATE organization_memberships SET role=3,access_all=1 WHERE user_id='alice'",
            [],
        )
        .unwrap();
    assert!(
        request(&app, &valid, Some("collection-fixture-access"), b"{invalid")
            .await
            .status()
            == StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn invited_placeholder_bad_password_is_ordinary_rejection_without_authority_or_state_changes()
{
    let mut store = fixture(":memory:");
    let organization = org(&store);
    VaultService::new(&mut store)
        .invite_org_members(
            "alice",
            &organization,
            &input(&["pending@example.test"], json!(2)),
        )
        .unwrap();
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base: "http://127.0.0.1:8000".into(),
        signing_key: [7; 32],
    };
    let before = snapshot(&app.store.lock().unwrap());
    let response=request(&app,"/identity/connect/token",None,b"grant_type=password&client_id=cli&username=pending%40example.test&password=incorrect&scope=api+offline_access&deviceIdentifier=pending-login&deviceName=fixture&deviceType=23").await;
    assert!(response.status() == StatusCode::BAD_REQUEST);
    let document: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(
        document["message"] == "Username or password is incorrect. Try again"
            && document.as_object().unwrap().len() == 9
            && snapshot(&app.store.lock().unwrap()) == before
    );
}
