use super::*;
use crate::organization_collections::tests::{create_org, fixture, org, snapshot};
use no_warden::{VaultService, organization_members::OrganizationMemberQuery};
use serde_json::{Value, json};

fn read(store: &mut Store, org: &str) -> Result<Value, no_warden::ApiError> {
    VaultService::new(store)
        .list_org_member_mini_details("alice", org)
        .map(|response| serde_json::to_value(response).unwrap())
}
#[test]
fn mini_join_preserves_all_states_unfiltered_names_scope_and_only_seven_public_fields() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let _foreign = create_org(&mut store, "bob");
    store.db.execute("UPDATE accounts SET document=json_set(document,'$.name','Recipient 雪','$.keys',json_object('publicKey','private-projection-sentinel','encryptedPrivateKey','private-projection-sentinel')) WHERE id='bob'",[]).unwrap();
    store.db.execute("INSERT INTO organization_memberships VALUES('member',?1,'bob','wrapped-org-key',3,1,0)",[&organization]).unwrap();
    let placeholder = "invited@example.test";
    store.db.execute("INSERT INTO accounts VALUES('placeholder',?1,json_object('id','placeholder','email',?1,'name',?1),'','2000')",[placeholder]).unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES('invited',?1,'placeholder','',2,0,0)",
            [&organization],
        )
        .unwrap();
    let owner: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='alice'",
            [&organization],
            |row| row.get(0),
        )
        .unwrap();
    for (role, status, projected) in [(0, 0, 0), (1, 1, 1), (2, 2, 2), (3, -126, -1)] {
        store
            .db
            .execute(
                "UPDATE organization_memberships SET role=?1,status=?2 WHERE id='member'",
                params![role, status],
            )
            .unwrap();
        let before = snapshot(&store);
        let value = read(&mut store, &organization).unwrap();
        let expected = json!({"data":[
            {"id":owner,"userId":"alice","email":"alice@example.test","name":"","type":0,"status":2,"object":"organizationUserUserMiniDetails"},
            {"id":"member","userId":"bob","email":"bob@example.test","name":"Recipient 雪","type":if role==3 {4} else {role},"status":projected,"object":"organizationUserUserMiniDetails"},
            {"id":"invited","userId":"placeholder","email":placeholder,"name":placeholder,"type":2,"status":0,"object":"organizationUserUserMiniDetails"}
        ],"object":"list","continuationToken":null});
        assert!(value == expected, "Mini-member projection differed");
        assert!(
            snapshot(&store) == before,
            "Mini-member read changed persisted state"
        );
    }
    let full = serde_json::to_value(
        VaultService::new(&mut store)
            .list_org_members("alice", &organization, &OrganizationMemberQuery::default())
            .unwrap(),
    )
    .unwrap();
    assert!(
        full["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "invited")
            .unwrap()["name"]
            .is_null()
    );
}
#[test]
fn mini_manager_admission_does_not_inherit_full_member_list_access_all_gate() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    store.db.execute("UPDATE organization_memberships SET role=3,access_all=0 WHERE organization_id=?1 AND user_id='alice'",[&organization]).unwrap();
    let before = snapshot(&store);
    assert!(read(&mut store, &organization).is_ok());
    assert_eq!(
        VaultService::new(&mut store)
            .list_org_members("alice", &organization, &OrganizationMemberQuery::default())
            .unwrap_err()
            .status_code(),
        404
    );
    assert!(
        snapshot(&store) == before,
        "Mini-member Manager read changed state"
    );
}
#[test]
fn mini_join_failures_are_safe_outer_errors_and_leave_database_unchanged() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    store
        .db
        .execute(
            "UPDATE accounts SET document='invalid-json' WHERE id='bob'",
            [],
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_memberships VALUES('member',?1,'bob','wrapped',2,1,0)",
            [&organization],
        )
        .unwrap();
    let before = snapshot(&store);
    let error = read(&mut store, &organization).unwrap_err();
    assert_eq!(error.kind, no_warden::ErrorKind::Storage);
    assert_eq!(error.message, "Storage operation failed.");
    assert!(
        snapshot(&store) == before,
        "Mini-member error changed state"
    );
}
