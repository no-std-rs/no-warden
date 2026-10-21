use super::*;
use no_warden::{
    organization_collections::CollectionAccessData,
    organization_web_reads::OrganizationWebReadsStorage,
};
use rusqlite::params;
fn store() -> Store {
    let store = Store::open(":memory:").unwrap();
    store.db.execute_batch("INSERT INTO accounts VALUES('actor','actor@example.test','{}','fixture verifier','2026-01-01T00:00:00Z'),('manager','manager@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');
      INSERT INTO organizations VALUES('org','opaque name','billing@example.test',NULL,NULL),('foreign','opaque name','billing@example.test',NULL,NULL);
      INSERT INTO organization_memberships VALUES('owner-member','org','actor','opaque wrapped key',0,2,1),('manager-member','org','manager','opaque wrapped key',3,2,0);
      INSERT INTO organization_collections VALUES('one','org','opaque encrypted name',NULL),('two','org','opaque encrypted name',NULL),('foreign-collection','foreign','opaque encrypted name',NULL);
      INSERT INTO organization_collection_users VALUES('one','manager',1,0,0);").unwrap();
    for (id, owner, org) in [
        ("shared", None, Some("org")),
        ("foreign-shared", None, Some("foreign")),
        ("personal", Some("actor"), None),
    ] {
        let doc = json!({"id":id,"object":"cipherDetails","type":2,"name":"opaque encrypted name","notes":"opaque encrypted notes","secureNote":{"type":0},"key":null,"fields":null,"passwordHistory":null,"creationDate":"created","revisionDate":"revision","deletedDate":null,"favorite":true,"folderId":null,"futureEncryptedExtension":{"nested":[null,"opaque ciphertext",7]}});
        store.db.execute("INSERT INTO items(id,owner,organization_id,kind,document,revision,created) VALUES(?1,?2,?3,'cipher',?4,'revision','created')",params![id,owner,org,doc.to_string()]).unwrap();
    }
    store.db.execute_batch("INSERT INTO organization_collection_ciphers VALUES('one','shared');INSERT INTO cipher_annotations VALUES('shared','actor',NULL,1);").unwrap();
    store
}
#[test]
fn organization_cipher_projection_is_scoped_private_and_preserves_opaque_extensions() {
    let mut store = store();
    let before: Vec<(String, String)> = store
        .db
        .prepare("SELECT id,document FROM items ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let changes = store.db.total_changes();
    let value = cipher_list(&mut store, "actor", "org")
        .unwrap_or_else(|_| panic!("Organization read failed"));
    assert_eq!(value["data"].as_array().unwrap().len(), 1);
    let row = &value["data"][0];
    assert_eq!(row["id"], "shared");
    assert_eq!(row["organizationId"], "org");
    // Actual native organization-details omits unknown outer response fields.
    // The encrypted extension remains in raw storage, checked independently.
    assert!(row.get("futureEncryptedExtension").is_none());
    let raw_shared: Value =
        serde_json::from_str(&before.iter().find(|(id, _)| id == "shared").unwrap().1).unwrap();
    assert_eq!(
        raw_shared["futureEncryptedExtension"],
        json!({"nested":[null,"opaque ciphertext",7]})
    );
    for name in [
        "archivedDate",
        "edit",
        "favorite",
        "folderId",
        "permissions",
        "viewPassword",
    ] {
        assert!(row.get(name).is_none());
    }
    assert_eq!(row["fields"], json!([]));
    assert_eq!(row["passwordHistory"], json!([]));
    let after: Vec<(String, String)> = store
        .db
        .prepare("SELECT id,document FROM items ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(store.db.total_changes(), changes);
    assert_eq!(
        cipher_list(&mut store, "manager", "org")
            .unwrap_err()
            .0
            .as_u16(),
        404
    );
}
#[test]
fn aggregate_collection_details_include_full_memberships_without_changing_single_details() {
    let mut store = store();
    let value = serde_json::to_value(
        VaultService::new(&mut store)
            .list_org_collection_details("actor", "org")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 2);
    assert_eq!(value["data"][0]["users"].as_array().unwrap().len(), 2);
    for row in value["data"].as_array().unwrap() {
        assert_eq!(row.as_object().unwrap().len(), 14);
        assert_eq!(row["unmanaged"], false);
        assert_eq!(row["manage"], true);
    }
    let manager = serde_json::to_value(
        VaultService::new(&mut store)
            .list_org_collection_details("manager", "org")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manager["data"].as_array().unwrap().len(), 1);
    assert_eq!(manager["data"][0]["readOnly"], true);
    assert_eq!(manager["data"][0]["manage"], false);
    let mut service = VaultService::new(&mut store);
    let individual = serde_json::to_value(
        service
            .get_org_collection_details("actor", "org", "one")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(individual.as_object().unwrap().len(), 13);
    assert!(individual.get("unmanaged").is_none());
    assert_eq!(individual["users"].as_array().unwrap().len(), 1);
}
#[test]
fn implicit_collection_access_requires_confirmation_but_direct_grants_retain_target_states() {
    let store = store();
    store.db.execute_batch("INSERT INTO accounts VALUES('admin','admin@example.test','{}','fixture verifier','2026-01-01T00:00:00Z');INSERT INTO organization_memberships VALUES('admin-member','org','admin','',1,0,1);").unwrap();
    for status in [0, 1, 2, -1] {
        store
            .db
            .execute(
                "UPDATE organization_memberships SET status=?1 WHERE id='admin-member'",
                [status],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE organization_memberships SET status=?1 WHERE id='manager-member'",
                [status],
            )
            .unwrap();
        let rows = organization_collections::web_details(&store.db, "actor", "org").unwrap();
        let first = rows
            .iter()
            .find(|r| r.collection().collection.id == "one")
            .unwrap();
        assert!(
            (0..first.users_len()).any(|i| first.user(i).is_some_and(|r| r.id == "manager-member"))
        );
        assert_eq!(
            (0..first.users_len()).any(|i| first.user(i).is_some_and(|r| r.id == "admin-member")),
            status == 2
        );
        let second = rows
            .iter()
            .find(|r| r.collection().collection.id == "two")
            .unwrap();
        assert!(
            !(0..second.users_len())
                .any(|i| second.user(i).is_some_and(|r| r.id == "manager-member"))
        );
        assert_eq!(
            (0..second.users_len()).any(|i| second.user(i).is_some_and(|r| r.id == "admin-member")),
            status == 2
        );
    }
}
#[test]
fn configured_or_unknown_group_storage_cannot_be_reported_as_empty() {
    let mut store = store();
    assert_eq!(
        store.organization_group_presence("org").unwrap(),
        OrganizationGroupPresence::NoCreatedGroups
    );
    store
        .db
        .execute_batch(
            "CREATE TABLE organization_groups(id TEXT PRIMARY KEY,organization_id TEXT);",
        )
        .unwrap();
    assert_eq!(
        store.organization_group_presence("org").unwrap(),
        OrganizationGroupPresence::ConfiguredOrUnknown
    );
    assert_eq!(
        VaultService::new(&mut store)
            .list_empty_org_groups("actor", "org")
            .unwrap_err()
            .status_code(),
        403
    );
}
#[test]
fn query_selection_preserves_first_decoded_root_and_opaque_identifier_case() {
    for query in [
        "organizationId=raw",
        "%6FrganizationId=%72aw",
        ".organizationId=raw",
        "organizationId[value]=raw",
        "[organizationId]=raw",
        "ignored=x&organizationId=raw",
        "organizationId=raw&organizationId=foreign",
    ] {
        assert_eq!(
            query_organization(Some(query)).unwrap_or_else(|_| panic!("Query selection failed")),
            "raw"
        );
    }
    assert_eq!(
        query_organization(Some("organizationId=UPPERCASE"))
            .unwrap_or_else(|_| panic!("Query selection failed")),
        "UPPERCASE"
    );
    assert_eq!(
        query_organization(Some("organizationId="))
            .unwrap_or_else(|_| panic!("Query selection failed")),
        ""
    );
    assert_eq!(query_organization(None).unwrap_err().0.as_u16(), 401);
    assert_eq!(
        query_organization(Some("OrganizationId=wrong-case"))
            .unwrap_err()
            .0
            .as_u16(),
        401
    );
}
