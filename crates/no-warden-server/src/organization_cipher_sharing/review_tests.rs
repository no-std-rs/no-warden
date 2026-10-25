//! Independently authored regressions for pinned native historical-grant observations.
//! The paired 1.37.4 probe distinguishes read admission from route projections.
use super::*;
use rusqlite::types::Value as SqlValue;

const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const REVISION: &str = "2026-01-01T00:00:00.000Z";

fn fixture() -> Store {
    let mut store = Store::open(":memory:").unwrap();
    store.db.execute_batch(
        "INSERT INTO accounts VALUES('owner','owner@example.test','{}','fixture-verifier','2026-01-01T00:00:00.000Z'),('reader','reader@example.test','{}','fixture-verifier','2026-01-01T00:00:00.000Z');
         INSERT INTO organizations(id,name,billing_email) VALUES('old-org','old','owner@example.test'),('canonical-org','canonical','owner@example.test');
         INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) VALUES('owner-old','old-org','owner','opaque-key',0,2,1),('owner-current','canonical-org','owner','opaque-key',0,2,1),('reader-old','old-org','reader','opaque-key',2,2,0),('reader-current','canonical-org','reader','opaque-key',2,2,0);
         INSERT INTO organization_collections(id,organization_id,name) VALUES('old-collection','old-org','opaque-name'),('current-collection','canonical-org','opaque-name');
         INSERT INTO organization_collection_users VALUES('old-collection','reader',0,0,0);",
    ).unwrap();
    let original = json!({"id":"cipher","type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"secureNote":{"type":0},"key":null,"favorite":true,"folderId":null,"creationDate":REVISION,"revisionDate":REVISION,"organizationId":null});
    store.db.execute(
        "INSERT INTO items(id,owner,kind,document,revision,created) VALUES('cipher','owner','cipher',?1,?2,?2),('private-control','reader','cipher',?1,?2,?2)",
        params![original.to_string(), REVISION],
    ).unwrap();
    let input = |organization: &str, ids: &[&str]| {
        let mut document = original.clone();
        document["organizationId"] = json!(organization);
        document["encryptedFor"] = json!("owner");
        document["lastKnownRevisionDate"] = json!(REVISION);
        Input::parse(&serde_json::to_vec(&json!({"collectionIds":ids,"cipher":document})).unwrap())
            .unwrap_or_else(|_| panic!("Historical sharing fixture schema rejected"))
    };
    assert!(
        input("old-org", &["old-collection", "missing"])
            .execute(&mut store, "owner", "cipher")
            .is_err(),
        "A failed share must leave the fixture's historical association"
    );
    assert!(
        input("canonical-org", &["current-collection"])
            .execute(&mut store, "owner", "cipher")
            .is_ok(),
        "Retry must move the personal source into the canonical organization"
    );
    let before = single(&store);
    assert!(before["organizationId"] == "canonical-org");
    assert!(before["collectionIds"] == json!(["old-collection"]));
    assert_permissions(&before, true);
    store
}

fn single(store: &Store) -> Value {
    store
        .item("reader", "cipher", "cipher")
        .unwrap()
        .unwrap_or_else(|| panic!("Historical reader unexpectedly denied"))
}

fn list_projection(store: &Store) -> Value {
    // GET /ciphers and /sync both obtain their cipher list through Store::items.
    let rows = store.items("reader", "cipher").unwrap();
    let mut matches = rows.into_iter().filter(|row| row["id"] == "cipher");
    let row = matches
        .next()
        .unwrap_or_else(|| panic!("Historical cipher missing from list/sync projection"));
    assert!(
        matches.next().is_none(),
        "List/sync must contain one source"
    );
    row
}

fn assert_permissions(row: &Value, writable: bool) {
    assert!(
        row["viewPassword"] == json!(writable),
        "Unexpected password visibility projection"
    );
    assert!(row["edit"] == json!(writable), "Unexpected edit projection");
    assert!(
        row["permissions"]["delete"] == json!(writable),
        "Unexpected delete projection"
    );
    assert!(
        row["permissions"]["restore"] == json!(writable),
        "Unexpected restore projection"
    );
}

fn private_state(store: &Store, include_account_revisions: bool) -> Vec<Vec<SqlValue>> {
    let account_query = if include_account_revisions {
        "SELECT id,document,password FROM accounts ORDER BY id"
    } else {
        // Membership changes legitimately bump both account revision locations.
        "SELECT id,json_remove(document, '$.revisionDate'),password FROM accounts ORDER BY id"
    };
    let queries = [
        account_query,
        "SELECT id,owner,organization_id,kind,document,revision,created,deleted FROM items ORDER BY id",
        "SELECT cipher_id,user_id,folder_id,favorite FROM cipher_annotations ORDER BY cipher_id,user_id",
        "SELECT cipher_id,owner,archived_at FROM cipher_archives ORDER BY cipher_id,owner",
    ];
    let mut result = Vec::new();
    for query in queries
        .into_iter()
        .chain(include_account_revisions.then_some("SELECT id,revision FROM accounts ORDER BY id"))
    {
        let mut statement = store.db.prepare(query).unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
            .unwrap();
        result.extend(rows.map(Result::unwrap));
    }
    result
}

fn revoke(store: &mut Store) {
    assert!(
        VaultService::new(store)
            .revoke_org_member("owner", "old-org", "reader-old")
            .is_ok(),
        "Old membership revocation failed"
    );
}

fn assert_raw_read_admitted(store: &mut Store) {
    assert!(
        access(&store.db, "reader", "cipher")
            .unwrap()
            .is_some_and(CipherAccessSnapshot::readable),
        "Revocation must preserve the measured historical read admission"
    );
    assert!(
        VaultService::new(store)
            .authorize_cipher_read("reader", "cipher")
            .is_ok(),
        "Authenticated read service must preserve native read admission"
    );
}

#[test]
fn revoked_historical_membership_single_get_hides_collection_but_keeps_permissions() {
    let mut store = fixture();
    revoke(&mut store);
    let before = private_state(&store, true);
    assert_raw_read_admitted(&mut store);
    let row = single(&store);
    assert_permissions(&row, true);
    assert!(
        row["collectionIds"] == json!([]),
        "Single GET must hide a revoked historical collection"
    );
    assert!(before == private_state(&store, true), "Reads mutated state");
}

#[test]
fn revoked_historical_membership_list_sync_keeps_cipher_without_write_permissions() {
    let mut store = fixture();
    revoke(&mut store);
    let before = private_state(&store, true);
    assert_raw_read_admitted(&mut store);
    let row = list_projection(&store);
    assert_permissions(&row, false);
    assert!(
        row["collectionIds"] == json!([]),
        "List/sync must hide a revoked historical collection"
    );
    assert!(before == private_state(&store, true), "Reads mutated state");
}

#[test]
fn restored_historical_membership_recovers_collection_and_route_permissions() {
    let mut store = fixture();
    let before = private_state(&store, false);
    revoke(&mut store);
    assert!(
        VaultService::new(&mut store)
            .restore_org_member("owner", "old-org", "reader-old")
            .is_ok(),
        "Historical membership restoration failed"
    );
    assert_raw_read_admitted(&mut store);
    for row in [single(&store), list_projection(&store)] {
        assert_permissions(&row, true);
        assert!(row["collectionIds"] == json!(["old-collection"]));
    }
    assert!(
        before == private_state(&store, false),
        "Membership transitions changed canonical source or private state"
    );
}

#[test]
fn removed_historical_membership_denies_read_despite_confirmed_canonical_membership() {
    let mut store = fixture();
    let before = private_state(&store, false);
    assert!(
        VaultService::new(&mut store)
            .remove_org_member("owner", "old-org", "reader-old")
            .is_ok(),
        "Historical membership removal failed"
    );
    let canonical_status: i32 = store
        .db
        .query_row(
            "SELECT status FROM organization_memberships WHERE id='reader-current'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(canonical_status == 2);
    assert!(
        access(&store.db, "reader", "cipher")
            .unwrap()
            .is_some_and(|access| !access.readable())
    );
    assert!(store.item("reader", "cipher", "cipher").unwrap().is_none());
    assert!(
        store
            .items("reader", "cipher")
            .unwrap()
            .iter()
            .all(|row| row["id"] != "cipher")
    );
    assert!(
        before == private_state(&store, false),
        "Membership removal changed canonical source or private state"
    );
}
