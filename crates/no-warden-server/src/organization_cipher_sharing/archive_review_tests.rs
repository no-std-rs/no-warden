//! Independently authored regressions for the measured personal-share archive contract.
//! Native differential receipts: no-warden-pr57-personal-archive-review-20261021.

use super::*;

const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const REVISION: &str = "2026-01-01T00:00:00.000000Z";
const ARCHIVED: &str = "2026-01-02T00:00:00.000000Z";

fn fixture(archived: bool) -> Store {
    let store = Store::open(":memory:").unwrap();
    let account = json!({"key": ENCRYPTED, "privateKey": ENCRYPTED, "userKeyId": "private-key-id"});
    for (id, email) in [("alice", "alice@example.test"), ("bob", "bob@example.test")] {
        store.db.execute(
            "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'test',?4)",
            params![id, email, account.to_string(), REVISION],
        ).unwrap();
    }
    for (id, owner, kind, document) in [
        (
            "folder",
            "alice",
            "folder",
            json!({"id":"folder","name":ENCRYPTED}),
        ),
        (
            "cipher",
            "alice",
            "cipher",
            json!({"id":"cipher","type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"secureNote":{"type":0},"organizationId":null,"key":null,"folderId":"folder","favorite":true,"creationDate":REVISION,"revisionDate":REVISION,"deletedDate":null,"archivedDate":null}),
        ),
        (
            "control",
            "alice",
            "cipher",
            json!({"id":"control","type":2,"name":ENCRYPTED,"secureNote":{"type":0},"favorite":false,"creationDate":REVISION,"revisionDate":REVISION}),
        ),
        (
            "foreign",
            "bob",
            "cipher",
            json!({"id":"foreign","type":2,"name":ENCRYPTED,"secureNote":{"type":0},"creationDate":REVISION,"revisionDate":REVISION}),
        ),
    ] {
        store.db.execute(
            "INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,?3,?4,?5,?5)",
            params![id, owner, kind, document.to_string(), REVISION],
        ).unwrap();
    }
    if archived {
        store.db.execute(
            "INSERT INTO cipher_archives(cipher_id,owner,archived_at) VALUES('cipher','alice',?1)",
            [ARCHIVED],
        ).unwrap();
    }
    store
}

fn request(archive: Option<Value>) -> Input {
    let mut cipher = json!({"id":"cipher","type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"secureNote":{"type":0},"organizationId":null,"encryptedFor":"alice","key":null,"folderId":"folder","favorite":true,"lastKnownRevisionDate":REVISION});
    if let Some(archive) = archive {
        cipher["archivedDate"] = archive;
    }
    Input::parse(&serde_json::to_vec(&json!({"collectionIds":[],"cipher":cipher})).unwrap())
        .unwrap_or_else(|_| panic!("Valid personal sharing fixture rejected"))
}

fn account_revision(store: &Store) -> String {
    store
        .db
        .query_row("SELECT revision FROM accounts WHERE id='alice'", [], |r| {
            r.get(0)
        })
        .unwrap()
}

// Snapshots contain opaque private values only in memory; assertions never format them.
fn protected_snapshot(store: &Store) -> Vec<String> {
    let mut rows = store.db.prepare(
        "SELECT json_array('account',id,CASE WHEN id='alice' THEN json_remove(document,'$.revisionDate') ELSE document END,CASE WHEN id='alice' THEN NULL ELSE revision END) FROM accounts
         UNION ALL SELECT json_array('item',id,owner,kind,document,revision,created) FROM items WHERE id<>'cipher'
         UNION ALL SELECT json_array('annotation',cipher_id,user_id,folder_id,favorite) FROM cipher_annotations
         UNION ALL SELECT json_array('association',collection_id,cipher_id) FROM organization_collection_ciphers
         ORDER BY 1",
    ).unwrap();
    rows.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn transaction_snapshot(store: &Store) -> Vec<String> {
    let mut rows = store.db.prepare(
        "SELECT json_array('account',id,email,document,password,revision) FROM accounts
         UNION ALL SELECT json_array('item',id,owner,organization_id,kind,document,deleted,revision,created) FROM items
         UNION ALL SELECT json_array('archive',cipher_id,owner,archived_at) FROM cipher_archives
         UNION ALL SELECT json_array('annotation',cipher_id,user_id,folder_id,favorite) FROM cipher_annotations
         UNION ALL SELECT json_array('association',collection_id,cipher_id) FROM organization_collection_ciphers
         ORDER BY 1",
    ).unwrap();
    rows.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

#[test]
fn personal_share_archive_metadata_matches_native_response_get_and_list() {
    for (initially_archived, input, expected) in [
        (true, Some(Value::Null), Value::Null),
        (true, None, Value::Null),
        (
            true,
            Some(json!("2030-02-03T04:05:06.000Z")),
            json!("2030-02-03T04:05:06.000000Z"),
        ),
        (
            true,
            Some(json!("2000-02-03T04:05:06.000Z")),
            json!("2000-02-03T04:05:06.000000Z"),
        ),
        (
            false,
            Some(json!("2030-02-03T04:05:06.000Z")),
            json!("2030-02-03T04:05:06.000000Z"),
        ),
    ] {
        let mut store = fixture(initially_archived);
        let before = project(&store.db, "alice", "cipher", true)
            .unwrap()
            .unwrap();
        let account_before = account_revision(&store);
        let protected_before = protected_snapshot(&store);
        assert!(
            request(input)
                .execute(&mut store, "alice", "cipher")
                .is_ok()
        );

        // HTTP sharing replies and GET use this single-item projection; sync/list
        // uses list(). Assert both views rather than inspecting only raw JSON.
        let response = project(&store.db, "alice", "cipher", true)
            .unwrap()
            .unwrap();
        let listed = list(&store.db, "alice").unwrap();
        let synced = listed.iter().find(|row| row["id"] == "cipher").unwrap();
        assert!(
            response["archivedDate"] == expected,
            "Personal share must apply measured archive metadata"
        );
        assert!(
            synced["archivedDate"] == expected,
            "List must expose the committed archive state"
        );
        assert!(response.as_object().unwrap().len() == 30);
        for document in [&response, synced] {
            assert!(
                document["name"] == before["name"]
                    && document["notes"] == before["notes"]
                    && document["key"] == before["key"]
                    && document["secureNote"] == before["secureNote"],
                "Opaque encrypted payload must remain unchanged"
            );
            assert!(
                document["folderId"] == before["folderId"]
                    && document["favorite"] == before["favorite"],
                "Personal annotations must remain unchanged"
            );
            assert!(
                document["creationDate"] == before["creationDate"]
                    && document["deletedDate"] == before["deletedDate"],
                "Unrelated lifecycle metadata must remain unchanged"
            );
            assert!(document["organizationId"].is_null() && document["collectionIds"] == json!([]));
            assert!(
                document["revisionDate"] != before["revisionDate"],
                "Successful share must advance the cipher revision"
            );
        }
        let scope: (Option<String>, Option<String>) = store
            .db
            .query_row(
                "SELECT owner,organization_id FROM items WHERE id='cipher'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(scope.0.as_deref() == Some("alice") && scope.1.is_none());
        assert!(
            account_revision(&store) != account_before,
            "Successful share must advance the actor account revision"
        );
        assert!(
            protected_snapshot(&store) == protected_before,
            "Private keys, folder, controls, and other accounts must remain unchanged"
        );
        assert!(store.pending.is_null());
    }
}

#[test]
fn personal_share_archive_write_failure_rolls_back_item_and_account() {
    // Atomic failure of the local provider is a local guarantee, not a claim
    // about an injected failure on the native server.
    let mut store = fixture(true);
    let input = request(Some(json!("2030-02-03T04:05:06.000Z")));
    let before = transaction_snapshot(&store);
    store.db.execute_batch("CREATE TRIGGER reject_personal_share_archive BEFORE INSERT ON cipher_archives WHEN NEW.cipher_id='cipher' BEGIN SELECT RAISE(ABORT,'injected archive write failure'); END;").unwrap();
    assert!(
        input.execute(&mut store, "alice", "cipher").is_err(),
        "Archive persistence failure must fail the personal share"
    );
    assert!(
        transaction_snapshot(&store) == before,
        "Archive failure must roll back the item, archive, and account revision together"
    );
    assert!(store.pending.is_null());
    store
        .db
        .execute_batch("DROP TRIGGER reject_personal_share_archive")
        .unwrap();
    assert!(
        input.execute(&mut store, "alice", "cipher").is_ok(),
        "Unchanged source must permit retry after the injected failure"
    );
    let after = project(&store.db, "alice", "cipher", true)
        .unwrap()
        .unwrap();
    assert!(after["archivedDate"] == "2030-02-03T04:05:06.000000Z");
}
