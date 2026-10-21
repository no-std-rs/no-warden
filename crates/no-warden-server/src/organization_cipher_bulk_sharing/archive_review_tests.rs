//! Independent regressions for the five-case native bulk archive probe.
use super::*;

const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const REVISION: &str = "2026-01-01T00:00:00.000000Z";

fn fixture(archived: bool) -> (Store, String) {
    let s = crate::organization_collections::tests::fixture(":memory:");
    let col =
        s.db.query_row("SELECT id FROM organization_collections LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    for (id, owner, kind) in [
        ("folder", "alice", "folder"),
        ("cipher", "alice", "cipher"),
        ("control", "alice", "cipher"),
        ("foreign", "bob", "cipher"),
    ] {
        let doc = json!({"id":id,"type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"key":null,"secureNote":{"type":0},"organizationId":null,"favorite":true,"folderId":(kind=="cipher").then_some("folder"),"creationDate":REVISION,"deletedDate":null,"revisionDate":REVISION});
        s.db.execute(
            "INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,?3,?4,?5,?5)",
            params![id, owner, kind, doc.to_string(), REVISION],
        )
        .unwrap();
    }
    if archived {
        s.db.execute(
            "INSERT INTO cipher_archives VALUES('cipher','alice','2026-01-02T00:00:00.000000Z')",
            [],
        )
        .unwrap();
    }
    (s, col)
}

fn request(col: &str, archive: Option<Value>) -> Input {
    let mut doc = json!({"id":"cipher","type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"key":null,"secureNote":{"type":0},"organizationId":null,"encryptedFor":"alice","favorite":true,"folderId":"folder","lastKnownRevisionDate":REVISION});
    if let Some(archive) = archive {
        doc["archivedDate"] = archive;
    }
    Input::parse(&serde_json::to_vec(&json!({"ciphers":[doc],"collectionIds":[col]})).unwrap())
        .unwrap_or_else(|_| panic!("Valid personal bulk archive fixture rejected"))
}

// Opaque values stay in memory; boolean assertions never format snapshots.
fn snapshot(s: &Store, full: bool) -> Vec<String> {
    let mut q = s.db.prepare("SELECT json_array('account',id,CASE WHEN ?1 OR id<>'alice' THEN document ELSE json_remove(document,'$.revisionDate') END,CASE WHEN ?1 OR id<>'alice' THEN revision ELSE NULL END) FROM accounts
        UNION ALL SELECT json_array('item',id,owner,organization_id,kind,document,revision,created) FROM items WHERE ?1 OR id<>'cipher'
        UNION ALL SELECT json_array('archive',cipher_id,owner,archived_at) FROM cipher_archives WHERE ?1
        UNION ALL SELECT json_array('member',id,organization_id,user_id,key,role,status,access_all) FROM organization_memberships
        UNION ALL SELECT json_array('annotation',cipher_id,user_id,folder_id,favorite) FROM cipher_annotations
        UNION ALL SELECT json_array('association',collection_id,cipher_id) FROM organization_collection_ciphers ORDER BY 1").unwrap();
    q.query_map([full], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

#[test]
fn personal_bulk_share_applies_measured_archive_metadata_to_get_list_and_annotation() {
    for (archived, input, expected) in [
        (true, Some(Value::Null), None),
        (true, None, None),
        (
            true,
            Some(json!("2030-02-03T04:05:06.000Z")),
            Some("2030-02-03T04:05:06.000000Z"),
        ),
        (
            true,
            Some(json!("2000-02-03T04:05:06.000Z")),
            Some("2000-02-03T04:05:06.000000Z"),
        ),
        (
            false,
            Some(json!("2030-02-03T04:05:06.000Z")),
            Some("2030-02-03T04:05:06.000000Z"),
        ),
    ] {
        let (mut s, col) = fixture(archived);
        let before = sharing::project(&s.db, "alice", "cipher", true)
            .unwrap()
            .unwrap();
        let protected = snapshot(&s, false);
        let revision: String =
            s.db.query_row("SELECT revision FROM accounts WHERE id='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(request(&col, input).execute(&mut s, "alice").is_ok());
        let after = sharing::project(&s.db, "alice", "cipher", true)
            .unwrap()
            .unwrap();
        let listed = sharing::list(&s.db, "alice").unwrap();
        let list_row = listed.iter().find(|row| row["id"] == "cipher").unwrap();
        let annotation: Option<String> = s.db.query_row("SELECT archived_at FROM cipher_archives WHERE cipher_id='cipher' AND owner='alice'", [], |r| r.get(0)).unwrap();
        assert!(
            annotation.as_deref() == expected,
            "Archive annotation must apply the native contract"
        );
        for row in [&after, list_row] {
            assert!(
                row["archivedDate"] == json!(expected),
                "GET and list must expose the normalized committed archive"
            );
            for field in [
                "name",
                "notes",
                "key",
                "secureNote",
                "folderId",
                "favorite",
                "creationDate",
                "deletedDate",
            ] {
                assert!(
                    row[field] == before[field],
                    "Opaque payload and private metadata must remain unchanged"
                );
            }
            assert!(row["revisionDate"] != before["revisionDate"]);
            assert!(row["organizationId"].is_null() && row["collectionIds"] == json!([]));
        }
        let scope: (Option<String>, Option<String>) =
            s.db.query_row(
                "SELECT owner,organization_id FROM items WHERE id='cipher'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(scope.0.as_deref() == Some("alice") && scope.1.is_none());
        let current: String =
            s.db.query_row("SELECT revision FROM accounts WHERE id='alice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(current != revision);
        assert!(
            snapshot(&s, false) == protected,
            "Controls, foreign revisions, private keys and organization context must remain unchanged"
        );
        assert!(s.pending.is_null());
    }
}

#[test]
fn personal_bulk_share_archive_failure_rolls_back_the_current_item_and_account() {
    // This injected transaction failure is a local provider guarantee.
    let (mut s, col) = fixture(true);
    let before = snapshot(&s, true);
    let input = request(&col, Some(json!("2030-02-03T04:05:06.000Z")));
    s.db.execute_batch("CREATE TRIGGER reject_bulk_archive BEFORE INSERT ON cipher_archives WHEN NEW.cipher_id='cipher' BEGIN SELECT RAISE(ABORT,'injected archive write failure'); END;").unwrap();
    assert!(
        input.execute(&mut s, "alice").is_err(),
        "Archive failure must fail this bulk item"
    );
    assert!(
        snapshot(&s, true) == before,
        "Archive failure must roll back the current item, archive and account revisions"
    );
    assert!(s.pending.is_null());
    s.db.execute_batch("DROP TRIGGER reject_bulk_archive")
        .unwrap();
    assert!(input.execute(&mut s, "alice").is_ok());
    let after = sharing::project(&s.db, "alice", "cipher", true)
        .unwrap()
        .unwrap();
    assert!(after["archivedDate"] == "2030-02-03T04:05:06.000000Z");
}
