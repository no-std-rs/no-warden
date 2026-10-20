use super::*;
use crate::organization_collections::tests::{fixture, org};
use no_warden::VaultService;
use rusqlite::params;
use serde_json::{Value, json};

#[test]
fn bulk_status_retains_successful_prefix_and_rolls_back_failed_item() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    store.db.execute("INSERT INTO accounts SELECT 'carol','carol@example.test',json_set(document,'$.id','carol','$.email','carol@example.test'),password,revision FROM accounts WHERE id='bob'", []).unwrap();
    for (id, user) in [("first", "bob"), ("failing", "carol")] {
        store
            .db
            .execute(
                "INSERT INTO organization_memberships VALUES(?1,?2,?3,'retained-key',2,2,0)",
                params![id, organization, user],
            )
            .unwrap();
    }
    let before: String = store
        .db
        .query_row(
            "SELECT document FROM accounts WHERE id='carol'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store.db.execute_batch("CREATE TRIGGER reject_carol_revision AFTER UPDATE ON accounts WHEN NEW.id='carol' BEGIN SELECT RAISE(ABORT,'private-storage-diagnostic'); END;").unwrap();
    let input = Input::parse(br#"{"ids":["first","failing","missing","first"]}"#, true)
        .unwrap_or_else(|_| panic!("Authored input"));
    let mut scratch = vec![None; input.len()];
    let reply = serde_json::to_value(
        VaultService::new(&mut store)
            .bulk_revoke_org_members("alice", &organization, &input, &mut scratch)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["data"][0]["error"], "");
    assert_eq!(reply["data"][1]["error"], "Storage operation failed.");
    assert_eq!(reply["data"][2]["error"], "User not found in organization");
    assert_eq!(reply["data"][3]["error"], "User is already revoked");
    let state: Vec<(String, i32, String)> = store.db.prepare("SELECT id,status,key FROM organization_memberships WHERE id IN ('first','failing') ORDER BY id").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap();
    assert_eq!(
        state,
        [
            ("failing".into(), 2, "retained-key".into()),
            ("first".into(), -126, "retained-key".into())
        ]
    );
    let after: String = store
        .db
        .query_row(
            "SELECT document FROM accounts WHERE id='carol'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
    assert!(!reply.to_string().contains("private-storage"));
    store
        .db
        .execute_batch("DROP TRIGGER reject_carol_revision")
        .unwrap();
    let mut scratch = vec![None; input.len()];
    let reply: Value = serde_json::to_value(
        VaultService::new(&mut store)
            .bulk_restore_org_members("alice", &organization, &input, &mut scratch)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["data"][0]["error"], "");
    assert_eq!(reply["data"][1]["error"], "User is already active");
    assert_eq!(reply["data"][2]["error"], "User not found in organization");
    assert_eq!(reply["data"][3]["error"], "User is already active");
    assert_eq!(reply["object"], json!("list"));
}
