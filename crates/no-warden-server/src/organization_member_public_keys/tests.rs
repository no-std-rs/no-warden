use super::*;
use crate::organization_collections::tests::{create_org, fixture, org, snapshot};
use axum::http::StatusCode;
use no_warden::VaultService;
use serde_json::{Value, json};

fn read(
    store: &mut Store,
    organization: &str,
    input: &Input,
) -> Result<Value, no_warden::ApiError> {
    let mut scratch = Vec::new();
    scratch.resize_with(input.len(), || None);
    VaultService::new(store)
        .get_org_member_public_keys("alice", organization, input, &mut scratch)
        .map(|response| serde_json::to_value(response).unwrap())
}

#[test]
fn public_key_owned_decoder_validates_whole_schema_and_preserves_opaque_ids_without_a_batch_cap() {
    for valid in [br#"{"ids":[]}"#.as_slice(), b"[[]]"] {
        assert!(Input::parse(valid).is_ok());
    }
    for invalid in [
        b"{}".as_slice(),
        br#"{"ids":null}"#,
        br#"{"Ids":[]}"#,
        br#"{"ids":[],"ids":[]}"#,
        br#"{"ids":"member"}"#,
        br#"{"ids":["member",null]}"#,
        br#"{"ids":["member",42]}"#,
        b"[]",
    ] {
        assert!(
            Input::parse(invalid)
                .err()
                .is_some_and(|e| e.0 == StatusCode::UNPROCESSABLE_ENTITY)
        );
    }
    for invalid in [
        b"{".as_slice(),
        b"[[],0]",
        b"{\"ids\":[],\"ignored\":\"\xff\"}",
    ] {
        assert!(
            Input::parse(invalid)
                .err()
                .is_some_and(|e| e.0 == StatusCode::BAD_REQUEST)
        );
    }
    let body = json!({"ids":vec!["opaque\0雪";513],"ignored":true});
    let input = Input::parse(&serde_json::to_vec(&body).unwrap())
        .unwrap_or_else(|_| panic!("Authored input"));
    assert_eq!(input.len(), 513);
    assert!(input.get(0) == Some("opaque\0雪") && input.get(512) == Some("opaque\0雪"));
}

#[test]
fn public_key_join_preserves_null_empty_and_opaque_keys_across_all_target_states_and_scopes() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    let foreign = create_org(&mut store, "bob");
    store.db.execute("INSERT INTO organization_memberships VALUES('member',?1,'bob','wrapped-org-key',2,2,0)",[&organization]).unwrap();
    let foreign_member: String = store
        .db
        .query_row(
            "SELECT id FROM organization_memberships WHERE organization_id=?1 AND user_id='bob'",
            [foreign],
            |row| row.get(0),
        )
        .unwrap();
    let input = Input::parse(
        &serde_json::to_vec(&json!({"ids":["missing","member",foreign_member,"member","bob",""]}))
            .unwrap(),
    )
    .unwrap_or_else(|_| panic!("Authored input"));
    for public_key in [None, Some(""), Some("future-public-key\0雪")] {
        store.db.execute("UPDATE accounts SET document=json_set(document,'$.keys',json_object('publicKey',?1,'encryptedPrivateKey','retained-private-key')) WHERE id='bob'",[public_key]).unwrap();
        for (role, status) in [(0, 0), (1, 1), (2, 2), (3, -126), (4, -128), (-7, 9)] {
            store
                .db
                .execute(
                    "UPDATE organization_memberships SET role=?1,status=?2 WHERE id='member'",
                    params![role, status],
                )
                .unwrap();
            let before = snapshot(&store);
            let response = read(&mut store, &organization, &input).unwrap();
            let row = json!({"object":"organizationUserPublicKeyResponseModel","id":"member","userId":"bob","key":public_key});
            assert!(
                response
                    == json!({"data":[row.clone(),row],"object":"list","continuationToken":null}),
                "Public-key projection differed"
            );
            assert!(snapshot(&store) == before, "Public-key read changed state");
        }
    }
    // A membership whose account vanished is omitted, distinct from a null key.
    store.db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    store.db.execute("INSERT INTO organization_memberships VALUES('dangling',?1,'absent-account','wrapped',2,2,0)",[&organization]).unwrap();
    store.db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let input =
        Input::parse(br#"{"ids":["dangling"]}"#).unwrap_or_else(|_| panic!("Authored input"));
    assert_eq!(
        read(&mut store, &organization, &input).unwrap(),
        json!({"object":"list","data":[],"continuationToken":null})
    );
}

#[test]
fn public_key_read_failures_do_not_mutate_state_or_return_a_successful_prefix() {
    let mut store = fixture(":memory:");
    let organization = org(&store);
    store.db.execute("INSERT INTO accounts VALUES('carol','carol@example.test','invalid-json','opaque-verifier','2000')",[]).unwrap();
    for (member, user) in [("member", "bob"), ("bad-document", "carol")] {
        store
            .db
            .execute(
                "INSERT INTO organization_memberships VALUES(?1,?2,?3,'wrapped',2,2,0)",
                params![member, organization, user],
            )
            .unwrap();
    }
    let input = Input::parse(br#"{"ids":["member","bad-document","member"]}"#)
        .unwrap_or_else(|_| panic!("Authored input"));
    let before = snapshot(&store);
    let mut scratch = Vec::new();
    scratch.resize_with(input.len(), || None);
    let error = VaultService::new(&mut store)
        .get_org_member_public_keys("alice", &organization, &input, &mut scratch)
        .unwrap_err();
    assert_eq!(error.kind, no_warden::ErrorKind::Storage);
    assert_eq!(error.message, "Storage operation failed.");
    assert!(scratch.iter().all(Option::is_none));
    assert!(
        snapshot(&store) == before,
        "Public-key failure changed state"
    );
}
