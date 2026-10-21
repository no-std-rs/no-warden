use super::*;

#[test]
fn positional_cipher_is_rejected_before_sharing_can_execute() {
    const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // Serde's struct sequence representation accepts a complete positional DTO.
    // The HTTP sharing contract instead requires an inner JSON object.
    let positional = json!([
        2, ENCRYPTED, null, ENCRYPTED, null, "org", "alice", null,
        null, false, 0, null, {"type":0}, null, null, null, null, null,
        null, null
    ]);
    assert!(CipherRequest::deserialize(&positional).is_ok());
    for cipher in [positional, json!([2]), json!(42)] {
        let body =
            serde_json::to_vec(&json!({"collectionIds":["collection"],"cipher":cipher})).unwrap();
        let failure = Input::parse(&body)
            .err()
            .expect("Reject non-object before executing any association");
        assert_eq!(failure.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let control = serde_json::to_vec(&json!({"collectionIds":["collection"],"cipher":{"type":2,"name":ENCRYPTED,"secureNote":{"type":0},"organizationId":"org","encryptedFor":"alice"}})).unwrap();
    assert!(Input::parse(&control).is_ok());
}
