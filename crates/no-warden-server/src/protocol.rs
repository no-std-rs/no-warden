//! JSON wire responses for the demonstrated personal-vault protocol.
//!
//! Ciphertext is copied without being interpreted or decrypted here. The
//! upstream contracts and examined versions are recorded in docs/protocol.md.

use serde_json::{Value, json};

/// Upstream folder responses expose exactly these four fields. Extra stored
/// request fields stay private and do not become part of the wire contract.
pub fn folder(document: &Value) -> Value {
    json!({
        "id": document["id"],
        "name": document["name"],
        "revisionDate": document["revisionDate"],
        "object": "folder",
    })
}

fn kdf(account: &Value, pascal_case: bool) -> Value {
    let kind = account.get("kdf").and_then(Value::as_i64).unwrap_or(0);
    let iterations = account
        .get("kdfIterations")
        .and_then(Value::as_i64)
        .unwrap_or(600_000);
    if pascal_case {
        json!({
            "KdfType": kind,
            "Iterations": iterations,
            "Memory": account["kdfMemory"],
            "Parallelism": account["kdfParallelism"],
        })
    } else {
        json!({
            "kdfType": kind,
            "iterations": iterations,
            "memory": account["kdfMemory"],
            "parallelism": account["kdfParallelism"],
        })
    }
}

fn account_keys(account: &Value) -> Value {
    let private_key = &account["keys"]["encryptedPrivateKey"];
    let public_key = &account["keys"]["publicKey"];
    if private_key.is_null() {
        return Value::Null;
    }
    json!({
        "publicKeyEncryptionKeyPair": {
            "wrappedPrivateKey": private_key,
            "publicKey": public_key,
            "signedPublicKey": null,
            "object": "publicKeyEncryptionKeyPair",
        },
        "securityState": null,
        "signatureKeyPair": null,
        "object": "privateKeys",
    })
}

/// Self-hosted endpoint discovery used by Bitwarden clients.
pub fn config(base: &str) -> Value {
    let base = base.trim_end_matches('/');
    json!({
        "version": "2026.6.0",
        "gitHash": null,
        "server": {
            "name": "no-warden development server",
            "url": "https://github.com/no-std-rs/no-warden",
        },
        "settings": {
            "disableUserRegistration": false,
            "suppressOnboardingInterstitials": true,
        },
        "environment": {
            "vault": base,
            "api": format!("{base}/api"),
            "identity": format!("{base}/identity"),
            "notifications": format!("{base}/notifications"),
            "sso": "",
            "cloudRegion": null,
        },
        "push": {
            "pushTechnology": 0,
            "vapidPublicKey": null,
        },
        "featureStates": {},
        "communication": null,
        "object": "config",
    })
}

/// KDF discovery; upstream exposes both shapes at both prelogin routes.
pub fn prelogin(account: &Value, _modern: bool) -> Value {
    let settings = kdf(account, false);
    json!({
        "kdf": settings["kdfType"],
        "kdfIterations": settings["iterations"],
        "kdfMemory": settings["memory"],
        "kdfParallelism": settings["parallelism"],
        "kdfSettings": settings,
        "salt": null,
    })
}

/// Personal-account profile and encrypted account keys.
pub fn profile(account: &Value, security_stamp: &str) -> Value {
    json!({
        "_status": 0,
        "id": account["id"],
        "name": account["name"],
        "email": account["email"],
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "culture": "en-US",
        "twoFactorEnabled": false,
        "key": account["key"],
        "privateKey": account["keys"]["encryptedPrivateKey"],
        "accountKeys": account_keys(account),
        "securityStamp": security_stamp,
        "organizations": [],
        "organizationsNew": [],
        "providers": [],
        "providerOrganizations": [],
        "forcePasswordReset": false,
        "avatarColor": account["avatarColor"].as_str(),
        "usesKeyConnector": false,
        "creationDate": account["creationDate"],
        "object": "profile",
    })
}

/// The camelCase user decryption fragment included in `/api/sync`.
pub fn user_decryption(account: &Value) -> Value {
    json!({
        "masterPasswordUnlock": {
            "kdf": kdf(account, false),
            "salt": account["email"],
            "masterKeyEncryptedUserKey": account["key"],
            "masterKeyWrappedUserKey": account["key"],
        },
        "userKeyId": account["userKeyId"],
    })
}

/// PascalCase account fields merged into an OAuth token response.
///
/// The caller supplies access and refresh tokens, expiry, type, and scope after
/// authenticating the request. This builder does not authenticate an account.
pub fn token_fields(account: &Value) -> Value {
    let settings = kdf(account, false);
    json!({
        "Key": account["key"],
        "PrivateKey": account["keys"]["encryptedPrivateKey"],
        "AccountKeys": account_keys(account),
        "Kdf": settings["kdfType"],
        "KdfIterations": settings["iterations"],
        "KdfMemory": settings["memory"],
        "KdfParallelism": settings["parallelism"],
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": {},
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "UserKeyId": account["userKeyId"],
            "MasterPasswordUnlock": {
                "Kdf": kdf(account, true),
                "Salt": account["email"],
                "MasterKeyEncryptedUserKey": account["key"],
                "MasterKeyWrappedUserKey": account["key"],
            },
            "Object": "userDecryptionOptions",
        },
    })
}

/// Personal API-key grants have access-only authority and a distinct upstream
/// decryption fragment. Token issuance itself belongs to the authenticated host.
pub fn api_key_token_fields(account: &Value) -> Value {
    let mut response = token_fields(account);
    let fields = response.as_object_mut().expect("token fields");
    fields.remove("MasterPasswordPolicy");
    fields["UserDecryptionOptions"]
        .as_object_mut()
        .expect("decryption options")
        .remove("UserKeyId");
    if let Some(keys) = fields.get_mut("AccountKeys").and_then(Value::as_object_mut) {
        if let Some(object) = keys.remove("object") {
            keys.insert("Object".into(), object);
        }
        if let Some(pair) = keys
            .get_mut("publicKeyEncryptionKeyPair")
            .and_then(Value::as_object_mut)
            && let Some(object) = pair.remove("object")
        {
            pair.insert("Object".into(), object);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_projects_raw_empty_names_and_authoritative_avatar_without_extensions() {
        for (avatar, expected) in [
            (Value::Null, Value::Null),
            (json!(""), json!("")),
            (json!("abcdefg"), json!("abcdefg")),
            (json!("éabcde"), json!("éabcde")),
            (json!("legacy string"), json!("legacy string")),
            (json!({"legacy":true}), Value::Null),
            (json!(7), Value::Null),
            (json!(true), Value::Null),
            (json!(["legacy"]), Value::Null),
        ] {
            let account = json!({"id":"alice","email":"alice@example.test","name":"","avatarColor":avatar,"untrustedExtension":"private"});
            let response = profile(&account, "private-stamp");
            assert!(response["securityStamp"] == "private-stamp");
            assert!(
                response["name"] == "",
                "Empty names must not fall back to email."
            );
            assert!(
                response["avatarColor"] == expected,
                "Avatar projection must preserve strings and map legacy non-string values to null."
            );
            assert!(response["email"] == "alice@example.test");
            assert_eq!(response["culture"], "en-US");
            assert!(response.get("untrustedExtension").is_none());
        }
    }

    #[test]
    fn legacy_account_key_projection_preserves_partial_and_empty_states() {
        for (public, private) in [
            (None, None),
            (Some("public-only"), None),
            (None, Some("wrapped-private-only")),
            (Some(""), Some("")),
            (Some("public"), Some("wrapped-private")),
        ] {
            let account = json!({"keys":{"publicKey":public,"encryptedPrivateKey":private}});
            let projected = account_keys(&account);
            if private.is_none() {
                assert!(projected.is_null());
                continue;
            }
            assert_eq!(projected.as_object().unwrap().len(), 4);
            let pair = &projected["publicKeyEncryptionKeyPair"];
            assert_eq!(pair.as_object().unwrap().len(), 4);
            assert!(pair["publicKey"] == json!(public));
            assert!(pair["wrappedPrivateKey"] == json!(private));
            assert!(pair["signedPublicKey"].is_null());
            assert_eq!(pair["object"], "publicKeyEncryptionKeyPair");
            assert!(projected["securityState"].is_null());
            assert!(projected["signatureKeyPair"].is_null());
            assert_eq!(projected["object"], "privateKeys");
        }
    }

    #[test]
    fn account_key_response_boundaries_expose_only_their_pinned_fields() {
        use no_warden::{
            identity::Secret,
            wire::{AccountKeysResponse, InitializedAccountKeysResponse, UserPublicKeyResponse},
        };
        let get = serde_json::to_value(AccountKeysResponse {
            key: Some(Secret::new("wrapped-user-key")),
            public_key: "public",
            private_key: Secret::new("wrapped-private"),
        })
        .unwrap();
        assert_eq!(get.as_object().unwrap().len(), 5);
        assert!(get["key"] == "wrapped-user-key");
        assert!(get["publicKey"] == "public");
        assert!(get["privateKey"] == "wrapped-private");
        assert_eq!(get["object"], "keys");
        assert!(
            get["accountKeys"]
                == account_keys(
                    &json!({"keys":{"publicKey":"public","encryptedPrivateKey":"wrapped-private"}})
                )
        );
        let initialized = serde_json::to_value(InitializedAccountKeysResponse {
            public_key: "public",
            private_key: Secret::new("wrapped-private"),
        })
        .unwrap();
        assert_eq!(initialized.as_object().unwrap().len(), 3);
        assert!(initialized["publicKey"] == "public");
        assert!(initialized["privateKey"] == "wrapped-private");
        assert_eq!(initialized["object"], "keys");
        assert!(initialized.get("accountKeys").is_none());
        assert!(initialized.get("key").is_none());
        let public = serde_json::to_value(UserPublicKeyResponse {
            user_id: "another-user",
            public_key: "public",
        })
        .unwrap();
        assert_eq!(public.as_object().unwrap().len(), 3);
        assert!(public["userId"] == "another-user");
        assert!(public["publicKey"] == "public");
        assert_eq!(public["object"], "userKey");
        for field in [
            "privateKey",
            "encryptedPrivateKey",
            "key",
            "accountKeys",
            "email",
        ] {
            assert!(public.get(field).is_none());
        }
    }

    #[test]
    fn folder_projection_preserves_name_and_revision_without_private_extensions() {
        let document = json!({
            "id": "opaque-folder-id", "name": "future-format\nquoted \" café 🔐",
            "revisionDate": "2026-01-02T03:04:05.123456Z", "object": "ignored",
            "creationDate": "private", "deletedDate": "private",
            "unknown": {"future": [1, null, "private"]},
        });
        let original = document.clone();
        let response = folder(&document);
        assert_eq!(response.as_object().unwrap().len(), 4);
        assert_eq!(response["id"], document["id"]);
        assert!(response["name"] == document["name"]);
        assert_eq!(response["revisionDate"], document["revisionDate"]);
        assert_eq!(response["object"], "folder");
        assert!(
            document == original,
            "Projecting a response must preserve stored data."
        );
    }
}
